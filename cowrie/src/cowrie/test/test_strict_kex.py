# SPDX-License-Identifier: BSD-3-Clause
"""Strict KEX negotiation, packet ordering and real encrypted rekeying."""

import unittest
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from twisted.conch.ssh import keys, transport
from twisted.conch.ssh.common import NS, getNS
from twisted.internet.defer import succeed
from twisted.internet.testing import StringTransport

from cowrie.ssh.factory import CowrieSSHFactory
from cowrie.ssh.transport import HoneyPotSSHTransport


class StrictClient(transport.SSHClientTransport):
    """Test peer with directional strict sequence resets, using real Conch KEX."""

    def sendPacket(self, message, payload):
        super().sendPacket(message, payload)
        if message == transport.MSG_NEWKEYS:
            self.outgoingPacketSequence = 0

    def ssh_NEWKEYS(self, packet):
        self.incomingPacketSequence = 0
        super().ssh_NEWKEYS(packet)


def make_server():
    factory = CowrieSSHFactory("shell", None)
    key = keys.Key(Ed25519PrivateKey.generate())
    factory.privateKeys = {b"ssh-ed25519": key}
    factory.publicKeys = {b"ssh-ed25519": key.public()}
    server = factory.buildProtocol(None)
    server.transport = StringTransport()
    server.transport.loseConnection = Mock()
    server.buf = b""
    server.gotVersion = True
    server.otherVersionString = b"SSH-2.0-test-client"
    server.currentEncryptions = transport.SSHCiphers(b"none", b"none", b"none", b"none")
    server.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")
    return server


def make_client(server, strict):
    client = (StrictClient if strict else transport.SSHClientTransport)()
    client.transport = StringTransport()
    client.buf = b""
    client.gotVersion = True
    client._gotNewKeys = False
    client.ourVersionString = server.otherVersionString
    client.otherVersionString = server.ourVersionString
    client.currentEncryptions = transport.SSHCiphers(b"none", b"none", b"none", b"none")
    client.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")
    client.supportedKeyExchanges = [b"curve25519-sha256"]
    if strict:
        client.supportedKeyExchanges += [server._KEX_STRICT_C]
    client.supportedPublicKeys = [b"ssh-ed25519"]
    client.supportedCiphers = [b"aes128-ctr"]
    client.supportedMACs = [b"hmac-sha2-256"]
    client.supportedCompressions = [b"none"]
    client.verifyHostKey = lambda *args: succeed(True)
    client.connectionSecure = Mock()
    return client


def pump(server, client):
    for _ in range(20):
        moved = False
        for sender, receiver in ((server, client), (client, server)):
            data = sender.transport.value()
            sender.transport.clear()
            if data:
                moved = True
                receiver.dataReceived(data)
        if not moved:
            return
    raise AssertionError("Handshake did not settle")


class StrictKexTests(unittest.TestCase):
    def pair(self, strict=True):
        server = make_server()
        client = make_client(server, strict)
        server.sendKexInit()
        client.sendKexInit()
        pump(server, client)
        server.transport.loseConnection.assert_not_called()
        self.assertEqual(server._keyExchangeState, server._KEY_EXCHANGE_NONE)
        self.assertEqual(client._keyExchangeState, client._KEY_EXCHANGE_NONE)
        self.assertEqual(server._strict_kex, strict)
        return server, client

    def test_initial_advertisement_preserves_algorithms_and_payload(self):
        server = make_server()
        original = list(server.supportedKeyExchanges)
        server.sendKexInit()
        advertised = getNS(server.ourKexInitPayload[17:])[0].split(b",")
        self.assertEqual(advertised, original + [b"ext-info-s", server._KEX_STRICT_S])
        self.assertEqual(server.supportedKeyExchanges, original)
        fields = getNS(server.ourKexInitPayload[17:], 10)
        self.assertEqual(list(fields[1:-1]), [
            b",".join(values) for values in (
                server.supportedPublicKeys,
                server.supportedCiphers, server.supportedCiphers,
                server.supportedMACs, server.supportedMACs,
                server.supportedCompressions, server.supportedCompressions,
                server.supportedLanguages, server.supportedLanguages,
            )
        ])
        self.assertIn(server.ourKexInitPayload, server.transport.value())

    def test_real_strict_handshake_and_encrypted_messages(self):
        server, client = self.pair()
        self.assertTrue(server._initial_kex_done)
        # The server's first post-NEWKEYS packet is its existing EXT_INFO.
        self.assertEqual(server.outgoingPacketSequence, 1)
        self.assertEqual(server.incomingPacketSequence, 0)
        self.assertEqual(client.peerExtensions, {b"server-sig-algs": server._SERVER_SIG_ALGS, b"ping@openssh.com": b"0"})
        client.sendIgnore(b"encrypted client probe")
        server.sendIgnore(b"encrypted server probe")
        pump(server, client)
        self.assertEqual(server.incomingPacketSequence, 1)
        server.transport.loseConnection.assert_not_called()

    def test_real_non_strict_handshake_keeps_old_counters(self):
        server, client = self.pair(False)
        self.assertGreater(server.incomingPacketSequence, 0)
        self.assertGreater(server.outgoingPacketSequence, 1)
        client.sendIgnore(b"probe")
        pump(server, client)
        server.transport.loseConnection.assert_not_called()

    def test_rekeys_in_both_directions_reset_each_time(self):
        server, client = self.pair()
        for initiator in (server, client, server, client):
            with self.subTest(initiator=type(initiator).__name__):
                initiator.sendKexInit()
                pump(server, client)
                server.transport.loseConnection.assert_not_called()
                self.assertEqual(server._keyExchangeState, server._KEY_EXCHANGE_NONE)
                self.assertEqual(server.incomingPacketSequence, 0)
                self.assertEqual(server.outgoingPacketSequence, 0)
                advertised = getNS(server.ourKexInitPayload[17:])[0].split(b",")
                self.assertNotIn(server._KEX_STRICT_S, advertised)
                client.sendIgnore(b"post-rekey")
                pump(server, client)
                self.assertEqual(server.incomingPacketSequence, 1)

    def test_initial_kexinit_must_be_first_packet_when_strict(self):
        server = make_server()
        client = make_client(server, True)
        client.sendIgnore(b"before KEXINIT")
        client.sendKexInit()
        server.sendKexInit()
        server.dataReceived(client.transport.value())
        server.transport.loseConnection.assert_called_once()
        self.assertTrue(server._strict_disconnect)

    def test_non_strict_client_can_send_ignore_before_kexinit(self):
        server = make_server()
        client = make_client(server, False)
        client.sendIgnore(b"before KEXINIT")
        client.sendKexInit()
        server.sendKexInit()
        pump(server, client)
        server.transport.loseConnection.assert_not_called()

    def test_initial_unexpected_packets_are_rejected(self):
        for message in (2, 3, 4, 5, 7, 21, 31, 32, 34, 50, 94, 192, 193):
            with self.subTest(message=message):
                server = make_server()
                server._strict_kex = True
                server._strict_expected = 30
                server.dispatchMessage(message, b"")
                server.transport.loseConnection.assert_called_once()

    def test_newkeys_validation_precedes_counter_reset(self):
        for payload, sent, state in (
            (b"garbage", True, HoneyPotSSHTransport._KEY_EXCHANGE_PROGRESSING),
            (b"", False, HoneyPotSSHTransport._KEY_EXCHANGE_PROGRESSING),
            (b"", True, HoneyPotSSHTransport._KEY_EXCHANGE_NONE),
        ):
            with self.subTest(payload=payload, sent=sent, state=state):
                server = make_server()
                server._strict_kex = True
                server._newkeys_sent = sent
                server._keyExchangeState = state
                server.incomingPacketSequence = 17
                server.ssh_NEWKEYS(payload)
                self.assertEqual(server.incomingPacketSequence, 17)
                self.assertFalse(server._initial_kex_done)
                server.transport.loseConnection.assert_called_once()

    def test_outgoing_newkeys_uses_old_mac_sequence_then_resets(self):
        server = make_server()
        server._strict_kex = True
        server.outgoingPacketSequence = 9
        original = server.currentEncryptions.makeMAC
        server.currentEncryptions.makeMAC = Mock(wraps=original)
        server.sendPacket(transport.MSG_NEWKEYS, b"")
        self.assertEqual(server.currentEncryptions.makeMAC.call_args.args[0], 9)
        self.assertEqual(server.outgoingPacketSequence, 0)

    def test_late_marker_cannot_enable_strict_kex(self):
        server, client = self.pair(False)
        client.supportedKeyExchanges += [server._KEX_STRICT_C]
        client.sendKexInit()
        pump(server, client)
        self.assertFalse(server._strict_kex)
        server.transport.loseConnection.assert_not_called()

    def test_rekey_marker_removal_cannot_disable_strict_kex(self):
        server, client = self.pair()
        client.supportedKeyExchanges.remove(server._KEX_STRICT_C)
        client.sendKexInit()
        pump(server, client)
        self.assertTrue(server._strict_kex)
        server.transport.loseConnection.assert_not_called()

    def test_every_current_executable_kex_completes(self):
        for algorithm in make_server().supportedKeyExchanges:
            with self.subTest(algorithm=algorithm):
                server = make_server()
                client = make_client(server, True)
                client.supportedKeyExchanges = [algorithm, server._KEX_STRICT_C]
                server.sendKexInit()
                client.sendKexInit()
                pump(server, client)
                server.transport.loseConnection.assert_not_called()
                self.assertEqual(server.kexAlg, algorithm)
                self.assertTrue(server._initial_kex_done)

    def test_incoming_newkeys_and_first_encrypted_packet_in_one_buffer(self):
        server = make_server()
        client = make_client(server, True)
        client.connectionSecure = lambda: client.sendIgnore(b"first encrypted packet")
        server.sendKexInit()
        client.sendKexInit()
        pump(server, client)
        self.assertEqual(server.incomingPacketSequence, 1)
        server.transport.loseConnection.assert_not_called()

    def test_rekey_flush_uses_reset_outgoing_counter(self):
        server, client = self.pair()
        client.service = Mock()
        server.sendKexInit()
        server.sendPacket(94, b"queued channel data")
        self.assertEqual(server._blockedByKeyExchange, [(94, b"queued channel data")])
        pump(server, client)
        self.assertEqual(server.outgoingPacketSequence, 1)
        self.assertEqual(client.incomingPacketSequence, 1)
        client.service.packetReceived.assert_called_once_with(94, b"queued channel data")
        server.transport.loseConnection.assert_not_called()

    def test_incorrect_guessed_packet_is_discarded_once(self):
        server = make_server()
        client = make_client(server, True)
        client.supportedKeyExchanges.insert(0, b"unimplemented-guess")
        server.sendKexInit()
        client.sendKexInit()
        # Set first_kex_packet_follows in the actual saved/transmitted payload.
        client.ourKexInitPayload = client.ourKexInitPayload[:-5] + b"\x01\0\0\0\0"
        client.transport.clear()
        # Re-encode KEXINIT without incrementing the sequence twice.
        client.outgoingPacketSequence = 0
        client._keyExchangeState = client._KEY_EXCHANGE_NONE
        client.sendPacket(20, client.ourKexInitPayload[1:])
        client._keyExchangeState = client._KEY_EXCHANGE_REQUESTED
        client.sendPacket(30, b"incorrect guessed key exchange")
        pump(server, client)
        server.transport.loseConnection.assert_not_called()
        self.assertTrue(server._initial_kex_done)
        self.assertFalse(server.ignoreNextPacket)

    def test_strict_state_is_per_connection(self):
        strict, _ = self.pair()
        normal = make_server()
        self.assertTrue(strict._strict_kex)
        self.assertFalse(normal._strict_kex)
        self.assertFalse(normal._initial_kex_done)

    def test_non_strict_rekeys_preserve_counters(self):
        server, client = self.pair(False)
        previous_in = server.incomingPacketSequence
        previous_out = server.outgoingPacketSequence
        for initiator in (server, client):
            initiator.sendKexInit()
            pump(server, client)
            self.assertGreater(server.incomingPacketSequence, previous_in)
            self.assertGreater(server.outgoingPacketSequence, previous_out)
            previous_in = server.incomingPacketSequence
            previous_out = server.outgoingPacketSequence
            server.transport.loseConnection.assert_not_called()

    def test_duplicate_newkeys_after_completed_exchange_is_rejected(self):
        server, client = self.pair()
        before = server.incomingPacketSequence
        client.sendPacket(transport.MSG_NEWKEYS, b"")
        server.dataReceived(client.transport.value())
        server.transport.loseConnection.assert_called_once()
        # The authenticated packet increments the old counter; it is not reset.
        self.assertEqual(server.incomingPacketSequence, before + 1)

    def test_prohibited_packet_after_ecdhe_init_is_rejected(self):
        server = make_server()
        server._strict_kex = True
        server._strict_expected = transport.MSG_NEWKEYS
        for message in (2, 3, 4, 7, 20, 30, 50, 192):
            with self.subTest(message=message):
                server._strict_disconnect = False
                server.transport.loseConnection.reset_mock()
                server.dispatchMessage(message, b"")
                server.transport.loseConnection.assert_called_once()

    def test_kex_list_does_not_contain_strict_as_an_executable_method(self):
        server = make_server()
        client = make_client(server, True)
        # A client offering only markers must fail negotiation, not execute one.
        client.supportedKeyExchanges = [server._KEX_STRICT_C, server._KEX_STRICT_S]
        server.sendKexInit()
        client.sendKexInit()
        server.dataReceived(client.transport.value())
        server.transport.loseConnection.assert_called_once()
        self.assertIsNone(server.kexAlg)

    def test_strict_handshake_without_extension_negotiation(self):
        server = make_server()
        client = make_client(server, True)
        client._EXT_INFO_C = b"test-no-extensions"
        server.sendKexInit()
        client.sendKexInit()
        pump(server, client)
        server.transport.loseConnection.assert_not_called()
        self.assertFalse(server._peerSupportsExtensions)
        self.assertEqual(server.outgoingPacketSequence, 0)
        self.assertEqual(server.incomingPacketSequence, 0)
