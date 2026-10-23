# SPDX-License-Identifier: BSD-3-Clause
"""Encrypted extension ordering and advertised signature capability checks."""

import struct
import unittest
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from twisted.conch.ssh import keys, userauth
from twisted.conch.ssh.common import NS, getNS

from cowrie.ssh.userauth import HoneyPotSSHUserAuthServer
from cowrie.test.test_strict_kex import make_client, make_server, pump

REFERENCE_SIG_ALGS = (
    b"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
    b"sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,"
    b"rsa-sha2-512,rsa-sha2-256"
)


def ext_info(entries):
    return struct.pack("!L", len(entries)) + b"".join(NS(k) + NS(v) for k, v in entries)


class ExtInfoTests(unittest.TestCase):
    def pair(self, strict=True, extensions=True, auth_version=b"0"):
        server = make_server()
        client = make_client(server, strict)
        if not extensions:
            client._EXT_INFO_C = b"test-no-extensions"
        if auth_version is not None:
            sent = []

            def secure():
                if not sent:
                    sent.append(True)
                    client.sendPacket(7, ext_info([(b"ext-info-in-auth@openssh.com", auth_version)]))

            client.connectionSecure = secure
        self.messages = []
        original = client.dispatchMessage

        def received(number, payload):
            self.messages.append((number, payload))
            original(number, payload)

        client.dispatchMessage = received
        client.service = Mock()
        server.sendKexInit()
        client.sendKexInit()
        pump(server, client)
        server.transport.loseConnection.assert_not_called()
        return server, client

    def authenticate(self, server, client):
        server.service = Mock()
        server.service.name = b"ssh-userauth"
        # A synchronous auth result exercises ordering before service changes.
        server.service.packetReceived.side_effect = lambda *args: server.sendPacket(51, NS(b"password") + b"\0")
        client.sendPacket(50, NS(b"test-user") + NS(b"ssh-connection") + NS(b"none"))
        pump(server, client)

    def test_initial_contents_and_first_post_newkeys_order(self):
        for strict in (False, True):
            with self.subTest(strict=strict):
                server, client = self.pair(strict)
                self.assertEqual(server._SERVER_SIG_ALGS, REFERENCE_SIG_ALGS)
                numbers = [n for n, _ in self.messages]
                self.assertEqual(numbers[numbers.index(21) + 1:], [7])
                self.assertEqual(client.peerExtensions, {
                    b"server-sig-algs": server._SERVER_SIG_ALGS,
                    b"ping@openssh.com": b"0",
                })
                self.assertNotIn(b"publickey-hostbound@openssh.com", client.peerExtensions)
                self.assertFalse(any("hostbound" in n for n in dir(HoneyPotSSHUserAuthServer)))
                self.assertEqual(
                    [p for n, p in self.messages if n == 7],
                    [ext_info([(b"server-sig-algs", server._SERVER_SIG_ALGS), (b"ping@openssh.com", b"0")])],
                )

    def test_no_client_marker_means_no_server_ext_info(self):
        server, client = self.pair(extensions=False)
        self.authenticate(server, client)
        self.assertFalse(any(n == 7 for n, _ in self.messages))

    def test_auth_update_after_request_before_synchronous_result_once(self):
        server, client = self.pair()
        self.messages.clear()
        self.authenticate(server, client)
        self.assertEqual([n for n, _ in self.messages], [7, 51])
        self.assertEqual(self.messages[0][1], ext_info([(b"server-sig-algs", server._SERVER_SIG_ALGS)]))
        self.messages.clear()
        self.authenticate(server, client)
        self.assertEqual([n for n, _ in self.messages], [51])

    def test_missing_or_unknown_auth_extension_version_has_no_update(self):
        for version in (None, b"1", b"0\0"):
            with self.subTest(version=version):
                server, client = self.pair(auth_version=version)
                self.messages.clear()
                self.authenticate(server, client)
                self.assertEqual([n for n, _ in self.messages], [51])

    def test_service_request_stage_does_not_send_auth_update(self):
        server, client = self.pair()
        self.messages.clear()
        service = Mock()
        service.name = b"ssh-userauth"
        server.factory.getService = Mock(return_value=lambda: service)
        client.instance = Mock()
        client.instance.name = b"ssh-userauth"
        client.sendPacket(5, NS(b"ssh-userauth"))
        pump(server, client)
        self.assertFalse(server._userauth_request_seen)
        self.assertEqual([n for n, _ in self.messages], [6])

    def test_auth_update_queues_before_result_during_rekey(self):
        server, client = self.pair()
        self.messages.clear()
        server.service = Mock()
        server.service.name = b"ssh-userauth"
        server.service.packetReceived.side_effect = lambda *args: server.sendPacket(51, NS(b"password") + b"\0")
        server.sendKexInit()
        client.sendPacket(50, NS(b"test-user") + NS(b"ssh-connection") + NS(b"none"))
        server.dataReceived(client.transport.value())
        client.transport.clear()
        self.assertEqual([n for n, _ in server._blockedByKeyExchange], [7, 51])
        pump(server, client)
        numbers = [n for n, _ in self.messages]
        self.assertEqual(numbers[numbers.index(21) + 1:], [7, 51])
        server.transport.loseConnection.assert_not_called()

    def test_malformed_auth_request_does_not_send_update(self):
        server, client = self.pair()
        self.messages.clear()
        server.service = Mock()
        server.service.name = b"ssh-userauth"
        client.sendPacket(50, NS(b"user") + b"\0\0\0\x05xy")
        server.dataReceived(client.transport.value())
        self.assertFalse(server._userauth_request_seen)
        self.assertEqual(self.messages, [])
        server.transport.loseConnection.assert_called_once()

    def test_rekeys_do_not_repeat_initial_ext_info_and_keep_initial_negotiation(self):
        server, client = self.pair()
        self.messages.clear()
        client._EXT_INFO_C = b"test-no-extensions-during-rekey"
        for peer in (server, client):
            peer.sendKexInit()
            pump(server, client)
        self.assertFalse(any(n == 7 for n, _ in self.messages))
        self.messages.clear()
        self.authenticate(server, client)
        self.assertEqual([n for n, _ in self.messages], [7, 51])

    def test_late_client_extension_cannot_enable_auth_update(self):
        server, client = self.pair(auth_version=None)
        client.sendIgnore(b"first post-NEWKEYS packet")
        client.sendPacket(7, ext_info([(b"ext-info-in-auth@openssh.com", b"0")]))
        pump(server, client)
        self.messages.clear()
        self.authenticate(server, client)
        self.assertEqual([n for n, _ in self.messages], [51])

    def test_malformed_ext_info_disconnects(self):
        for payload in (b"", struct.pack("!L", 1), ext_info([]) + b"extra",
                        struct.pack("!L", 1) + NS(b"name") + b"\0\0\0\x05xy"):
            with self.subTest(payload=payload):
                server, client = self.pair(auth_version=None)
                client.sendPacket(7, payload)
                pump(server, client)
                server.transport.loseConnection.assert_called_once()
                self.assertFalse(server._ext_info_in_auth)

    def test_existing_extension_entries_are_preserved_and_not_duplicated(self):
        server = make_server()
        server._peerSupportsExtensions = True
        server.sendPacket = Mock()
        server.sendExtInfo([(b"server-sig-algs", b"old"), (b"custom", b"binary\0value")])
        server.sendExtInfo([])
        server.sendPacket.assert_called_once_with(7, ext_info([
            (b"server-sig-algs", server._SERVER_SIG_ALGS),
            (b"custom", b"binary\0value"), (b"ping@openssh.com", b"0"),
        ]))


class SignatureCapabilityTests(unittest.TestCase):
    def test_all_reference_signature_algorithms_parse_and_verify(self):
        ed = keys.Key(ed25519.Ed25519PrivateKey.generate())
        rsa_key = keys.Key(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        examples = [(b"ssh-ed25519", ed)]
        for curve, name in ((ec.SECP256R1(), b"nistp256"), (ec.SECP384R1(), b"nistp384"),
                            (ec.SECP521R1(), b"nistp521")):
            examples.append((b"ecdsa-sha2-" + name, keys.Key(ec.generate_private_key(curve))))
        examples += [(b"rsa-sha2-512", rsa_key), (b"rsa-sha2-256", rsa_key)]
        verified = set()
        for algorithm, private in examples:
            with self.subTest(algorithm=algorithm):
                public = keys.Key.fromString(private.public().blob(), type="blob")
                signature = private.sign(b"test authentication", signatureType=algorithm)
                self.assertTrue(public.verify(signature, b"test authentication"))
                self.assertFalse(public.verify(signature, b"modified"))
                verified.add(algorithm)
        for algorithm, private in (
            (b"sk-ssh-ed25519@openssh.com", ed),
            (b"sk-ecdsa-sha2-nistp256@openssh.com", examples[1][1]),
        ):
            with self.subTest(algorithm=algorithm):
                application = b"ssh:test"
                _, components = getNS(private.public().blob())
                public = keys.Key.fromString(NS(algorithm) + components + NS(application), type="blob")
                flags_counter = b"\x01" + struct.pack("!L", 1)
                placeholder = NS(algorithm) + NS(b"placeholder") + flags_counter
                wrapped = userauth.SSHUserAuthServer._wrapMessageWithSKMetadata(
                    placeholder, b"test authentication", application
                )
                _, signature, _ = getNS(private.sign(wrapped), 2)
                sk_signature = NS(algorithm) + NS(signature) + flags_counter
                self.assertTrue(public.verify(sk_signature, wrapped))
                self.assertFalse(public.verify(sk_signature, b"modified"))
                verified.add(algorithm)
        self.assertEqual(verified, set(make_server()._SERVER_SIG_ALGS.split(b",")))
