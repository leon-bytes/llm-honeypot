# SPDX-License-Identifier: BSD-3-Clause
"""OpenSSH Ping/Pong validation, dispatch and encrypted rekey queues."""

import unittest
from unittest.mock import Mock

from twisted.conch.ssh.common import NS

from cowrie.test.test_strict_kex import make_client, make_server, pump


class PingPongTests(unittest.TestCase):
    def test_valid_ping_echoes_exact_string(self):
        for data in (b"", b"hello", bytes(range(256)), b"\0\xff\r\n"):
            with self.subTest(data=data):
                server = make_server()
                server.sendPacket = Mock()
                server.dispatchMessage(192, NS(data))
                server.sendPacket.assert_called_once_with(193, NS(data))
                server.transport.loseConnection.assert_not_called()

    def test_malformed_ping_and_pong_disconnect_without_reply(self):
        for message in (192, 193):
            for payload in (b"", b"\0", b"\0\0\0", b"\0\0\0\x05xy",
                            NS(b"") + b"extra", NS(b"one") + NS(b"two"),
                            b"\xff\xff\xff\xff"):
                with self.subTest(message=message, payload=payload):
                    server = make_server()
                    server.sendPacket = Mock()
                    server.dispatchMessage(message, payload)
                    server.sendPacket.assert_not_called()
                    server.transport.loseConnection.assert_called_once()
                    self.assertTrue(server._strict_disconnect)

    def test_unexpected_pong_is_ignored_without_service_dispatch(self):
        server = make_server()
        server.service = Mock()
        server.sendPacket = Mock()
        server.dispatchMessage(193, NS(b"unsolicited"))
        server.service.packetReceived.assert_not_called()
        server.sendPacket.assert_not_called()
        server.transport.loseConnection.assert_not_called()

    def test_strict_initial_handshake_rejects_ping_and_pong(self):
        for expected in (30, 21):
            for message in (192, 193):
                with self.subTest(expected=expected, message=message):
                    server = make_server()
                    server._strict_kex = True
                    server._strict_expected = expected
                    server.sendPacket = Mock()
                    server.dispatchMessage(message, NS(b"probe"))
                    server.transport.loseConnection.assert_called_once()
                    server.sendPacket.assert_not_called()

    def pair(self, strict):
        server = make_server()
        client = make_client(server, strict)
        client.service = Mock()
        server.sendKexInit()
        client.sendKexInit()
        pump(server, client)
        return server, client

    def test_encrypted_ping_and_pong_dispatch_after_handshake(self):
        for strict in (False, True):
            with self.subTest(strict=strict):
                server, client = self.pair(strict)
                server.service = Mock()
                client.sendPacket(192, NS(b"\0\xffprobe"))
                client.sendPacket(193, NS(b"unexpected pong"))
                pump(server, client)
                client.service.packetReceived.assert_called_once_with(193, NS(b"\0\xffprobe"))
                server.service.packetReceived.assert_not_called()
                server.transport.loseConnection.assert_not_called()

    def test_pongs_queue_in_order_through_real_rekey(self):
        for strict in (False, True):
            for initiator in ("server", "client"):
                with self.subTest(strict=strict, initiator=initiator):
                    server, client = self.pair(strict)
                    # Establish an active exchange on the server before probes.
                    if initiator == "server":
                        server.sendKexInit()
                    else:
                        client.sendKexInit()
                        server.dataReceived(client.transport.value())
                        client.transport.clear()
                    server.dispatchMessage(192, NS(b"first"))
                    server.dispatchMessage(192, NS(b"\0\xffsecond"))
                    self.assertEqual(server._blockedByKeyExchange, [
                        (193, NS(b"first")), (193, NS(b"\0\xffsecond")),
                    ])
                    client.service.packetReceived.assert_not_called()
                    pump(server, client)
                    self.assertEqual(
                        [(c.args[0], c.args[1]) for c in client.service.packetReceived.call_args_list],
                        [(193, NS(b"first")), (193, NS(b"\0\xffsecond"))],
                    )
                    server.transport.loseConnection.assert_not_called()
                    if strict:
                        self.assertEqual(server.outgoingPacketSequence, 2)

    def test_ping_extension_is_advertised(self):
        server, client = self.pair(True)
        self.assertEqual(client.peerExtensions, {b"server-sig-algs": server._SERVER_SIG_ALGS, b"ping@openssh.com": b"0"})

    def test_ping_before_initial_strict_kexinit_cannot_bypass_ordering(self):
        server = make_server()
        client = make_client(server, True)
        server.sendKexInit()
        client.sendPacket(192, NS(b"before initial KEXINIT"))
        client.sendKexInit()
        server.dataReceived(client.transport.value())
        server.transport.loseConnection.assert_called_once()
        self.assertTrue(server._strict_disconnect)
        # The reply was queued, never sent before strict negotiation failed.
        self.assertEqual(server._blockedByKeyExchange, [
            (193, NS(b"before initial KEXINIT")),
        ])
