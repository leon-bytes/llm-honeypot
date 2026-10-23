# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
# SPDX-License-Identifier: BSD-3-Clause

"""SSH exec uses the shell relay and completes without an interactive prompt."""

from __future__ import annotations

import json
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from twisted.conch.ssh.common import NS
from twisted.internet.defer import Deferred, succeed
from twisted.internet.task import Clock
from twisted.internet.testing import StringTransport
from twisted.web.client import Agent, ProxyAgent

from cowrie.insults import insults
from cowrie.llm import llm as llm_module
from cowrie.llm.llm import LLMClient
from cowrie.shell import honeypot, protocol
from cowrie.shell.session import SSHSessionForCowrieUser
from cowrie.ssh.session import HoneyPotSSHSession


def response(content="", exit_code=0, close_session=False):
    return {
        "choices": [{"message": {"content": content}}],
        "honeypot": {
            "exit_code": exit_code,
            "close_session": close_session,
            "prompt": "root@host:~# ",
        },
    }


class RelayExecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.command = Deferred()
        self.client = MagicMock()
        self.client.get_relay_response.side_effect = [
            self.command,
            Deferred(),
        ]
        for module in (protocol, honeypot):
            patcher = patch.object(
                module, "get_shared_client", return_value=self.client
            )
            patcher.start()
            self.addCleanup(patcher.stop)

        def connection_made(proto):
            proto.events = MagicMock()
            proto.sessionid = "exec-session"
            proto.realClientIP = "192.0.2.1"
            proto.realClientPort = 12345
            proto.realServerIP = "192.0.2.2"
            proto.realServerPort = 22

        patcher = patch.object(
            protocol.HoneyPotBaseProtocol, "connectionMade", connection_made
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.avatar = MagicMock()
        self.avatar.environ = {"HOME": "/root"}
        self.avatar.username = "root"
        self.terminal = MagicMock()
        self.proto = protocol.HoneyPotExecProtocol(self.avatar, b"uname -a")
        self.proto.makeConnection(self.terminal)
        self.addCleanup(self.proto.setTimeout, None)

    def test_interactive_ctrl_c_redraws_last_relay_prompt(self) -> None:
        login = Deferred()
        self.client.get_relay_response.side_effect = [login, succeed(None)]
        proto = protocol.HoneyPotInteractiveProtocol(self.avatar)
        terminal = MagicMock()
        proto.makeConnection(terminal)
        self.addCleanup(proto.setTimeout, None)
        proto.hostname = "svr04"
        relay_response = response()
        relay_response["honeypot"]["prompt"] = "root@relay-host:/tmp# "
        login.callback(relay_response)
        terminal.write.reset_mock()
        proto.lineBuffer = [b"u", b"n"]
        proto.lineBufferIndex = 2

        proto.keystrokeReceived(b"\x03", None)

        output = b"".join(call.args[0] for call in terminal.write.call_args_list)
        self.assertEqual(output, b"^C\nroot@relay-host:/tmp# ")
        self.assertNotIn(b"svr04", output)
        self.assertEqual(proto.lineBuffer, [])
        self.assertEqual(proto.lineBufferIndex, 0)
        terminal.transport.processEnded.assert_not_called()

    def test_ctrl_c_without_relay_login_uses_existing_prompt_path(self) -> None:
        self.proto.cmdstack = []
        shell = honeypot.HoneyPotShell(self.proto, interactive=True)
        with patch.object(shell, "showPrompt") as show_prompt:
            shell.handle_CTRL_C()
        show_prompt.assert_called_once_with()
        self.terminal.write.assert_called_once_with(b"^C\n")

    def test_noninteractive_ctrl_c_does_not_display_relay_prompt(self) -> None:
        self.proto.relay_login_complete = True
        self.proto.cmdstack[0].handle_CTRL_C()
        self.terminal.write.assert_called_once_with(b"\n")
        self.terminal.transport.processEnded.assert_not_called()

    def test_single_exec_contains_command_and_metadata(self) -> None:
        self.client.get_relay_response.assert_called_once_with(
            session_id=self.proto.sessionid,
            event="exec",
            content="uname -a",
            username="root",
            src_ip="192.0.2.1",
            src_port=12345,
            dst_ip="192.0.2.2",
            dst_port=22,
        )
        self.terminal.write.assert_not_called()
        self.command.callback(response())
        self.proto.connectionLost()
        self.assertEqual(self.client.get_relay_response.call_count, 1)

    def test_output_exit_status_and_no_prompt(self) -> None:
        self.command.callback(response("Linux relay\n", exit_code=7))
        self.terminal.write.assert_called_once_with(b"Linux relay\n")
        self.terminal.transport.processEnded.assert_called_once()
        reason = self.terminal.transport.processEnded.call_args.args[0]
        self.assertEqual(reason.value.exitCode, 7)
        self.assertEqual(self.proto.cmdstack, [])

    def test_channel_ids_are_unique_and_command_is_preserved(self) -> None:
        self.client.get_relay_response.side_effect = None
        self.client.get_relay_response.return_value = Deferred()
        raw = b"  printf 'a\\nb'; uname -a  "
        other = protocol.HoneyPotExecProtocol(self.avatar, raw)
        other.makeConnection(MagicMock())
        self.addCleanup(other.setTimeout, None)
        self.assertNotEqual(self.proto.sessionid, other.sessionid)
        self.assertEqual(
            self.client.get_relay_response.call_args.kwargs["content"], raw.decode()
        )

    def test_explicit_pty_converts_newlines(self) -> None:
        self.avatar.pty_allocated = True
        self.command.callback(response("Linux relay\n"))
        self.terminal.write.assert_called_once_with(b"Linux relay\r\n")

    def test_term_environment_alone_does_not_convert_newlines(self) -> None:
        self.avatar.environ["TERM"] = "xterm"
        self.command.callback(response("Linux relay\n"))
        self.terminal.write.assert_called_once_with(b"Linux relay\n")

    def test_invalid_responses_close_without_output(self) -> None:
        for invalid in (
            None,
            {},
            [],
            {"choices": []},
            response(exit_code="bad"),
            response(content=123),
            response(exit_code=-1),
            response(exit_code=True),
            response(exit_code=0x100000000),
            response(content="\ud800"),
        ):
            with self.subTest(response=invalid):
                pending = Deferred()
                self.client.get_relay_response.side_effect = None
                self.client.get_relay_response.return_value = pending
                proto = protocol.HoneyPotExecProtocol(self.avatar, b"id")
                terminal = MagicMock()
                proto.makeConnection(terminal)
                self.addCleanup(proto.setTimeout, None)
                pending.callback(invalid)
                terminal.write.assert_not_called()
                terminal.transport.processEnded.assert_called_once()
                self.assertEqual(
                    terminal.transport.processEnded.call_args.args[0].value.exitCode, 1
                )

    def test_timeout_ignores_late_response(self) -> None:
        self.proto.timeoutConnection()
        self.command.callback(response("late output\n"))
        self.terminal.write.assert_not_called()
        self.terminal.transport.processEnded.assert_called_once()
        self.assertEqual(
            self.terminal.transport.processEnded.call_args.args[0].value.exitCode, 1
        )

    def test_synchronous_relay_failure_closes_with_error(self) -> None:
        self.client.get_relay_response.side_effect = RuntimeError("relay unavailable")
        proto = protocol.HoneyPotExecProtocol(self.avatar, b"id")
        terminal = MagicMock()
        proto.makeConnection(terminal)
        terminal.write.assert_not_called()
        terminal.transport.processEnded.assert_called_once()
        self.assertEqual(
            terminal.transport.processEnded.call_args.args[0].value.exitCode, 1
        )

    def test_stdin_eof_does_not_end_pending_command(self) -> None:
        self.proto.eofReceived()
        self.proto.eofReceived()
        self.terminal.transport.processEnded.assert_not_called()
        self.command.callback(response())
        self.terminal.transport.processEnded.assert_called_once()
        self.terminal.write.assert_not_called()

    def test_close_session_ends_once(self) -> None:
        self.command.callback(response("bye\n", close_session=True))
        self.proto.eofReceived()
        self.terminal.transport.processEnded.assert_called_once()
        self.assertTrue(self.proto.relay_session_closed)

    def test_missing_response_ends_with_error(self) -> None:
        self.command.callback(None)
        reason = self.terminal.transport.processEnded.call_args.args[0]
        self.assertEqual(reason.value.exitCode, 1)
        self.terminal.write.assert_not_called()

    def test_command_request_failure_ends_with_error(self) -> None:
        self.command.errback(RuntimeError("relay unavailable"))
        reason = self.terminal.transport.processEnded.call_args.args[0]
        self.assertEqual(reason.value.exitCode, 1)
        self.terminal.write.assert_not_called()

    def test_ssh_exec_request_returns_output_status_and_closes_channel(self) -> None:
        # Exercise Conch's request_exec and process protocol, plus Cowrie's
        # session adapter and logging terminal wrapper, without a network.
        command = Deferred()
        self.client.get_relay_response.side_effect = [command]
        self.avatar.uid = 0
        self.avatar.gid = 0
        self.avatar.home = "/root"
        self.avatar.temporary = False
        channel = HoneyPotSSHSession.__new__(HoneyPotSSHSession)
        channel.session = SSHSessionForCowrieUser(self.avatar)
        channel.buf = b""
        channel.id = 0
        channel.conn = MagicMock()
        channel.conn.transport.transportId = "exec-session"
        channel.write = MagicMock()
        channel.loseConnection = MagicMock()
        with patch.object(insults.LoggingServerProtocol, "ttylogEnabled", False):
            self.assertEqual(channel.request_exec(NS(b"uname -a")), 1)
        self.addCleanup(channel.session.protocol.terminalProtocol.setTimeout, None)
        channel.eofReceived()
        channel.loseConnection.assert_not_called()
        command.callback(response("Linux relay\n", exit_code=7))
        channel.write.assert_called_once_with(b"Linux relay\n")
        channel.conn.sendRequest.assert_called_once_with(
            channel,
            b"exit-status",
            b"\x00\x00\x00\x07",
        )
        channel.loseConnection.assert_called_once()

    def test_interactive_login_still_flushes_commands_and_displays_prompts(
        self,
    ) -> None:
        login, command = Deferred(), Deferred()
        self.client.get_relay_response.side_effect = [login, command]
        proto = protocol.HoneyPotInteractiveProtocol(self.avatar)
        terminal = MagicMock()
        proto.makeConnection(terminal)
        self.addCleanup(proto.setTimeout, None)
        terminal.write.reset_mock()
        proto.lineReceived(b"uname -a")
        self.assertEqual(proto.cmdstack[0].pending_relay_lines, ["uname -a"])
        login.callback(response("welcome\n"))
        self.assertTrue(proto.relay_login_complete)
        self.client.get_relay_response.assert_called_with(
            session_id=proto.sessionid,
            event="command",
            content="uname -a",
            username="root",
        )
        command.callback(response("Linux relay\n"))
        self.assertEqual(
            [call.args[0] for call in terminal.write.call_args_list],
            [b"welcome\n", b"root@host:~# ", b"Linux relay\n", b"root@host:~# "],
        )
        terminal.transport.processEnded.assert_not_called()

    def test_late_response_after_disconnect_is_ignored(self) -> None:
        self.proto.connectionLost()
        self.command.callback(response("late output\n"))
        self.terminal.write.assert_not_called()
        self.terminal.transport.processEnded.assert_not_called()
        self.assertEqual(self.client.get_relay_response.call_count, 1)

    def test_late_failure_after_disconnect_is_ignored(self) -> None:
        self.proto.connectionLost()
        self.command.errback(RuntimeError("relay unavailable"))
        self.terminal.write.assert_not_called()
        self.terminal.transport.processEnded.assert_not_called()
        self.assertEqual(self.client.get_relay_response.call_count, 1)

    def test_interactive_disconnect_still_sends_logout(self) -> None:
        self.client.get_relay_response.side_effect = [Deferred(), Deferred()]
        proto = protocol.HoneyPotInteractiveProtocol(self.avatar)
        proto.makeConnection(MagicMock())
        proto.connectionLost()
        self.client.get_relay_response.assert_called_with(
            session_id=proto.sessionid, event="logout", content="", username="root"
        )

    def test_pty_allocation_is_explicit(self) -> None:
        self.avatar.uid = self.avatar.gid = 0
        self.avatar.home = "/root"
        self.avatar.temporary = False
        session = SSHSessionForCowrieUser(self.avatar)
        self.assertFalse(session.pty_allocated)
        session.getPty(b"xterm", (24, 80, 0, 0), [])
        self.assertTrue(session.pty_allocated)

    def test_interactive_response_preserves_prompt_and_session(self) -> None:
        self.proto.cmdstack = []
        shell = honeypot.HoneyPotShell(self.proto, interactive=True)
        self.proto.cmdstack = [shell]
        shell.handle_relay_response(response("Linux relay\n"))
        self.assertEqual(
            [call.args[0] for call in self.terminal.write.call_args_list],
            [b"Linux relay\n", b"root@host:~# "],
        )
        self.terminal.transport.processEnded.assert_not_called()


class InteractiveRelaySessionIdTests(unittest.TestCase):
    """Several channel protocols can share one SSH transport and avatar."""

    def setUp(self):
        self.client = MagicMock()
        self.client.get_relay_response.side_effect = lambda **kwargs: succeed(response())
        self.transport = SimpleNamespace(transportId="shared-transport", events=MagicMock())
        self.avatar = MagicMock()
        self.avatar.environ = {"HOME": "/root"}
        self.avatar.username = "root"
        for module in (protocol, honeypot):
            patcher = patch.object(module, "get_shared_client", return_value=self.client)
            patcher.start()
            self.addCleanup(patcher.stop)

        def initialize(proto):
            transport = proto.getProtoTransport()
            proto.sessionid = transport.transportId
            proto.events = transport.events
            proto.realClientIP, proto.realServerIP = "192.0.2.1", "192.0.2.2"
            proto.realClientPort, proto.realServerPort = 12345, 22

        patcher = patch.object(protocol.HoneyPotBaseProtocol, "connectionMade", initialize)
        patcher.start()
        self.addCleanup(patcher.stop)

    def new_shell(self, transport=None):
        proto = protocol.HoneyPotInteractiveProtocol(self.avatar)
        terminal = MagicMock()
        terminal.transport.session.conn.transport = transport or self.transport
        proto.makeConnection(terminal)
        self.addCleanup(proto.setTimeout, None)
        return proto

    def test_shared_transport_shells_get_distinct_uuid_ids_before_login(self):
        first, second = self.new_shell(), self.new_shell()
        self.assertIs(first.getProtoTransport(), second.getProtoTransport())
        self.assertNotEqual(first.sessionid, second.sessionid)
        for proto in (first, second):
            self.assertRegex(proto.sessionid, r"^[0-9a-f]{32}$")
            self.assertNotEqual(proto.sessionid, self.transport.transportId)
            self.assertIs(proto.events, self.transport.events)
        logins = self.client.get_relay_response.call_args_list
        self.assertEqual([call.kwargs["session_id"] for call in logins], [first.sessionid, second.sessionid])
        self.assertEqual(self.transport.transportId, "shared-transport")

    def test_id_is_stable_across_commands_interrupt_prompt_and_logout(self):
        proto = self.new_shell()
        sessionid = proto.sessionid
        proto.lineReceived(b"pwd")
        proto.keystrokeReceived(b"\x03", None)
        reply = response()
        reply["honeypot"]["prompt"] = "new prompt> "
        proto.cmdstack[0].handle_relay_response(reply)
        proto.lineReceived(b"hostname")
        proto.connectionLost()
        proto.connectionLost()
        calls = self.client.get_relay_response.call_args_list
        self.assertEqual([call.kwargs["event"] for call in calls], ["login", "command", "interrupt", "command", "logout"])
        self.assertEqual({call.kwargs["session_id"] for call in calls}, {sessionid})
        self.assertEqual(proto.sessionid, sessionid)
        self.assertEqual(self.transport.transportId, "shared-transport")

    def test_closed_channel_and_reconnect_never_reuse_shell_id(self):
        first, survivor = self.new_shell(), self.new_shell()
        first.connectionLost()
        additional = self.new_shell()
        reconnected_transport = SimpleNamespace(transportId="new-transport", events=MagicMock())
        reconnected = self.new_shell(reconnected_transport)
        self.assertEqual(len({p.sessionid for p in (first, survivor, additional, reconnected)}), 4)
        survivor.lineReceived(b"pwd")
        self.client.get_relay_response.assert_called_with(
            session_id=survivor.sessionid, event="command", content="pwd", username="root"
        )
        self.assertFalse(survivor._interactive_closing)
        self.assertEqual(self.transport.transportId, "shared-transport")
        self.assertEqual(reconnected_transport.transportId, "new-transport")


class InteractiveRelayTerminalSizeTests(unittest.TestCase):
    def setUp(self):
        InteractiveRelaySessionIdTests.setUp(self)
        self.ssh_avatar = self.avatar
        self.ssh_avatar.home = "/root"
        self.ssh_avatar.uid = self.ssh_avatar.gid = 0
        self.ssh_avatar.temporary = False

    def shell_with_pty(self, size=None):
        self.avatar = SSHSessionForCowrieUser(self.ssh_avatar)
        if size is not None:
            self.avatar.getPty(b"xterm", size, [])
        return InteractiveRelaySessionIdTests.new_shell(self)

    def assert_size(self, rows=None, cols=None):
        metadata = self.client.get_relay_response.call_args.kwargs
        for name, expected in (("rows", rows), ("cols", cols)):
            if expected is None:
                self.assertNotIn(name, metadata)
            else:
                self.assertEqual(metadata[name], expected)

    def test_login_uses_pty_rows_then_columns(self):
        proto = self.shell_with_pty((37, 200, 1024, 768))
        self.assert_size(rows=37, cols=200)
        self.assertEqual(proto.user.windowSize, (37, 200, 1024, 768))

    def test_resize_is_local_and_next_command_uses_new_dimensions(self):
        proto = self.shell_with_pty((24, 80, 0, 0))
        count = self.client.get_relay_response.call_count
        proto.user.windowChanged((48, 160, 0, 0))
        self.assertEqual(self.client.get_relay_response.call_count, count)
        proto.lineReceived(b"pwd")
        self.assert_size(rows=48, cols=160)

    def test_ssh_window_change_packet_updates_rows_columns(self):
        proto = self.shell_with_pty((24, 80, 0, 0))
        channel = HoneyPotSSHSession.__new__(HoneyPotSSHSession)
        channel.session = proto.user
        count = self.client.get_relay_response.call_count
        # SSH encodes columns first; Twisted passes rows first to the adapter.
        self.assertEqual(channel.request_window_change(struct.pack(">4L", 211, 43, 0, 0)), 1)
        self.assertEqual(proto.user.windowSize, (43, 211, 0, 0))
        self.assertEqual(self.client.get_relay_response.call_count, count)
        proto.lineReceived(b"pwd")
        self.assert_size(rows=43, cols=211)

    def test_queued_commands_read_dimensions_when_dispatched(self):
        proto = self.shell_with_pty((24, 80, 0, 0))
        first, second = Deferred(), Deferred()
        self.client.get_relay_response.side_effect = [first, second]
        proto.lineReceived(b"first")
        self.assert_size(rows=24, cols=80)
        proto.lineReceived(b"second")
        proto.user.windowChanged((51, 201, 0, 0))
        first.callback(response())
        self.assert_size(rows=51, cols=201)
        second.callback(response())

    def test_interrupt_uses_current_dimensions_while_command_pending(self):
        proto = self.shell_with_pty((24, 80, 0, 0))
        command = Deferred()
        self.client.get_relay_response.side_effect = [command, succeed(response())]
        proto.lineReceived(b"slow")
        proto.user.windowChanged((40, 180, 0, 0))
        proto.keystrokeReceived(b"\x03", None)
        self.assertEqual(self.client.get_relay_response.call_args.kwargs["event"], "interrupt")
        self.assert_size(rows=40, cols=180)
        self.assertFalse(command.called)
        command.callback(response("stale"))

    def test_channels_keep_dimensions_independent(self):
        first = self.shell_with_pty((24, 80, 0, 0))
        second = self.shell_with_pty((50, 200, 0, 0))
        self.assertNotEqual(first.sessionid, second.sessionid)
        first.user.windowChanged((35, 120, 0, 0))
        second.lineReceived(b"pwd")
        self.assert_size(rows=50, cols=200)
        first.lineReceived(b"pwd")
        self.assert_size(rows=35, cols=120)

    def test_missing_pty_size_is_omitted_for_all_supported_events(self):
        proto = self.shell_with_pty()
        self.assert_size()
        proto.lineReceived(b"pwd")
        self.assert_size()
        proto.keystrokeReceived(b"\x03", None)
        self.assert_size()

    def test_invalid_dimensions_are_omitted_individually(self):
        proto = self.shell_with_pty((24, 80, 0, 0))
        for size, expected in (
            ((0, 200, 0, 0), {"cols": 200}),
            ((40, 0, 0, 0), {"rows": 40}),
            ((-1, "80", 0, 0), {}),
            ((True, 1.5, 0, 0), {}),
            ((None, None), {}),
            (None, {}),
            ((), {}),
            ("24x80", {}),
        ):
            with self.subTest(size=size):
                proto.user.windowChanged(size)
                proto.lineReceived(b"pwd")
                self.assert_size(**expected)


class InteractiveRelayInterruptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = MagicMock()
        self.login = Deferred()
        self.pending = []

        def request(**kwargs):
            if kwargs["event"] == "login":
                return self.login
            if kwargs["event"] == "interrupt":
                return succeed({"honeypot": {"prompt": self.shell.last_relay_prompt}})
            pending = Deferred()
            if kwargs["event"] == "command":
                self.pending.append(pending)
            return pending

        self.client.get_relay_response.side_effect = request
        for module in (protocol, honeypot):
            patcher = patch.object(module, "get_shared_client", return_value=self.client)
            patcher.start()
            self.addCleanup(patcher.stop)

        def connection_made(proto):
            proto.events = MagicMock()
            proto.sessionid = "interactive-session"
            proto.realClientIP = "192.0.2.1"
            proto.realClientPort = 12345
            proto.realServerIP = "192.0.2.2"
            proto.realServerPort = 22

        patcher = patch.object(
            protocol.HoneyPotBaseProtocol, "connectionMade", connection_made
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        avatar = MagicMock()
        avatar.environ = {"HOME": "/root"}
        avatar.username = "root"
        self.proto = protocol.HoneyPotInteractiveProtocol(avatar)
        self.terminal = MagicMock()
        self.proto.makeConnection(self.terminal)
        self.addCleanup(self.proto.setTimeout, None)
        self.login.callback(response())
        self.shell = self.proto.cmdstack[0]
        self.shell.last_exit_code = 7
        self.terminal.write.reset_mock()

    def interrupt(self) -> None:
        self.proto.keystrokeReceived(b"\x03", None)

    def assert_no_stale_effects(self) -> None:
        self.terminal.write.assert_not_called()
        self.terminal.transport.processEnded.assert_not_called()
        self.assertEqual(self.shell.last_relay_prompt, "root@host:~# ")
        self.assertEqual(self.shell.last_exit_code, 7)
        self.assertFalse(self.proto.relay_session_closed)

    def test_delayed_success_and_metadata_are_ignored(self) -> None:
        self.proto.lineReceived(b"slow")
        self.proto.lineBuffer = [b"x"]
        self.proto.lineBufferIndex = 1
        self.interrupt()
        self.assertEqual(
            [call.args[0] for call in self.terminal.write.call_args_list],
            [b"^C\n", b"root@host:~# "],
        )
        self.assertEqual(self.proto.lineBuffer, [])
        self.assertEqual(self.proto.lineBufferIndex, 0)
        self.terminal.write.reset_mock()
        stale = response("stale output\n", exit_code=99)
        stale["honeypot"]["prompt"] = "stale prompt"
        self.pending[0].callback(stale)
        self.assert_no_stale_effects()

    def test_delayed_failure_is_consumed_without_prompt_or_log(self) -> None:
        with patch.object(self.shell, "handle_relay_error") as handler:
            self.proto.lineReceived(b"slow")
            self.interrupt()
            self.terminal.write.reset_mock()
            self.pending[0].errback(RuntimeError("relay unavailable"))
            handler.assert_not_called()
        self.assertIsNone(self.pending[0].result)
        self.assert_no_stale_effects()

    def test_stale_none_response_does_not_redraw_prompt(self) -> None:
        self.proto.lineReceived(b"slow")
        self.interrupt()
        self.terminal.write.reset_mock()
        self.pending[0].callback(None)
        self.assert_no_stale_effects()

    def test_stale_session_closure_is_ignored(self) -> None:
        self.proto.lineReceived(b"slow")
        self.interrupt()
        self.terminal.write.reset_mock()
        self.pending[0].callback(response("bye\n", exit_code=99, close_session=True))
        self.assert_no_stale_effects()

    def test_new_command_works_when_old_response_arrives_last(self) -> None:
        self.proto.lineReceived(b"old")
        self.interrupt()
        self.proto.lineReceived(b"new")
        fresh = response("new output\n", exit_code=3)
        fresh["honeypot"]["prompt"] = "new prompt"
        self.pending[1].callback(fresh)
        self.terminal.write.assert_any_call(b"new output\n")
        self.terminal.write.assert_any_call(b"new prompt")
        self.terminal.write.reset_mock()
        self.pending[0].callback(response("old output\n", close_session=True))
        self.terminal.write.assert_not_called()
        self.assertEqual(self.shell.last_exit_code, 3)
        self.assertEqual(self.shell.last_relay_prompt, "new prompt")
        self.assertFalse(self.proto.relay_session_closed)
        self.terminal.transport.processEnded.assert_not_called()

    def test_new_command_works_when_old_response_arrives_first(self) -> None:
        self.proto.lineReceived(b"old")
        self.interrupt()
        self.proto.lineReceived(b"new")
        self.terminal.write.reset_mock()
        self.pending[0].callback(response("old output\n"))
        self.assert_no_stale_effects()
        self.pending[1].callback(response("new output\n"))
        self.assertEqual(
            [call.args[0] for call in self.terminal.write.call_args_list],
            [b"new output\n", b"root@host:~# "],
        )

    def test_repeated_interrupts_invalidate_all_earlier_commands(self) -> None:
        self.proto.lineReceived(b"first")
        self.proto.lineReceived(b"second")
        self.interrupt()
        self.proto.lineReceived(b"third")
        self.interrupt()
        self.interrupt()
        self.terminal.write.reset_mock()
        for pending in self.pending:
            pending.callback(response("stale\n", close_session=True))
        self.assert_no_stale_effects()
        self.proto.lineReceived(b"fresh")
        self.pending[-1].callback(response("fresh\n"))
        self.terminal.write.assert_any_call(b"fresh\n")

    def test_normal_pending_commands_do_not_invalidate_each_other(self) -> None:
        self.proto.lineReceived(b"first")
        self.proto.lineReceived(b"second")
        self.pending[0].callback(response("first\n"))
        self.pending[1].callback(response("second\n"))
        self.assertEqual(
            [call.args[0] for call in self.terminal.write.call_args_list],
            [b"first\n", b"root@host:~# ", b"second\n", b"root@host:~# "],
        )

    def test_disconnect_ignores_pending_success_and_failure(self) -> None:
        self.proto.lineReceived(b"first")
        self.proto.lineReceived(b"second")
        self.proto.connectionLost()
        self.terminal.write.reset_mock()
        self.pending[0].callback(response("late\n", close_session=True))
        self.assertEqual(len(self.pending), 1)
        self.assertEqual(self.shell.pending_relay_lines, [])
        self.shell.handle_CTRL_C()
        self.assert_no_stale_effects()
        self.client.get_relay_response.assert_called_with(
            session_id=self.proto.sessionid, event="logout", content="", username="root"
        )


class InteractiveRelayQueueTests(unittest.TestCase):
    def setUp(self):
        RelayTerminalBytesTests.setUp(self)

    def writer(self, kind):
        return RelayTerminalBytesTests.writer(self, kind)

    def output(self):
        return RelayTerminalBytesTests.output(self)

    def test_rapid_paste_sends_one_command_at_a_time(self):
        for key in b"pwd\rhostname\rwhoami\r":
            self.proto.keystrokeReceived(bytes([key]), None)
        self.assertEqual(len(self.pending), 1)
        self.assertEqual(self.shell.pending_relay_lines, ["hostname", "whoami"])
        self.terminal.transport.write.reset_mock()
        for index, output in enumerate(("/root\n", "raspberrypi\n", "root\n")):
            self.assertEqual(len(self.pending), index + 1)
            self.pending[index].callback(response(output))
        self.assertEqual(self.output(), b"/root\r\nroot@host:~# raspberrypi\r\nroot@host:~# root\r\nroot@host:~# ")
        self.assertEqual(self.shell.pending_relay_lines, [])
        self.assertIsNone(self.shell._active_relay_command)

    def test_failure_advances_queue_after_fallback_prompt(self):
        self.proto.lineReceived(b"first")
        self.proto.lineReceived(b"second")
        with patch.object(self.shell, "_log"):
            self.pending[0].errback(RuntimeError("offline"))
        self.assertEqual(len(self.pending), 2)
        self.pending[1].callback(response("ok\n"))
        self.assertEqual(self.output(), b"root@host:~# ok\r\nroot@host:~# ")

    def test_none_response_advances_queue(self):
        self.proto.lineReceived(b"first")
        self.proto.lineReceived(b"second")
        self.pending[0].callback(None)
        self.assertEqual(len(self.pending), 2)
        self.pending[1].callback(response())
        self.assertIsNone(self.shell._active_relay_command)

    def test_synchronous_replies_drain_large_buffer_without_recursion(self):
        self.shell.pending_relay_lines = [str(i) for i in range(1500)]
        sent = []

        def request(**kwargs):
            sent.append(kwargs["content"])
            return succeed(response())

        self.client.get_relay_response.side_effect = request
        self.shell.flush_pending_relay_lines()
        self.assertEqual(sent, [str(i) for i in range(1500)])
        self.assertIsNone(self.shell._active_relay_command)
        self.assertEqual(self.shell.pending_relay_lines, [])

    def test_synchronous_request_exception_does_not_stall_queue(self):
        self.shell.pending_relay_lines = ["first", "second"]
        self.client.get_relay_response.side_effect = [RuntimeError("offline"), succeed(response("ok\n"))]
        with patch.object(self.shell, "_log"):
            self.shell.flush_pending_relay_lines()
        self.assertTrue(self.output().endswith(b"ok\r\nroot@host:~# "))
        self.assertEqual(self.shell.pending_relay_lines, [])
        self.assertIsNone(self.shell._active_relay_command)

    def test_prelogin_buffer_flush_is_serialized(self):
        self.proto.relay_login_complete = False
        self.proto.lineReceived(b"first")
        self.proto.lineReceived(b"second")
        self.shell.flush_pending_relay_lines()
        self.assertEqual(self.pending, [])
        self.proto.relay_login_complete = True
        self.shell.flush_pending_relay_lines()
        self.assertEqual(len(self.pending), 1)
        self.pending[0].callback(response())
        self.assertEqual(len(self.pending), 2)

    def check_stale_completion(self, failure):
        self.proto.lineReceived(b"old")
        self.proto.lineReceived(b"discarded")
        self.proto.keystrokeReceived(b"\x03", None)
        self.assertEqual(self.shell.pending_relay_lines, [])
        self.proto.lineReceived(b"new")
        self.proto.lineReceived(b"next")
        active = self.shell._active_relay_command
        self.terminal.transport.write.reset_mock()
        if failure:
            self.pending[0].errback(RuntimeError("stale failure"))
        else:
            self.pending[0].callback(response("stale", close_session=True))
        self.assertIs(self.shell._active_relay_command, active)
        self.assertEqual(len(self.pending), 2)
        self.assertEqual(self.shell.pending_relay_lines, ["next"])
        self.assertEqual(self.output(), b"")
        self.pending[1].callback(response("new\n"))
        self.assertEqual(len(self.pending), 3)
        self.client.get_relay_response.assert_called_with(
            session_id=self.proto.sessionid, event="command", content="next", username="root"
        )

    def test_stale_success_cannot_advance_new_queue(self):
        self.check_stale_completion(False)

    def test_stale_failure_cannot_advance_new_queue(self):
        self.check_stale_completion(True)

    def test_close_session_discards_remaining_commands(self):
        self.proto.lineReceived(b"exit")
        self.proto.lineReceived(b"never")
        self.pending[0].callback(response(close_session=True))
        self.assertEqual(len(self.pending), 1)
        self.assertEqual(self.shell.pending_relay_lines, [])
        self.shell.flush_pending_relay_lines()
        self.assertEqual(len(self.pending), 1)

    def test_disconnected_active_failure_does_not_restart_queue(self):
        self.proto.lineReceived(b"first")
        self.proto.lineReceived(b"never")
        self.proto.connectionLost()
        self.pending[0].errback(RuntimeError("offline"))
        self.assertEqual(len(self.pending), 1)
        self.assertEqual(self.shell.pending_relay_lines, [])
        self.assertIsNone(self.shell._active_relay_command)

    def test_independent_shell_does_not_wait_for_first_shell(self):
        other = protocol.HoneyPotInteractiveProtocol(self.proto.user)
        terminal = MagicMock()
        self.login = Deferred()
        other.makeConnection(terminal)
        self.addCleanup(other.setTimeout, None)
        self.login.callback(response())
        self.assertNotEqual(self.proto.sessionid, other.sessionid)
        self.proto.lineReceived(b"first")
        self.proto.lineReceived(b"queued")
        other.lineReceived(b"independent")
        self.assertEqual(len(self.pending), 2)
        self.client.get_relay_response.assert_called_with(
            session_id=other.sessionid, event="command", content="independent", username="root"
        )
        self.pending[1].callback(response("independent\n"))
        self.assertFalse(self.pending[0].called)
        terminal.write.assert_any_call(b"independent\n")
        self.pending[0].callback(response())
        self.assertEqual(len(self.pending), 3)


class RelayInterruptRequestBytesTests(unittest.TestCase):
    """Interrupt requests race commands but serialize prompt restoration/input."""

    def setUp(self):
        RelayTerminalBytesTests.setUp(self)
        self.interrupts = []

        def request(**kwargs):
            if kwargs["event"] == "login":
                return self.login
            pending = Deferred()
            if kwargs["event"] == "interrupt":
                self.interrupts.append(pending)
            elif kwargs["event"] == "command":
                self.pending.append(pending)
            return pending

        self.client.get_relay_response.side_effect = request

    def writer(self, kind):
        return RelayTerminalBytesTests.writer(self, kind)

    def output(self):
        return RelayTerminalBytesTests.output(self)

    def press(self, keys):
        for key in keys:
            self.proto.keystrokeReceived(bytes([key]), None)

    def test_idle_interrupt_uses_session_and_returned_prompt_once(self):
        self.shell.last_relay_prompt = "> "
        self.press(b"\x03")
        self.client.get_relay_response.assert_called_with(
            session_id=self.proto.sessionid, event="interrupt", content="", username="root"
        )
        self.assertEqual(self.output(), b"^C\r\n")
        reply = response("must not echo interrupt output\n", exit_code=130)
        reply["honeypot"]["prompt"] = "\x1b[?2004hroot@host:~# "
        self.interrupts[0].callback(reply)
        self.assertEqual(self.output(), b"^C\r\n\x1b[?2004hroot@host:~# ")
        self.assertTrue(self.shell._bracketed_paste_enabled)
        self.assertEqual(self.shell.last_exit_code, 7)

    def test_pending_command_does_not_delay_interrupt_or_overwrite_it(self):
        self.proto.lineReceived(b"slow")
        self.press(b"\x03")
        self.assertEqual(len(self.interrupts), 1)
        self.assertFalse(self.pending[0].called)
        self.pending[0].callback(response("stale", close_session=True))
        self.assertEqual(self.output(), b"^C\r\n")
        self.interrupts[0].callback(response())
        self.assertEqual(self.output(), b"^C\r\nroot@host:~# ")
        self.assertFalse(self.proto.relay_session_closed)

    def test_input_waits_for_prompt_then_command_response_follows(self):
        self.press(b"\x03echo hello\r")
        self.assertEqual(self.output(), b"^C\r\n")
        self.assertEqual(self.pending, [])
        self.interrupts[0].callback(response())
        self.assertEqual(self.output(), b"^C\r\nroot@host:~# echo hello\r\n")
        self.pending[0].callback(response("hello\n"))
        self.assertTrue(self.output().endswith(b"hello\r\nroot@host:~# "))
        self.assertNotIn(b"\r\r\n", self.output())

    def test_repeated_interrupt_discards_old_success_and_failure(self):
        self.press(b"\x03discard\x03\x03")
        self.assertEqual(len(self.interrupts), 3)
        self.interrupts[0].callback(response("stale", close_session=True))
        self.interrupts[1].errback(RuntimeError("stale failure"))
        self.assertEqual(self.output(), b"^C\r\n" * 3)
        self.interrupts[2].callback(response())
        self.assertEqual(self.output(), b"^C\r\n" * 3 + b"root@host:~# ")
        self.assertEqual(self.proto.lineBuffer, [])

    def test_failures_and_invalid_responses_restore_cached_prompt(self):
        for result in (None, {}, {"honeypot": {"prompt": 123}}, RuntimeError("offline")):
            with self.subTest(result=result):
                self.terminal.transport.write.reset_mock()
                self.press(b"\x03")
                if isinstance(result, Exception):
                    self.interrupts[-1].errback(result)
                else:
                    self.interrupts[-1].callback(result)
                self.assertEqual(self.output(), b"^C\r\nroot@host:~# ")
                self.assertFalse(self.shell._relay_interrupt_pending)

    def test_multiline_continuation_returns_to_normal_prompt(self):
        continuation = response()
        continuation["honeypot"]["prompt"] = "> "
        self.shell.handle_relay_response(continuation)
        self.terminal.transport.write.reset_mock()
        self.press(b"unfinished\x03")
        self.interrupts[0].callback(response())
        self.assertEqual(self.output(), b"unfinished^C\r\nroot@host:~# ")
        self.assertEqual(self.shell.last_relay_prompt, "root@host:~# ")

    def test_disconnect_ignores_interrupt_and_buffered_input(self):
        self.press(b"\x03pwd\r")
        self.proto.connectionLost()
        before = self.output()
        self.interrupts[0].callback(response("late", close_session=True))
        self.assertEqual(self.output(), before)
        self.assertEqual(self.proto._pending_interrupt_keys, [])
        self.assertEqual(self.pending, [])

    def test_prelogin_interrupt_buffers_following_command_until_response(self):
        self.login = Deferred()
        self.proto = protocol.HoneyPotInteractiveProtocol(self.proto.user)
        self.proto.makeConnection(self.terminal)
        self.addCleanup(self.proto.setTimeout, None)
        self.shell = self.proto.cmdstack[0]
        self.press(b"discard\x03pwd\r")
        self.assertEqual(self.interrupts, [])
        self.login.callback(response("welcome\n"))
        self.assertEqual(self.output(), b"welcome\r\nroot@host:~# \x1b[4hdiscard^C\r\n")
        self.assertEqual(len(self.interrupts), 1)
        self.assertEqual(self.pending, [])
        self.interrupts[0].callback(response())
        self.assertTrue(self.output().endswith(b"root@host:~# pwd\r\n"))
        self.assertEqual(len(self.pending), 1)

    def test_direct_command_input_waits_for_interrupt(self):
        self.press(b"\x03")
        self.proto.lineReceived(b"pwd")
        self.assertEqual(self.pending, [])
        self.interrupts[0].callback(response())
        self.assertEqual(len(self.pending), 1)
        self.client.get_relay_response.assert_called_with(
            session_id=self.proto.sessionid, event="command", content="pwd", username="root"
        )

    def test_ctrl_d_waits_then_logs_out_once(self):
        self.press(b"\x03\x04")
        self.terminal.transport.processEnded.assert_not_called()
        self.interrupts[0].callback(response())
        self.terminal.transport.processEnded.assert_called_once()
        self.assertTrue(self.output().endswith(b"\x1b[?2004l\r\r\nlogout\r\n"))
        self.proto.connectionLost()
        self.proto.connectionLost()
        events = [call.kwargs["event"] for call in self.client.get_relay_response.call_args_list]
        self.assertEqual(events.count("logout"), 1)

    def test_synchronous_failure_restores_prompt(self):
        self.client.get_relay_response.side_effect = RuntimeError("offline")
        self.press(b"\x03")
        self.assertEqual(self.output(), b"^C\r\nroot@host:~# ")


class RelayTerminalBytesTests(unittest.TestCase):
    """Capture transport bytes after the real Cowrie and Twisted writers."""

    def setUp(self) -> None:
        InteractiveRelayInterruptTests.setUp(self)
        self.terminal = self.writer("i")
        self.proto.terminal = self.terminal

    def writer(self, kind):
        terminal = insults.LoggingServerProtocol.__new__(insults.LoggingServerProtocol)
        terminal.type = kind
        terminal.bytesSent = 0
        terminal.ttylogEnabled = False
        terminal.transport = MagicMock()
        return terminal

    def output(self):
        return b"".join(
            call.args[0] for call in self.terminal.transport.write.call_args_list
        )

    def test_login_banner_bytes(self) -> None:
        self.login = Deferred()
        proto = protocol.HoneyPotInteractiveProtocol(self.proto.user)
        proto.makeConnection(MagicMock())
        self.addCleanup(proto.setTimeout, None)
        proto.terminal = self.terminal
        self.login.callback(response("welcome\n\nPi ready\n"))
        self.assertEqual(
            self.output(), b"welcome\r\n\r\nPi ready\r\nroot@host:~# \x1b[4h"
        )
        self.assertNotIn(b"\r\r\n", self.output())

    def test_command_formatting_bytes(self) -> None:
        for content, expected in (
            ("one\n", b"one\r\n"),
            ("one\ntwo\n", b"one\r\ntwo\r\n"),
            ("one\n\ntwo\n", b"one\r\n\r\ntwo\r\n"),
            ("no trailing newline", b"no trailing newline"),
            ("café\n", "café\r\n".encode()),
        ):
            with self.subTest(content=content):
                self.terminal.transport.write.reset_mock()
                self.proto.lineReceived(b"test")
                self.pending[-1].callback(response(content))
                self.assertEqual(self.output(), expected + b"root@host:~# ")
                self.assertNotIn(b"\r\r\n", self.output())

    def test_prompt_and_ctrl_c_bytes_with_delayed_response(self) -> None:
        prompt = "\x1b[?2004hroot@pi:/tmp# "
        reply = response("")
        reply["honeypot"]["prompt"] = prompt
        self.shell.handle_relay_response(reply)
        self.assertEqual(self.output(), prompt.encode())
        self.terminal.transport.write.reset_mock()
        self.proto.lineReceived(b"slow")
        self.proto.keystrokeReceived(b"\x03", None)
        self.assertEqual(self.output(), b"^C\r\n" + prompt.encode())
        self.pending[-1].callback(response("stale\n"))
        self.assertEqual(self.output(), b"^C\r\n" + prompt.encode())

    def test_exec_terminal_bytes_with_and_without_pty(self) -> None:
        for pty, expected in (
            (False, b"one\n\ntwo"),
            (True, b"one\r\n\r\ntwo"),
        ):
            with self.subTest(pty=pty):
                self.terminal = self.writer("e")
                proto = protocol.HoneyPotExecProtocol.__new__(protocol.HoneyPotExecProtocol)
                proto.terminal = self.terminal
                proto._exec_finished = False
                proto.user = SimpleNamespace(pty_allocated=pty)
                proto.setTimeout = MagicMock()
                proto._exec_response(response("one\n\ntwo", exit_code=7))
                self.assertEqual(self.output(), expected)
                self.assertNotIn(b"\r\r\n", self.output())
                reason = self.terminal.transport.processEnded.call_args.args[0]
                self.assertEqual(reason.value.exitCode, 7)


class InteractiveStartupBytesTests(unittest.TestCase):
    writer = RelayTerminalBytesTests.writer
    output = RelayTerminalBytesTests.output

    def setUp(self) -> None:
        RelayTerminalBytesTests.setUp(self)
        self.login = Deferred()
        self.proto = protocol.HoneyPotInteractiveProtocol(self.proto.user)
        self.proto.makeConnection(self.terminal)
        self.addCleanup(self.proto.setTimeout, None)
        self.shell = self.proto.cmdstack[0]

    def login_ready(self):
        self.login.callback(response("Linux raspberrypi\n"))

    def type_keys(self, keys):
        for key in keys:
            self.proto.keystrokeReceived(bytes([key]), None)

    def test_startup_is_silent_until_banner_then_enables_insert_once(self):
        self.assertEqual(self.proto.mode, "insert")
        self.assertEqual(self.output(), b"")
        self.login_ready()
        self.assertEqual(
            self.output(), b"Linux raspberrypi\r\nroot@host:~# \x1b[4h"
        )
        self.assertEqual(self.output().count(b"\x1b[4h"), 1)

    def test_pending_input_is_replayed_only_after_prompt(self):
        self.type_keys(b"ac")
        self.proto.keystrokeReceived(self.terminal.LEFT_ARROW, None)
        self.type_keys(b"b")
        self.assertEqual(self.output(), b"")
        self.assertEqual(self.proto.lineBuffer, [])
        self.login_ready()
        self.assertEqual(b"".join(self.proto.lineBuffer), b"abc")
        self.assertTrue(
            self.output().startswith(b"Linux raspberrypi\r\nroot@host:~# \x1b[4hac")
        )

    def test_middle_insertion_backspace_delete_and_insert_toggle(self):
        self.login_ready()
        self.type_keys(b"abc")
        self.proto.keystrokeReceived(self.terminal.LEFT_ARROW, None)
        self.type_keys(b"X")
        self.assertEqual(b"".join(self.proto.lineBuffer), b"abXc")
        self.proto.keystrokeReceived(self.terminal.BACKSPACE, None)
        self.assertEqual(b"".join(self.proto.lineBuffer), b"abc")
        self.proto.keystrokeReceived(self.terminal.DELETE, None)
        self.assertEqual(b"".join(self.proto.lineBuffer), b"ab")
        self.proto.keystrokeReceived(self.terminal.HOME, None)
        self.proto.keystrokeReceived(self.terminal.INSERT, None)
        self.type_keys(b"Z")
        self.assertEqual(b"".join(self.proto.lineBuffer), b"Zb")
        self.assertEqual(self.proto.mode, "typeover")
        self.assertIn(b"\x1b[4l", self.output())
        self.proto.keystrokeReceived(self.terminal.INSERT, None)
        self.type_keys(b"Y")
        self.assertEqual(b"".join(self.proto.lineBuffer), b"ZYb")
        self.assertEqual(self.proto.mode, "insert")
        self.assertEqual(self.output().count(b"\x1b[4h"), 2)

    def test_history_tab_and_ctrl_c(self):
        self.login_ready()
        self.type_keys(b"pwd\r")
        self.proto.keystrokeReceived(self.terminal.UP_ARROW, None)
        self.assertEqual(b"".join(self.proto.lineBuffer), b"pwd")
        self.proto.keystrokeReceived(self.terminal.DOWN_ARROW, None)
        self.assertEqual(self.proto.lineBuffer, [])
        before = self.output()
        self.type_keys(b"\t\x03")
        self.assertEqual(self.output()[len(before):], b"\a^C\r\nroot@host:~# ")
        self.pending[0].callback(response("stale\n"))
        self.assertNotIn(b"stale", self.output())

    def test_pending_ctrl_c_and_command_preserve_event_order(self):
        self.type_keys(b"discard\x03pwd\r")
        self.assertEqual(self.output(), b"")
        self.login_ready()
        commands = [
            call.kwargs["content"]
            for call in self.client.get_relay_response.call_args_list
            if call.kwargs["event"] == "command"
        ]
        self.assertEqual(commands, ["pwd"])
        self.assertEqual(self.proto.historyLines, [b"pwd"])
        self.assertEqual(self.output().count(b"^C"), 1)
        self.assertTrue(self.output().startswith(
            b"Linux raspberrypi\r\nroot@host:~# \x1b[4hdiscard^C\r\nroot@host:~# "
        ))
        self.assertNotIn(b"\r\r\n", self.output())

    def test_ctrl_c_empty_partial_and_repeated_bytes(self):
        self.login_ready()
        self.terminal.transport.write.reset_mock()
        self.type_keys(b"\x03partial\x03\x03")
        prompt = b"root@host:~# "
        self.assertEqual(
            self.output(),
            b"^C\r\n" + prompt + b"partial^C\r\n" + prompt + b"^C\r\n" + prompt,
        )
        self.assertEqual(self.output().count(b"^C"), 3)
        self.assertNotIn(b"\x03", self.output())
        self.assertNotIn(b"\r\r\n", self.output())
        self.assertEqual(self.proto.lineBuffer, [])
        self.assertEqual(self.proto.lineBufferIndex, 0)

    def test_ctrl_c_delayed_results_and_next_command_bytes(self):
        self.login_ready()
        self.type_keys(b"old-success\r")
        self.type_keys(b"old-failure\r")
        self.terminal.transport.write.reset_mock()
        self.type_keys(b"\x03")
        interrupted = b"^C\r\nroot@host:~# "
        self.assertEqual(self.output(), interrupted)
        self.pending[0].callback(response("stale\n", exit_code=99, close_session=True))
        self.assertEqual(len(self.pending), 1)
        self.assertEqual(self.shell.pending_relay_lines, [])
        self.assertEqual(self.output(), interrupted)
        self.assertEqual(self.shell.last_exit_code, 0)
        self.assertFalse(self.proto.relay_session_closed)
        self.type_keys(b"pwd\r")
        self.pending[1].callback(response("/root\n"))
        self.assertEqual(
            self.output(), interrupted + b"pwd\r\n/root\r\nroot@host:~# "
        )
        self.assertEqual(self.output().count(b"^C"), 1)
        self.assertNotIn(b"\r\r\n", self.output())

    def test_ctrl_c_after_disconnect_has_no_output(self):
        self.login_ready()
        self.terminal.transport.write.reset_mock()
        self.proto.connectionLost()
        self.proto.keystrokeReceived(b"\x03", None)
        self.shell.handle_CTRL_C()
        self.assertEqual(self.output(), b"")

    def test_disconnect_discards_input_and_late_login(self):
        self.type_keys(b"pwd\r")
        self.proto.connectionLost()
        self.login_ready()
        self.proto.keystrokeReceived(b"x", None)
        self.assertEqual(self.output(), b"")
        self.assertEqual(self.proto._pending_login_keys, [])

    def test_login_failure_restores_editing_without_early_escape(self):
        self.assertEqual(self.output(), b"")
        with patch.object(honeypot.HoneyPotShell, "_log") as logged:
            self.login.errback(RuntimeError("relay unavailable"))
            logged.failure.assert_called_once()
        self.assertEqual(self.output(), self.shell.last_relay_prompt.encode() + b"\x1b[4h")
        self.type_keys(b"x")
        self.assertEqual(self.proto.lineBuffer, [b"x"])

    def test_login_close_does_not_enable_insert_or_replay_input(self):
        self.type_keys(b"pwd\r")
        self.login.callback(response("bye\n", close_session=True))
        self.assertEqual(self.output(), b"bye\r\n")
        self.assertEqual(self.proto._pending_login_keys, [])
        self.terminal.transport.processEnded.assert_called_once()
        self.assertEqual(self.pending, [])

    def test_pending_input_buffer_is_bounded(self):
        self.type_keys(b"x" * 4097)
        self.assertEqual(len(self.proto._pending_login_keys), 4096)
        self.assertEqual(self.output(), b"")

    def test_ctrl_d_nonempty_preserves_editing_at_all_cursor_positions(self):
        self.login_ready()
        self.type_keys(b"abc")
        for position in (0, 1, 3):
            with self.subTest(position=position):
                self.proto.lineBufferIndex = position
                before = (list(self.proto.lineBuffer), self.proto.mode,
                          list(self.proto.historyLines), self.shell.last_relay_prompt)
                self.terminal.transport.write.reset_mock()
                self.type_keys(b"\x04")
                self.assertEqual(self.output(), b"\a")
                self.assertEqual(self.proto.lineBufferIndex, position)
                self.assertEqual(
                    (self.proto.lineBuffer, self.proto.mode,
                     self.proto.historyLines, self.shell.last_relay_prompt), before
                )
                self.terminal.transport.processEnded.assert_not_called()
        self.proto.lineBufferIndex = 1
        self.type_keys(b"X\r")
        self.client.get_relay_response.assert_called_with(
            session_id=self.proto.sessionid, event="command", content="aXbc", username="root"
        )
        self.assertFalse(self.proto._interactive_closing)

    def test_ctrl_d_empty_exact_logout_bytes_status_and_single_event(self):
        self.login_ready()
        self.shell.last_exit_code = 7
        self.terminal.transport.write.reset_mock()
        self.type_keys(b"\x04\x04")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.output(), b"\x1b[?2004l\r\r\nlogout\r\n")
        self.terminal.transport.processEnded.assert_called_once()
        self.assertEqual(
            self.terminal.transport.processEnded.call_args.args[0].value.exitCode, 7
        )
        self.assertFalse(any(
            c.kwargs["event"] == "logout" for c in self.client.get_relay_response.call_args_list
        ))
        self.proto.connectionLost()
        self.proto.connectionLost()
        self.assertEqual(sum(
            c.kwargs["event"] == "logout" for c in self.client.get_relay_response.call_args_list
        ), 1)
        self.proto.handle_CTRL_D()
        self.assertEqual(self.output(), b"\x1b[?2004l\r\r\nlogout\r\n")

    def test_ctrl_d_logout_ignores_pending_success_and_failure(self):
        self.login_ready()
        self.type_keys(b"first\rsecond\r")
        self.shell.last_exit_code = 3
        self.terminal.transport.write.reset_mock()
        self.type_keys(b"\x04")
        self.pending[0].callback(response("late\n", exit_code=99, close_session=True))
        self.assertEqual(len(self.pending), 1)
        self.assertEqual(self.shell.pending_relay_lines, [])
        self.assertEqual(self.output(), b"\x1b[?2004l\r\r\nlogout\r\n")
        self.assertEqual(self.shell.last_exit_code, 3)
        self.terminal.transport.processEnded.assert_called_once()

    def test_prelogin_empty_ctrl_d_closes_after_banner(self):
        self.type_keys(b"\x04pwd\r")
        self.assertEqual(self.output(), b"")
        self.login_ready()
        self.assertEqual(
            self.output(),
            b"Linux raspberrypi\r\nroot@host:~# \x1b[4h\x1b[?2004l\r\r\nlogout\r\n",
        )
        self.assertEqual(self.pending, [])
        self.assertEqual(self.proto._pending_login_keys, [])
        self.terminal.transport.processEnded.assert_called_once()

    def test_prelogin_nonempty_ctrl_d_preserves_text_then_submits(self):
        self.type_keys(b"pw\x04d\r")
        self.assertEqual(self.output(), b"")
        self.login_ready()
        self.assertEqual(
            self.output(), b"Linux raspberrypi\r\nroot@host:~# \x1b[4hpw\ad\r\n"
        )
        self.client.get_relay_response.assert_called_with(
            session_id=self.proto.sessionid, event="command", content="pwd", username="root"
        )
        self.terminal.transport.processEnded.assert_not_called()

    def test_ordinary_eof_keeps_existing_silent_close_behavior(self):
        self.login_ready()
        self.type_keys(b"partial")
        self.terminal.transport.write.reset_mock()
        self.proto.eofReceived()
        self.assertEqual(self.output(), b"")
        self.terminal.transport.processEnded.assert_called_once()

    def test_ctrl_d_preserves_eof_delivery_to_active_stdin_reader(self):
        self.login_ready()
        reader = MagicMock()
        self.proto.cmdstack.append(reader)
        self.terminal.transport.write.reset_mock()
        self.type_keys(b"\x04")
        reader.eofReceived.assert_called_once()
        self.assertEqual(self.output(), b"")
        self.terminal.transport.processEnded.assert_not_called()


class BracketedPasteBytesTests(unittest.TestCase):
    writer = RelayTerminalBytesTests.writer
    output = RelayTerminalBytesTests.output
    type_keys = InteractiveStartupBytesTests.type_keys

    def setUp(self):
        RelayTerminalBytesTests.setUp(self)

    def display_prompt(self, prompt="\x1b[?2004hpi# "):
        reply = response("")
        reply["honeypot"]["prompt"] = prompt
        self.shell.handle_relay_response(reply)
        self.terminal.transport.write.reset_mock()

    def test_enabled_prompt_disables_after_newline_before_response(self):
        self.display_prompt()
        self.type_keys(b"pwd\r")
        self.assertEqual(self.output(), b"pwd\r\n\x1b[?2004l\r")
        self.assertFalse(self.shell._bracketed_paste_enabled)
        self.assertEqual(self.proto.lineBuffer, [])
        self.assertEqual(self.proto.lineBufferIndex, 0)
        self.assertEqual(self.proto.historyLines, [b"pwd"])
        reply = response("/root\n")
        reply["honeypot"]["prompt"] = "\x1b[?2004hpi# "
        self.pending[0].callback(reply)
        self.assertEqual(
            self.output(), b"pwd\r\n\x1b[?2004l\r/root\r\n\x1b[?2004hpi# "
        )
        self.assertTrue(self.shell._bracketed_paste_enabled)
        self.type_keys(b"\r")
        self.assertEqual(self.output().count(b"\x1b[?2004l\r"), 2)
        self.assertNotIn(b"\r\r\n", self.output())

    def test_plain_disabled_and_multiple_mode_sequences(self):
        for prompt, enabled in (
            ("pi# ", False),
            ("\x1b[?2004h\x1b[?2004lpi# ", False),
            ("\x1b[?2004l\x1b[?2004hpi# ", True),
        ):
            with self.subTest(prompt=prompt):
                self.display_prompt(prompt)
                self.type_keys(b"\r")
                self.assertEqual(
                    self.output(), b"\r\n" + (b"\x1b[?2004l\r" if enabled else b"")
                )

    def test_repeated_enter_does_not_repeat_disable(self):
        self.display_prompt()
        self.type_keys(b"\r\r")
        self.assertEqual(self.output(), b"\r\n\x1b[?2004l\r\r\n")
        self.assertEqual(len(self.pending), 1)
        self.assertEqual(self.shell.pending_relay_lines, [""])

    def test_synchronous_response_follows_disable(self):
        self.display_prompt()
        reply = response("sync\n")
        reply["honeypot"]["prompt"] = "\x1b[?2004hpi# "
        self.client.get_relay_response.side_effect = lambda **kwargs: succeed(reply)
        self.type_keys(b"pwd\r")
        self.assertEqual(
            self.output(), b"pwd\r\n\x1b[?2004l\rsync\r\n\x1b[?2004hpi# "
        )
        self.assertTrue(self.shell._bracketed_paste_enabled)

    def test_ctrl_c_restores_mode_and_stale_callbacks_cannot_change_it(self):
        self.display_prompt()
        self.type_keys(b"old\r")
        self.type_keys(b"\x03")
        self.assertTrue(self.shell._bracketed_paste_enabled)
        self.type_keys(b"new\r")
        before = self.output()
        stale = response("stale\n")
        stale["honeypot"]["prompt"] = "\x1b[?2004hSTALE# "
        self.pending[0].callback(stale)
        self.assertEqual(self.output(), before)
        self.assertFalse(self.shell._bracketed_paste_enabled)
        self.assertEqual(self.output().count(b"\x1b[?2004l\r"), 2)

    def test_fallback_prompts_restore_tracking(self):
        self.display_prompt()
        self.type_keys(b"first\r")
        self.pending[0].callback(None)
        self.assertTrue(self.shell._bracketed_paste_enabled)
        self.type_keys(b"second\r")
        with patch.object(honeypot.HoneyPotShell, "_log"):
            self.pending[1].errback(RuntimeError("relay unavailable"))
        self.assertTrue(self.shell._bracketed_paste_enabled)
        self.type_keys(b"\r")
        self.assertEqual(self.output().count(b"\x1b[?2004l\r"), 3)

    def test_prelogin_buffered_enter_tracks_displayed_login_prompt(self):
        self.login = Deferred()
        proto = protocol.HoneyPotInteractiveProtocol(self.proto.user)
        proto.makeConnection(self.terminal)
        self.addCleanup(proto.setTimeout, None)
        self.proto = proto
        self.type_keys(b"pwd\r")
        self.assertEqual(self.output(), b"")
        reply = response("banner\n")
        reply["honeypot"]["prompt"] = "\x1b[?2004hpi# "
        self.login.callback(reply)
        self.assertEqual(
            self.output(), b"banner\r\n\x1b[?2004hpi# \x1b[4hpwd\r\n\x1b[?2004l\r"
        )

    def test_ctrl_d_bell_and_exact_logout_have_no_extra_disable(self):
        self.display_prompt()
        self.type_keys(b"x\x04")
        self.assertEqual(self.output(), b"x\a")
        self.assertTrue(self.shell._bracketed_paste_enabled)
        self.type_keys(b"\x03")
        self.terminal.transport.write.reset_mock()
        self.type_keys(b"\x04")
        self.assertEqual(self.output(), b"\x1b[?2004l\r\r\nlogout\r\n")
        self.assertFalse(self.shell._bracketed_paste_enabled)


class RelayHTTPConnectionTests(unittest.TestCase):
    """Exercise actual Agent requests without opening network sockets."""

    def setUp(self):
        self.connections = []
        self.endpoint = MagicMock()
        self.endpoint.connect.side_effect = self.connect
        for patcher in (
            patch.dict("os.environ", {}, clear=True),
            patch.object(llm_module, "reactor", Clock()),
            patch.object(Agent, "_getEndpoint", return_value=self.endpoint),
            patch.object(llm_module, "HostnameEndpoint", return_value=self.endpoint),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.http = LLMClient()
        self.http.host = "http://relay.example:8000"
        self.http.path = "/v1/chat/completions"

    def connect(self, factory):
        wire = factory.buildProtocol(None)
        transport = StringTransport()
        self.connections.append((wire, transport))
        wire.makeConnection(transport)
        return succeed(wire)

    def reply(self, index, content=""):
        body = json.dumps(response(content)).encode()
        # Deliberately omit Connection: close and never deliver the peer's FIN.
        self.connections[index][0].dataReceived(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body
        )

    def requests(self):
        return [
            json.loads(transport.value().split(b"\r\n\r\n", 1)[1])
            for _, transport in self.connections
        ]

    def test_consecutive_requests_use_separate_connections_direct_and_proxy(self):
        for proxy in (False, True):
            with self.subTest(proxy=proxy):
                self.connections.clear()
                environment = {"http_proxy": "http://proxy.example:8080"} if proxy else {}
                with patch.dict("os.environ", environment, clear=True):
                    client = LLMClient()
                client.host = self.http.host
                self.assertIsInstance(client.agent, ProxyAgent if proxy else Agent)
                self.assertIs(client.agent._pool, client._conn_pool)
                results = []

                def next_request(result):
                    results.append(result)
                    return client.get_relay_response("session", "command", "second")

                d = client.get_relay_response("session", "command", "first")
                d.addCallback(next_request)
                d.addCallback(results.append)
                self.reply(0, "first\n")
                self.assertEqual(len(self.connections), 2)
                self.reply(1, "second\n")
                self.assertFalse(client._conn_pool.persistent)
                self.assertEqual(results, [response("first\n"), response("second\n")])
                self.assertEqual(
                    [r["messages"][0]["content"] for r in self.requests()],
                    ["first", "second"],
                )
                self.assertIsNot(self.connections[0][0], self.connections[1][0])
                for _, transport in self.connections:
                    self.assertIn(b"Connection: close\r\n", transport.value())
                    self.assertTrue(transport.disconnecting)
                self.assertFalse(client._conn_pool._connections)

    def start_shell(self):
        # Reuse the existing SSH fixture, then replace only its HTTP boundary.
        InteractiveRelayInterruptTests.setUp(self)
        self.client.get_relay_response.side_effect = self.http.get_relay_response

    def test_rapid_fifo_commands_execute_once_in_order(self):
        self.start_shell()
        for command in (b"pwd", b"hostname", b"whoami"):
            self.proto.lineReceived(command)
        self.assertEqual(len(self.connections), 1)
        for index in range(3):
            self.assertEqual(len(self.connections), index + 1)
            self.reply(index, f"result {index}\n")
        self.assertEqual(
            [r["messages"][0]["content"] for r in self.requests()],
            ["pwd", "hostname", "whoami"],
        )
        self.assertEqual(self.shell.pending_relay_lines, [])
        self.assertIsNone(self.shell._active_relay_command)
        self.assertEqual(self.client.get_relay_response.call_count, 4)  # login + commands

    def test_interrupt_opens_connection_before_command_completes(self):
        self.start_shell()
        self.proto.lineReceived(b"sleep 30")
        self.proto.keystrokeReceived(b"\x03", None)
        self.assertEqual(len(self.connections), 2)
        self.assertEqual(
            [r["honeypot"]["event"] for r in self.requests()],
            ["command", "interrupt"],
        )
        self.reply(1)
        self.assertFalse(self.shell._relay_interrupt_pending)
        self.terminal.write.reset_mock()
        self.reply(0, "stale output\n")
        self.terminal.write.assert_not_called()
        self.assertFalse(self.proto.relay_session_closed)


class RelayExecRequestTests(unittest.TestCase):
    def test_exec_request_serialization(self) -> None:
        self.check_request_serialization("exec", "  uname -a  ")

    def test_interrupt_request_serialization(self) -> None:
        self.check_request_serialization("interrupt", "")

    def test_terminal_dimensions_serialization(self):
        for event in ("login", "command", "interrupt"):
            with self.subTest(event=event):
                self.check_request_serialization(event, "", {"cols": 200, "rows": 37}, {"cols": 200, "rows": 37})

    def test_invalid_dimensions_not_serialized(self):
        for dimensions, expected in (
            ({"cols": 0, "rows": 40}, {"rows": 40}),
            ({"cols": 200, "rows": -1}, {"cols": 200}),
            ({"cols": "80", "rows": True}, {}),
            ({"cols": None, "rows": 1.5}, {}),
        ):
            with self.subTest(dimensions=dimensions):
                self.check_request_serialization("command", "", dimensions, expected)

    def check_request_serialization(self, event, content, dimensions=None, expected_dimensions=None) -> None:
        client = LLMClient.__new__(LLMClient)
        client.host = "http://relay.example:8000"
        client.path = "/v1/chat/completions"
        client.model = "test-model"
        client.debug = False
        client.agent = MagicMock()
        client.agent.request.return_value = succeed(MagicMock())
        reply = response("output\n", exit_code=7)
        client._handle_response_body = MagicMock(
            return_value=succeed((200, json.dumps(reply).encode()))
        )
        with patch.object(client, "_build_headers", return_value=MagicMock()):
            result = client.get_relay_response(
                session_id="unique-channel",
                event=event,
                content=content,
                username="root",
                src_ip="192.0.2.1",
                src_port=12345,
                dst_ip="192.0.2.2",
                dst_port=22,
                **(dimensions or {}),
            )
        received = []
        result.addCallback(received.append)
        self.assertEqual(received, [reply])
        client.agent.request.assert_called_once()
        args, kwargs = client.agent.request.call_args
        self.assertEqual(args, (b"POST", b"http://relay.example:8000/v1/chat/completions"))
        self.assertEqual(
            json.loads(kwargs["bodyProducer"].body),
            {
                "model": "test-model",
                "user": "unique-channel",
                "stream": False,
                "messages": [{"role": "user", "content": content}],
                "honeypot": {
                    "event": event,
                    "username": "root",
                    "src_ip": "192.0.2.1",
                    "src_port": 12345,
                    "dst_ip": "192.0.2.2",
                    "dst_port": 22,
                    **(expected_dimensions or {}),
                },
            },
        )
