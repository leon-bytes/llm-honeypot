"""Local mock relay unit and isolated localhost integration checks."""

import io
import json
import unittest
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

from twisted.internet.defer import Deferred, succeed

from cowrie.llm.llm import LLMClient
from cowrie.test import test_relay_exec

import mock_llm


class MockRelayTests(unittest.TestCase):
    def setUp(self):
        mock_llm.sessions.clear()
        self.addCleanup(mock_llm.sessions.clear)

    def request(self, event, command="", session_id="test-channel"):
        body = json.dumps({
            "model": "testing",
            "user": session_id,
            "stream": False,
            "messages": [{"role": "user", "content": command}],
            "honeypot": {"event": event, "username": "root"},
        }).encode()
        handler = mock_llm.Handler.__new__(mock_llm.Handler)
        handler.path = "/v1/chat/completions"
        handler.headers = {"Content-Length": str(len(body))}
        handler.rfile = io.BytesIO(body)
        handler.send_json = Mock()
        handler.do_POST()
        handler.send_json.assert_called_once()
        status, response = handler.send_json.call_args.args
        self.assertEqual(status, 200)
        return response

    def test_interrupt_preserves_state_and_returns_normal_prompt(self):
        self.request("login")
        self.request("command", "touch retained")
        state = mock_llm.sessions["test-channel"]
        with mock_llm.sessions_lock:
            state["cwd"] = "/tmp"
        history = list(state["history"])
        reply = self.request("interrupt")
        self.assertEqual(reply["choices"][0]["message"]["content"], "")
        self.assertEqual(reply["honeypot"]["exit_code"], 130)
        self.assertEqual(reply["honeypot"]["prompt"], mock_llm.get_prompt("/tmp"))
        self.assertFalse(reply["honeypot"]["close_session"])
        self.assertIs(mock_llm.sessions["test-channel"], state)
        self.assertEqual(state["history"], history)
        self.assertIn("retained", state["files"])

    def test_interrupt_without_login_does_not_create_session(self):
        reply = self.request("interrupt")
        self.assertEqual(reply["honeypot"]["exit_code"], 130)
        self.assertEqual(reply["honeypot"]["prompt"], mock_llm.get_prompt("/root"))
        self.assertEqual(mock_llm.sessions, {})

    def test_sleep_preserves_command_output(self):
        reply = self.request("command", "sleep 0; hostname")
        self.assertEqual(reply["choices"][0]["message"]["content"], "raspberrypi\n")
        self.assertEqual(reply["honeypot"]["exit_code"], 0)
        for interval in ("bad", "-1", "nan", "inf"):
            reply = self.request("exec", "sleep " + interval)
            self.assertEqual(reply["honeypot"]["exit_code"], 1)

    def test_shell_ids_isolate_mock_history_files_interrupts_and_logout(self):
        fixture = test_relay_exec.InteractiveRelaySessionIdTests(
            "test_shared_transport_shells_get_distinct_uuid_ids_before_login"
        )
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()

        def request(**kwargs):
            return succeed(self.request(
                kwargs["event"], kwargs.get("content", ""), kwargs["session_id"]
            ))

        fixture.client.get_relay_response.side_effect = request
        first = fixture.new_shell()
        first.lineReceived(b"touch first-only")
        first_state = mock_llm.sessions[first.sessionid]
        second = fixture.new_shell()
        self.assertIs(first.getProtoTransport(), second.getProtoTransport())
        self.assertIs(mock_llm.sessions[first.sessionid], first_state)
        self.assertEqual(first_state["history"], ["touch first-only"])
        second.lineReceived(b"touch second-only")
        second_state = mock_llm.sessions[second.sessionid]
        self.assertIsNot(first_state, second_state)
        self.assertEqual(set(first_state["files"]), {"first-only"})
        self.assertEqual(set(second_state["files"]), {"second-only"})
        second.lineReceived(b"cat first-only")
        self.assertEqual(second.cmdstack[0].last_exit_code, 1)
        second_history = list(second_state["history"])
        first.keystrokeReceived(b"\x03", None)
        self.assertEqual(second_state["history"], second_history)
        self.assertEqual(first_state["history"], ["touch first-only"])
        first.connectionLost()
        first.connectionLost()
        self.assertNotIn(first.sessionid, mock_llm.sessions)
        self.assertIs(mock_llm.sessions[second.sessionid], second_state)
        second.lineReceived(b"ls")
        self.assertEqual(second.cmdstack[0].last_exit_code, 0)
        self.assertEqual(set(second_state["files"]), {"second-only"})
        third = fixture.new_shell()
        self.assertNotIn(third.sessionid, (first.sessionid, second.sessionid))
        second.connectionLost()
        self.assertNotIn(second.sessionid, mock_llm.sessions)
        self.assertIn(third.sessionid, mock_llm.sessions)
        self.assertEqual(fixture.transport.transportId, "shared-transport")

    def test_exec_without_login(self):
        reply = self.request("exec", "hostname; uname; pwd")
        self.assertEqual(
            reply["choices"][0]["message"]["content"],
            "raspberrypi\nLinux\n/root\n",
        )
        self.assertEqual(reply["honeypot"]["exit_code"], 0)
        self.assertEqual(reply["honeypot"]["prompt"], "")
        self.assertTrue(reply["honeypot"]["close_session"])
        self.assertEqual(mock_llm.sessions, {})

    def test_unknown_exec_command(self):
        reply = self.request("exec", "does-not-exist")
        self.assertEqual(
            reply["choices"][0]["message"]["content"],
            "-bash: does-not-exist: command not found\n",
        )
        self.assertEqual(reply["honeypot"]["exit_code"], 127)
        self.assertEqual(mock_llm.sessions, {})

    def test_exec_reuses_interactive_command_behavior(self):
        for command in ("uname -a", "hostname", "pwd", "cat missing"):
            with self.subTest(command=command):
                interactive = self.request("command", command)
                executed = self.request("exec", command, "exec-channel")
                self.assertEqual(executed["choices"], interactive["choices"])
                self.assertEqual(
                    executed["honeypot"]["exit_code"],
                    interactive["honeypot"]["exit_code"],
                )
                self.assertNotIn("exec-channel", mock_llm.sessions)

    def test_exec_state_is_disposable_and_does_not_replace_interactive_state(self):
        self.request("login")
        self.request("command", "echo retained > existing")
        state = mock_llm.sessions["test-channel"]
        history = list(state["history"])
        reply = self.request("exec", "touch temporary; ls; exit")
        self.assertIn("temporary", reply["choices"][0]["message"]["content"])
        self.assertIs(mock_llm.sessions["test-channel"], state)
        self.assertNotIn("temporary", state["files"])
        self.assertEqual(state["history"], history)

    def test_interactive_login_commands_and_logout(self):
        login = self.request("login")
        self.assertIn("Wi-Fi", login["choices"][0]["message"]["content"])
        self.assertTrue(login["honeypot"]["prompt"])
        self.request("command", "echo retained > existing")
        reply = self.request("command", "cat existing")
        self.assertEqual(reply["choices"][0]["message"]["content"], "retained\n")
        self.assertFalse(reply["honeypot"]["close_session"])
        logout = self.request("logout")
        self.assertTrue(logout["honeypot"]["close_session"])
        self.assertEqual(mock_llm.sessions, {})


class MockRelayInterruptIntegrationTests(unittest.TestCase):
    """Real HTTP concurrency plus Cowrie callbacks and its terminal writer."""

    def writer(self, kind):
        return test_relay_exec.RelayTerminalBytesTests.writer(self, kind)

    def output(self):
        return test_relay_exec.RelayTerminalBytesTests.output(self)

    def test_interrupt_completes_before_delayed_command_and_late_output_is_ignored(self):
        test_relay_exec.RelayTerminalBytesTests.setUp(self)
        with mock_llm.sessions_lock:
            mock_llm.sessions.clear()
        self.addCleanup(mock_llm.sessions.clear)
        server = mock_llm.ThreadingHTTPServer(("127.0.0.1", 0), mock_llm.Handler)
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()

        def stop_server():
            server.shutdown()
            server.server_close()
            serving.join(timeout=3)

        self.addCleanup(stop_server)
        pool = ThreadPoolExecutor(max_workers=3)
        self.addCleanup(pool.shutdown, wait=True)
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def delay(seconds):
            self.assertEqual(seconds, 30)
            started.set()
            if not release.wait(timeout=5):
                raise RuntimeError("Test did not release delayed command")

        patcher = patch.object(mock_llm.time, "sleep", side_effect=delay)
        patcher.start()
        self.addCleanup(patcher.stop)
        calls = []

        def http_post(url, payload):
            request = urllib.request.Request(
                url.decode(), data=payload, headers={"Content-Type": "application/json"}
            )
            # Explicitly bypass host proxy settings for this localhost test.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=4) as response:
                return response.read()

        def send(method, url, headers, bodyProducer):
            self.assertEqual(method, b"POST")
            deferred = Deferred()
            future = pool.submit(http_post, url, bodyProducer.body)
            calls.append((json.loads(bodyProducer.body), future, deferred))
            return deferred

        # Use the production serializer, with only HTTP I/O bridged to worker
        # futures. Deliver Deferred callbacks on this test's main thread.
        client = LLMClient.__new__(LLMClient)
        client.host = f"http://127.0.0.1:{server.server_port}"
        client.path = "/v1/chat/completions"
        client.model = "testing"
        client.debug = False
        client.agent = Mock()
        client.agent.request.side_effect = send
        client._build_headers = Mock(return_value={})
        client._handle_response_body = lambda body: succeed((200, body))
        self.client.get_relay_response.side_effect = client.get_relay_response

        def finish(index):
            _, future, deferred = calls[index]
            raw = future.result(timeout=3)
            deferred.callback(raw)
            return json.loads(raw)

        # Rapidly pasted normal commands must not reach HTTP concurrently.
        for key in b"sleep 30; hostname\rpwd\rwhoami\r":
            self.proto.keystrokeReceived(bytes([key]), None)
        self.assertTrue(started.wait(timeout=2), "Command never reached HTTP handler")
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.shell.pending_relay_lines, ["pwd", "whoami"])
        self.terminal.transport.write.reset_mock()
        release.set()
        finish(0)
        self.assertEqual(len(calls), 2)
        finish(1)
        self.assertEqual(len(calls), 3)
        finish(2)
        prompt = mock_llm.get_prompt("/root").encode()
        self.assertEqual(self.output(), b"raspberrypi\r\n" + prompt + b"/root\r\n" + prompt + b"root\r\n" + prompt)
        self.assertEqual([call[0]["messages"][0]["content"] for call in calls], ["sleep 30; hostname", "pwd", "whoami"])

        calls.clear()
        started.clear()
        release.clear()
        self.terminal.transport.write.reset_mock()
        self.proto.lineReceived(b"sleep 30; hostname")
        self.proto.lineReceived(b"discarded")
        self.assertTrue(started.wait(timeout=2), "Command never reached HTTP handler")
        self.proto.keystrokeReceived(b"\x03", None)
        interrupt = finish(1)
        self.assertEqual(calls[0][0]["honeypot"]["event"], "command")
        self.assertEqual(calls[1][0]["honeypot"]["event"], "interrupt")
        self.assertEqual(calls[0][0]["user"], calls[1][0]["user"])
        self.assertEqual(interrupt["honeypot"]["exit_code"], 130)
        expected = b"^C\r\n" + mock_llm.get_prompt("/root").encode()
        self.assertEqual(self.output(), expected)
        self.assertFalse(calls[0][1].done(), "Interrupt waited for the command")

        # A subsequent command can complete before the abandoned one, too.
        self.proto.lineReceived(b"pwd")
        finish(2)
        before = self.output()
        self.assertTrue(before.endswith(b"/root\r\n" + mock_llm.get_prompt("/root").encode()))
        release.set()
        abandoned = finish(0)
        self.assertEqual(abandoned["choices"][0]["message"]["content"], "raspberrypi\n")
        self.assertEqual(self.output(), before)
        self.assertEqual(self.shell.last_relay_prompt, mock_llm.get_prompt("/root"))
        self.assertNotIn(b"\r\r\n", self.output())
        self.terminal.transport.processEnded.assert_not_called()


if __name__ == "__main__":
    unittest.main()
