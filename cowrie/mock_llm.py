from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import threading
import time
import uuid


# Temporary in-memory session state for local testing.
# The real relay will eventually own this state.
sessions = {}
sessions_lock = threading.Lock()


def get_prompt(cwd):
    if cwd == "/root":
        location = "~"
    else:
        location = cwd

    return f"\x1b[?2004hroot@raspberrypi:{location}# "


def make_response(content, cwd="/root", exit_code=0,
                  source="builtin", close_session=False):
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "model": "raspberrypi-shell",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": content,
                },
            }
        ],
        "honeypot": {
            "exit_code": exit_code,
            "cwd": cwd,
            "prompt": get_prompt(cwd),
            "source": source,
            "close_session": close_session,
            "elapsed_ms": 1,
        },
    }


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        data = json.dumps(payload).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_error_json(self, status, message):
        self.send_json(
            status,
            {
                "error": {
                    "message": message
                }
            },
        )

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_error_json(404, "Not found")
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
        except Exception:
            self.send_error_json(400, "Invalid JSON")
            return

        if body.get("stream") is True:
            self.send_error_json(400, "stream must be false")
            return

        session_id = body.get("user")
        if not session_id:
            self.send_error_json(400, "missing user")
            return

        honeypot = body.get("honeypot", {})
        event = honeypot.get("event")

        if event not in ("login", "command", "logout", "exec", "interrupt"):
            self.send_error_json(400, "unknown honeypot event")
            return

        messages = body.get("messages", [])
        command = messages[-1].get("content", "") if messages else ""

        # LOGIN
        if event == "login":
            with sessions_lock:
                sessions[session_id] = {
                    "cwd": "/root",
                    "files": {},
                    "history": [],
                }

            content = (
                "Linux raspberrypi 6.12.75+rpt-rpi-2712 aarch64\n"
                "\n"
                "Wi-Fi is currently blocked by rfkill.\n"
                "Use raspi-config to set the country before use.\n"
            )

            self.send_json(
                200,
                make_response(
                    content,
                    cwd="/root",
                    source="login",
                ),
            )
            return

        # LOGOUT
        if event == "logout":
            with sessions_lock:
                state = sessions.pop(
                    session_id,
                    {
                        "cwd": "/root",
                        "files": {},
                        "history": [],
                    },
                )
                cwd = state["cwd"]

            self.send_json(
                200,
                make_response(
                    "",
                    cwd=cwd,
                    source="logout",
                    close_session=True,
                ),
            )
            return

        if event == "interrupt":
            with sessions_lock:
                cwd = sessions.get(session_id, {}).get("cwd", "/root")
            self.send_json(200, make_response("", cwd=cwd, exit_code=130))
            return

        # Exec uses disposable state; interactive commands retain their state.
        state = {"cwd": "/root", "files": {}, "history": []}
        with sessions_lock:
            if event != "exec":
                state = sessions.setdefault(session_id, state)
            state["history"].append(command)

        content = ""
        exit_code = 0
        close_session = False

        command = command.strip()

        def run_one_command(cmd):
            cmd = cmd.strip()
            # Local delay fixture; never hold the state lock while waiting.
            if cmd.startswith("sleep "):
                try:
                    seconds = float(cmd[6:].strip())
                    if not math.isfinite(seconds) or seconds < 0:
                        raise ValueError
                except ValueError:
                    return "sleep: invalid time interval\n", 1, False
                time.sleep(seconds)
                return "", 0, False
            with sessions_lock:
                return run_immediate_command(cmd)

        def run_immediate_command(cmd):
            if cmd == "":
                return "", 0, False

            if cmd == "hostname":
                return "raspberrypi\n", 0, False

            if cmd == "uname":
                return "Linux\n", 0, False

            if cmd == "whoami":
                return "root\n", 0, False

            if cmd == "pwd":
                return state["cwd"] + "\n", 0, False

            if cmd in ("exit", "logout"):
                return "logout\n", 0, True

            if cmd.startswith("touch "):
                filename = cmd[6:].strip()
                state["files"][filename] = state["files"].get(filename, "")
                return "", 0, False

            if cmd.startswith("echo ") and ">" in cmd:
                left, right = cmd.split(">", 1)

                text = left[5:].strip()
                filename = right.strip()

                state["files"][filename] = text + "\n"
                return "", 0, False

            if cmd == "ls":
                entries = ["iot-stack"] + sorted(state["files"].keys())
                return "  ".join(entries) + "\n", 0, False

            if cmd.startswith("cat "):
                filename = cmd[4:].strip()

                if filename in state["files"]:
                    return state["files"][filename], 0, False

                return f"cat: {filename}: No such file or directory\n", 1, False

            if cmd.startswith("more "):
                filename = cmd[5:].strip()

                if filename in state["files"]:
                    return state["files"][filename], 0, False

                return f"more: cannot open {filename}: No such file or directory\n", 1, False

            name = cmd.split()[0]
            return f"-bash: {name}: command not found\n", 127, False

        # Bash can execute several commands on one line separated by semicolons.
        parts = command.split(";")

        output_parts = []
        exit_code = 0
        close_session = False

        for part in parts:
            part_output, exit_code, close_session = run_one_command(part)

            if part_output:
                output_parts.append(part_output)

            if close_session:
                break

        content = "".join(output_parts)

        with sessions_lock:
            response = make_response(
                content,
                cwd=state["cwd"],
                exit_code=exit_code,
                source="builtin",
                close_session=close_session or event == "exec",
            )

            if event == "exec":
                response["honeypot"]["prompt"] = ""
            elif close_session and sessions.get(session_id) is state:
                sessions.pop(session_id, None)

        self.send_json(200, response)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    print("Relay mock listening on port 8000...")
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
