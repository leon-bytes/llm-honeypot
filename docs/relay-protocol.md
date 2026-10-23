# Relay protocol: how Cowrie talks to the Orchestrator

For the front end's maintainer. Cowrie sends **every** command line to the relay, not only the ones it
does not know: even `ls` and `cat` have to answer like our Pi, not like Cowrie's
built-in filesystem. The relay owns the session state (working directory,
variables, history, files the attacker created), because the fake Docker API has to
see the same state. Cowrie keeps the SSH side: banner, key exchange, password check,
the terminal.

It is plain OpenAI chat completions with two additions, so your mock and the `openai`
Python client work unchanged. The additions are the `user` field (standard OpenAI)
and a `honeypot` object: send it with `extra_body={"honeypot": {...}}` in the
`openai` client.

- URL: `POST http://127.0.0.1:8000/v1/chat/completions` on the Orchestrator (the
  relay listens on localhost only; Cowrie runs on the same machine). `stream` must
  be `false`.
- No API key unless we set one in `honeypot/config.json`; any `Authorization`
  header is accepted until then.

## Request

```json
{
  "model": "raspberrypi-shell",
  "user": "<Cowrie's session id, the same for every request in one SSH session>",
  "messages": [{"role": "user", "content": "<the command line exactly as typed>"}],
  "honeypot": {
    "event": "command",
    "username": "root",
    "src_ip": "10.11.12.57", "src_port": 51234,
    "dst_ip": "10.11.12.21", "dst_port": 22
  }
}
```

### The session id (`user`)

`user` must be **unique for every SSH session, across Cowrie restarts**. The relay
keeps a session's working directory, variables and history under this id, so an id
that comes round again picks up a stranger's session. Cowrie's `sessionno` is a
counter that starts again at 1 when Cowrie restarts: do not use it. Use a random id
made when the connection is accepted, for example Cowrie's own per-connection
session id (the 12 hex characters it puts in its logs as `session`, made from
`uuid4`), or `uuid.uuid4().hex`. Using Cowrie's log id also lets us join Cowrie's
logs with the relay's. If one connection opens a second shell or exec channel, give
that channel its own id (for example the connection id plus `-2`).

### Events

`honeypot.event` is one of:

| event | when | `content` of the message |
|---|---|---|
| `login` | right after the password is accepted, before anything is printed | ignored (send `""`) |
| `command` | each line the attacker enters, including empty lines | the line, without the newline |
| `logout` | the connection closed without `exit` (dropped, Ctrl-D, timeout) | ignored |
| `exec` | run-one-command mode, `ssh host 'cmd'`: once, instead of `login` | the command string the client sent |
| `complete` | the attacker pressed Tab | the line typed so far, up to the cursor |
| `interrupt` | the attacker pressed Ctrl-C, **at a prompt or while an answer is being waited for** | ignored (send `""`) |

`interrupt` is built in the relay since 2026-10-13 and **not sent by Cowrie yet**; see
"Ctrl-C" below for what it does and why it is needed. `exec` is built (2026-10-01). `complete` is **not built in the relay yet** (it
answers 400 today); its section below says how it will work, so Cowrie can be
written against it now. Cowrie must send `login` and `logout`: without `login` the relay
starts the session on the first command, with no login text and the attacker's
address unknown (it shows up as `127.0.0.1` in `env`, `who` and `Last login:`), and
without `logout` a dropped connection stays in `who` until it times out.

**`cols` (optional, recommended):** the client's terminal width, from the SSH
`pty-req` (and again after a window change), on `login` and on any later request.
`ps`, `top`, `ss` and `ls` lay their output out to the terminal width as on the real
machine; without it the relay assumes 80 (and leaves an `ls` listing wider than that to
the model). **`rows` (optional, since 2026-10-13):** the height,
from the same request. `echo $COLUMNS` and `echo $LINES` print the two; without them
the relay says 80 and 24.

Only the **last** `user` message is read; there is no need to send history. The
address fields matter on `login` and `exec` (they end up in `env`, `who`, `w` and
the next `Last login:` line) and may be left out on `command`.

**Send every line, however long.** Cowrie's `max_input_size` cap exists to protect
Cowrie's own shell parser, which the relay path does not use, and real bash has no
such limit: a long pasted one-liner runs on the Pi. Answering it with Cowrie's
syntax error would be a tell. The relay owns any limit it needs (for example
trimming what goes into the model prompt) and still answers like bash.

### Two fields for measurement only

Cowrie never sends these; only the measurement tools on the dev machine do, through the SSH
tunnel. The relay listens on localhost, so an attacker cannot send them.

- **`mode`**: `"model_only"` makes the model answer every line of the session (the code
  still keeps the state); `"normal"` is the default. Set once, on `login` or `exec`.
- **`hide_examples`** (since 2026-10-13): a list of corpus numbers the model is not
  shown as examples in this session. The leave-one-out test asks each corpus command
  with its own recording hidden (`tools/run_leave_one_out.py`). The numbers of the
  examples that were shown come back in the log (`meta.examples`).

## Response

**One request per connection.** The relay answers in HTTP/1.0 and closes the connection
after every response, and since 2026-10-15 it says so (`Connection: close`). Twisted's
HTTP client (Cowrie's) keeps an HTTP/1.0 connection without that header for reuse, so
a request sent within a millisecond of the previous answer (a command typed right after
Ctrl-C; pasted lines sent one after another) went out on the closing connection and was
lost: the front end saw "connection closed" and drew the last prompt. A client should
open a new connection for each request.

```json
{
  "id": "chatcmpl-…", "object": "chat.completion", "model": "raspberrypi-shell",
  "choices": [{"index": 0, "finish_reason": "stop",
               "message": {"role": "assistant", "content": "<terminal output>"}}],
  "honeypot": {
    "exit_code": 0,
    "cwd": "/root",
    "prompt": "\u001b[?2004hroot@raspberrypi:~# ",
    "source": "builtin",
    "close_session": false,
    "elapsed_ms": 3
  }
}
```

What Cowrie does with it:

1. Write `content` to the terminal, turning each `\n` into `\r\n` (normal terminal
   output). `content` already ends with `\n` when the command printed a line, and is
   `""` when it printed nothing: **do not add a newline of your own**.
2. If `close_session` is true (the attacker typed `exit` or `logout`, and `content`
   is `logout\n`), close the connection. Otherwise write `prompt` as-is.

For `login`, `content` is the whole login text (MOTD, `Last login:` line, the Wi-Fi
rfkill warning), and `prompt` is the first prompt. Printed this way the bytes match
what Ground Truth sends exactly, including one `\r\r\n` after the `Last login:` line
and the `\e[?2004h` in front of every prompt; `tests/test_relay.py` checks this
against `gt_frontdoor_2026-09.json`.

`exit_code`, `cwd` and `source` (`builtin`, `model`, `fallback`, `interrupted`, `login`, `logout`)
are for logging; Cowrie does not need them to draw the terminal. (`cache` was a fifth
`source`, the replayed-recording tier. It is off since 2026-10-08, config
`replay_tier`, and does not appear unless that is switched on.)

## Ctrl-C: the `interrupt` event (since 2026-10-13)

**Send it on every Ctrl-C of an interactive session**, whether a prompt is showing or
an answer is still being waited for: one request with
`"honeypot": {"event": "interrupt"}`, content `""`, the same `user` id. Do not wait
for the pending command's response first; send it at once.

What the relay does with it:

| Situation | Effect |
|---|---|
| a normal prompt is showing | nothing but `$?`, which becomes 130, as in bash |
| the `> ` prompt is showing (an unfinished line) | the half-typed command is dropped; the prompt that comes back is the normal one |
| **an answer is being generated** | the generation is stopped at once (the connection to the model node is shut, which also stops the node), and that command's own response returns right away with `content: ""`, `exit_code: 130`, `source: "interrupted"`. Lines of the same session that were sent before the Ctrl-C and are still waiting their turn are given up the same way, without being run: a terminal throws away what was typed ahead of a Ctrl-C |

The response to `interrupt` itself has `content: ""`, `exit_code: 130` and the
`prompt` to draw. So on Ctrl-C Cowrie writes `^C`, a line break, and **the `prompt`
of the interrupt's response** (not the last prompt it remembers).

**Why it matters for a pending answer:** without the event the relay cannot know the
command was given up. It finishes generating (up to the answer deadline, 25 s), and
since a session's commands are answered in order, whatever the attacker types next
waits for that. On a real machine Ctrl-C kills the command and the next one runs at
once. With the event the next command is answered immediately and the model node is
free again.

A response that arrives for a command Cowrie has already given up (it may cross the
Ctrl-C on the way) is ignored by Cowrie, as it does today.

On a relay failure: write the last prompt, as today.

## Unfinished lines: the `> ` prompt (since 2026-10-13)

A line bash cannot run yet (an open quote, a line ending in a backslash, `|`, `&&` or
`||`, an unclosed `$(`, an `if`/`for`/`while` without its end, a here-document) is
answered as bash answers it: `content` is `""` and `prompt` is `"\u001b[?2004h> "`. The
relay keeps the text; the next `command` is its next line, and when the command is
whole it is run and the normal prompt comes back. **Cowrie needs nothing new for this**:
it already writes `prompt` as it comes. Two consequences for Cowrie:

- **Ctrl-C must be told to the relay** (the section above): without it the relay goes
  on collecting lines for a command the attacker gave up, while Cowrie shows a normal
  prompt.
- Cowrie must not split or join lines itself, and must send empty lines too (an empty
  line inside an open quote is part of the text).

A here-document (`cat << EOF`) arrives the same way: line by line at `> `, until the
end word; the relay then runs the whole command. An answer that is one empty line
(a bare `echo`) has `content` `"\n"`: write it like any other content.

In run-one-command mode there is nothing more to read, so the relay answers with bash's
own error (`bash: -c: line 1: unexpected EOF while looking for matching `"'`, status 2).

## Errors

HTTP 400 with `{"error": {"message": …}}` for a missing `user`, an unknown event or
`stream: true`; 500 if the relay itself failed.

**On any failure** (a non-200 status, a body that is not JSON or lacks `choices` /
`honeypot`, a refused connection, a timeout), Cowrie prints nothing and writes **the
last `prompt` the relay sent in this session**, byte for byte. It must **never** draw
a prompt of its own: Cowrie's prompt comes from `cowrie.cfg` (`hostname`), lacks the
`\e[?2004h` in front, and shows Cowrie's working directory rather than the relay's.
If the failure is on `login`, so there is no last prompt yet, write
`"\u001b[?2004hroot@raspberrypi:~# "` (the first prompt, from
`gt_frontdoor_2026-09.json` `login.prompt_raw`). The same rule holds anywhere else
Cowrie would fall back to its own shell: nothing an attacker sees may come from
Cowrie's built-in filesystem or commands.

## Run-one-command mode (`exec`)

`ssh root@host 'uname -a'` asks the server to run one command without a shell
session. Measured on Ground Truth (2026-10-01, as `pi`, non-interactive):

- Nothing is printed but the command's own output: no MOTD, no `Last login:`, no
  Wi-Fi rfkill warning, **no prompt**. The connection closes when the command ends
  and the client gets its exit status (`exit 3` gives 3).
- Standard error stays separate from standard output: `ls /nonexistent` sent its
  message on stderr, and `ssh host cmd 2>/dev/null` hides it.
- There is no terminal: `tty` prints `not a tty` (exit 1); `$-` is `hBc`, `$0` is
  `bash`, `PS1` is empty, `echo $TERM` prints `dumb`. `env` lacks `TERM`, `SSH_TTY`,
  `NO_AT_BRIDGE` and `TEXTDOMAIN`; the rest is as in a login.
- bash's own errors start `bash: line 1:` instead of `-bash:`
  (`bash: line 1: lastlog2: command not found`).
- `ls` prints one name per line (its output is not a terminal).
- The session **is** listed by `who` and `w` while it runs (logind registers it; `w`
  shows no TTY and `sshd-session: pi [priv]` as WHAT), but it does **not** change the
  next `Last login:` line: `/var/log/lastlog` and `wtmp` were untouched by these runs.

How it works:

1. Cowrie sends **one** request with `event: "exec"`, the command string as
   `content`, and the address fields. No `login` and no `logout` before or after. A
   fresh `user` id, as for any session.
2. The relay runs it as `bash -c` would, as described above, and answers with
   `prompt: ""` and `close_session: true`. `content` ends with `\n` when the command
   printed something, as for `command`. The session is gone afterwards.
3. Cowrie writes `content` to the channel's standard output **without** turning
   `\n` into `\r\n` (no terminal, so no translation; the exception is a client that
   asked for one with `ssh -t`, where Cowrie converts as usual). If the response
   carries `honeypot.stderr`, Cowrie writes it to the channel's stderr (SSH extended
   data). The relay does not split the two yet; until it does, everything is in
   `content`.
4. Cowrie sends `exit_code` as the channel's exit status and closes the channel. It
   never writes a prompt in this mode.
5. On a relay failure: write nothing, send exit status 1, close the channel.

Example:

```json
{"model": "raspberrypi-shell", "user": "3f9a1c0e2b7d",
 "messages": [{"role": "user", "content": "tty"}],
 "honeypot": {"event": "exec", "username": "root",
              "src_ip": "10.11.12.57", "src_port": 51234,
              "dst_ip": "10.11.12.21", "dst_port": 22}}
```

answers `"content": "not a tty\n"` with `"honeypot": {"exit_code": 1, "cwd": "/root",
"prompt": "", "source": "builtin", "close_session": true, "elapsed_ms": 2}`.

## Tab completion (`complete`)

Cowrie's own completion lists Cowrie's built-in filesystem, which is not this
machine. Cowrie must **never** complete from it. On Tab, Cowrie sends
`event: "complete"` with the line typed so far as `content`. The relay will answer
with `honeypot.completion`:

```json
{"insert": "text to add at the cursor", "show": "text to print, or \"\"", "bell": false}
```

Cowrie writes `insert` as if the attacker had typed it. If `show` is not empty
(bash's list of candidates on a second Tab), Cowrie writes it, then the last prompt
and the line typed so far. If `bell` is true, it writes `\a`.

Until the relay supports `complete` it answers 400, and Cowrie treats that like no
match: write `\a` and nothing else. A bell is a small difference; a listing of
Cowrie's filesystem is a large one.

## SFTP and scp

**Deferred (decided 2026-10-01).** For now Cowrie switches SFTP **off**
(`sftp_enabled = false`), so a student gets a plain refusal rather than Cowrie's own
fake filesystem. That is a known difference from the real Pi, recorded with the cost
of doing it properly in `TASKS.md`. The rest of this section is what full support
would mean.

Ground Truth has SFTP **on**: `/etc/ssh/sshd_config` has
`Subsystem sftp /usr/lib/openssh/sftp-server` and the binary is there (checked
2026-10-01). Since OpenSSH 9.0, `scp` uses SFTP too, so turning SFTP off in Cowrie
would also break `scp` and give a `subsystem request failed` error the real Pi never
gives. Cowrie's SFTP serves Cowrie's fake filesystem, so it cannot stay as it is
either.

What it should do, with the relay's file state as the only filesystem:

- **Uploads** (`put`, `scp file host:`) go to the relay, which stores them in the
  machine-wide file state, so `ls` and `cat` in any shell session see them
  afterwards. Uploaded files are also the most valuable data for the paper.
- **Listings, `stat` and downloads** are answered by the relay from what it knows
  about the machine; a path it does not know gets `No such file`.
- The SFTP calls are **not designed yet** (likely `event`s such as `file_write`,
  `file_read`, `file_stat`, `file_list`). They need agreeing with Cowrie's side
  before either side builds them.

Legacy `scp -O` does not use SFTP: it runs `scp -t <path>` in exec mode and speaks
the old scp protocol over the channel. That is not handled.

## Not handled yet

- Interactive programs that take over the terminal (`vim`, `top` without `-b`,
  `passwd`, `less` on a pager) and anything reading stdin.
- `Ctrl-D` at the `> ` prompt (bash reports an unexpected end of file and returns to
  the normal prompt; Cowrie sends `logout`).
- `Ctrl-C` during a slow answer. A model answer can take 20 s or more; see the
  latency numbers in `TASKS.md`.
- In the relay: the `complete` event, a separate `stderr`, and the SFTP calls
  (sections above).
- Environment variables the client sends. Ground Truth accepts `LANG`, `LC_*`,
  `COLORTERM` and `NO_COLOR` (`AcceptEnv`), so e.g. `COLORTERM=truecolor` from a
  modern client shows up in `env` there. The protocol has no field for them yet.
- A shell session without a terminal (`ssh -T host`, then commands on stdin). It
  should behave like exec mode, with commands arriving line by line.

## Trying it without Cowrie

`tools/relay_client.py` speaks this protocol: interactively it is a pretend SSH
session, and with `--run gt43_lab_2026-09.json` it replays the 43 test commands.
