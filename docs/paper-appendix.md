# Paper appendix: setup, grading and fine-tuning details

Supplementary material for the paper *Measured Against a Real Machine: An LLM Honeypot
with a Shell and a Docker API That Agree, on Local Edge Hardware*. The paper's
methodology describes roles (reference machine, gateway, model nodes, front end, answer
engine); this file names what stands behind them and gives the grading rules in full.
Every number here is the one reported in the paper.

## A. Hardware, software and network

| Role | Device and system |
|:---|:---|
| Reference machine | Raspberry Pi 5 (8 GB), Raspberry Pi OS Lite 64-bit (Debian 13) |
| Gateway | A second Raspberry Pi 5 (8 GB) with the same operating system |
| Model nodes | Four NVIDIA Jetson Orin Nano boards (JetPack 6.2, Ubuntu 22.04) |

**Reference machine.** Mosquitto takes the sensor readings in, Node-RED holds the
automation logic and InfluxDB stores the series, as one Docker Compose project on
Docker CE 29.8.1 (Engine API 1.56, arm64): three containers, three images, five volumes,
four networks. The SSH server listens on TCP port 22 and the Docker daemon on port 2375
without authentication; the services publish on the loopback address only, so a scan
finds only these two ports. The shell history of `root` is empty. Participants sit on a
separate subnet from which only ports 22 and 2375 of the two Raspberry Pis can be
reached.

**Front end.** Cowrie (commit `05c217d3`, with a co-author's changes) takes SSH on
port 22 of the gateway, accepts only `root` and sends every line to the answer engine.
Before login it presents the reference machine's identification string, and the
reference machine's SSH server was restricted to exactly the front end's key-exchange,
cipher and integrity algorithms, in the same order (the one logged change to it; no
recorded answer reads it). The two offers then differ in one extension entry
(`publickey-hostbound@openssh.com`), which the team chose not to add.

**Answer engine and model.** The answer engine (the relay, [`honeypot/`](../honeypot))
is one Python process on the gateway; it offers an OpenAI-compatible endpoint on the
loopback interface ([`relay-protocol.md`](relay-protocol.md)). The boards serve
Qwen2.5 with 3 billion parameters, quantized to 4 bits, through ollama 0.34.0 at
temperature 0. A board silent for 10 s counts as down; an answer is cut at 25 s keeping
whole lines; if no board answers, the command prints `Segmentation fault` with exit
status 139.

## B. Recordings, test set and gradability

**The three groups of the 43 test commands.**

| Group | n | What the test checks | How it is graded |
|:---|---:|:---|:---|
| Core | 27 | The answer is the same in every run once volatile values are masked, and needs no earlier command | Exact: 18; after masking: 9 (2 of them as sets of lines) |
| Stateful | 8 | The answer reflects files that earlier commands of the session created | Exact: 6; after masking: 2 |
| Structural | 8 | The answer changes in every run (process lists, uptime, the shell's process number) | Not graded as text; right structure only |

**The two qualifications.** The five overlapping corpus entries are 25 of the 27 lines
of `/etc/passwd` (two entries), the first five lines of `/etc/os-release`, the first 15
of the 21 lines of the environment, and `hostnamectl status`; they are not loaded, and
fine-tuning data drops any recording sharing three consecutive lines with a test answer.
The captured list is the 138 kernel threads in the process table (the corpus shows 18),
affecting `ps -aux` and `top -bn1`. Not graded as text among the 43: `ps -aux`,
`top -bn1`, `echo $$`, `cat /proc/uptime`, `ping`; in the corpus 20 answers are masked
and 3 not graded.

**The scorer** ([`eval_scorer.py`](../eval_scorer.py)). Both texts are first normalized:
terminal escape sequences and carriage returns are removed, trailing spaces are stripped
and trailing blank lines dropped. This hides differences an attacker could see, such as
the hyperlink escape that the reference machine's `hostnamectl` prints around the
operating-system name. A test passes at the first level that holds; the lists of masked
tests, tests compared as sets and tests not graded as text come from one
machine-readable file, and a missing or unreadable file stops the run.

| Level | Rule |
|:---|:---|
| Identical | The normalized texts are equal. |
| Masked | Equal after the fields listed for that test are blanked (for example the source port in `SSH_CONNECTION`, process IDs of listening sockets, packet counters and MAC addresses in `ifconfig`, the boot ID in `hostnamectl`). |
| Set | The same lines in any order, duplicates counted (the two listings of listening sockets). |
| Right structure | Only for the 8 answers not graded as text; see below. |
| *Lenient, reported apart:* Semantic | Same number of lines and of tokens per line, identical words; numbers have the same unit and are within a factor of 1.5; spacing is ignored. |
| *Lenient, reported apart:* Subset | Only `df -h` and `lscpu`: the header and the root file system row (or the processor identity fields) must agree; other rows and sizes may differ. |

**Right structure.** The process listings must have the recorded column header and a
plausible number of lines; the shell's own process ID must be a number; uptime must be
two decimal numbers; `top` must show its header lines and a memory line within a factor
of five of the reference machine's in every figure; and `ping` must print the recorded
unreachable-network error and a total packet loss. Two of the test commands are asked
twice on purpose (24 and 25, 26 and 27) because a live value must change between calls:
if the reference machine's two answers differ and the honeypot's are identical, both
fail.

**Per-boot values.** The link-local IPv6 addresses, MAC addresses and names of the
container bridges and virtual interfaces, and the order of an interface's IPv6 lines,
change at every boot and are masked or compared as sets; each interface in a honeypot
answer must still show the link-local address its own MAC implies.

**Causes.** A failed answer gets the first cause that applies: empty (the model
declined, was cut off or was blocked); no memory of the session; a leaked identity or a
mention of a language model the reference answer lacks; a link-local address that does
not fit its interface; a live value that does not change between two calls; the right
layout with wrong values; the same words with different punctuation or spacing
(`-bash:` against `bash:`); no useful example retrieved; and invented content for the
rest.

**How the scorer was checked.** Both checks exposed errors that were then corrected. On
the 43 answers of the earlier hackathon build, which people had graded (17 passed), the
first version agreed with the human verdicts on 38; the five disagreements were `df -h`
and `lscpu` (other sizes or section layout), the two uptime commands (the same value
twice) and `top` (memory figures off by a factor of 13). The lenient level for the two
listings, the repeated-value rule and the memory rule were added, and the scorer now
agrees on all 43; since the lenient level was fitted to these verdicts, this shows that
it can express them, not that it agrees with people on new answers. Scored against the
reference machine's own earlier recordings, the first version gave 40 of 43, failing
`netstat` and `ss` (the same six lines in another order) and `ifconfig` (link-local
addresses change at every boot); with set comparison and per-boot masks it gives 43 of
43.

## C. How answers are produced and shared state

**Code and switches.** A line is answered in code only if every command and option in it
is implemented, so state is never half applied; formats were checked byte for byte
against the corpus and the reference machine's program versions in an emulated copy.
The answers moved to code last form thirteen categories, each behind a switch that
hands it back to the model. An earlier build's replay of a recorded answer for a command
typed exactly as in the corpus was removed as a stored answer (of the 159 corpus
commands it answered, 140 now go to the model and 19 are computed; no test command was
ever answered that way), as was the emulated API's lookup of the attack's exec output.

**Shared state.** The emulated API contains no Docker client, socket or proxy (a test
guards this). The reference machine's own client and compose plugin, run in the emulated
system against it, give the same text on 905 single command lines and 6 sequences of
state-changing commands. Generated, with no effect on the shared state: `exec` in a
running container, `kill`, `restart`, network and volume changes and the other compose
commands.

## D. Fine-tuning

**Models and data.** The 3B base model is the served Qwen2.5; the 1.7B one is Qwen3,
reasoning off throughout. 8,353 training records (16.1 million tokens per pass, the
longest 5,517), each a chat as the honeypot builds it: 996 from 166 corpus commands,
3,464 exact program texts (recorded with the reference machine's package versions in the
emulated system), 3,893 answers the code computes. The 169 held-back records were fixed
before the data grew. Training data holds no test command, no answer sharing three
consecutive lines with a test answer, no reference-machine address and no held-back
record, each checked by a test.

**Settings and rules.** Same for all methods: rank 16, scaling 32, learning rate 1e-4
with cosine decay, 16 records per step, three passes, best checkpoint by held-back loss.
One RTX 5090: 2.3 h (LoRA), 4.9 h (QLoRA), 4.7 h (DoRA), 2.1 h (1.7B with DoRA), peak
27 to 29 GB. Fine-tuning is used only if, as a 4-bit file on a node, a model is worse
than the base on no kind of record, better by at least ten points over all records, at
most 5% slower per token, and its wrong answers show nothing alarming (rules fixed
before training; only the speed condition changed, before any node measurement). In the
paper, the accuracy conditions were checked on the training machine's full-precision
scores and only the speed condition on a node. If both pass, the 1.7B model is taken if
the 3B gets fewer than five more of the 84 recorded and program-text records right (37
against 34) and the 1.7B answers at least 20% faster at the median (it was 37% faster);
otherwise the one with more right (equal: the 1.7B). Scored again at full precision
after the merge, the 3B model answers 102 and the 1.7B 95 of the 169 records exactly; 1
and 3 answers changed between right and wrong, the rounding of the merge.
