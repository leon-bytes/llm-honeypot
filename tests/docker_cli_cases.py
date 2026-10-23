"""The command lines on which the shell's docker code is compared with the real client.

Each case is (scenario, has a terminal, the arguments after `docker`). The real client's
output for every case is recorded in tests/fixtures/docker_cli.json by
`tools/docker_cli_oracle.py --write` (it needs the arm64 userland and Ground Truth's
client; the test suite then needs neither). `--check` runs the real client again now
and compares, which is the way to try a new case before adding it here.

Scenarios (tools/docker_cli_oracle.py, build): "base" is the machine as recorded, three
running containers; "attacked" adds the attacker's three: one running with the host
mounted, one created and never started, one stopped.
"""
from __future__ import annotations
import json
import re
import sys
from types import SimpleNamespace

T = "table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"
ALL_PS = ("{{.ID}}|{{.Image}}|{{.Command}}|{{.CreatedAt}}|{{.RunningFor}}|{{.Ports}}|{{.State}}|"
          "{{.Status}}|{{.Size}}|{{.Names}}|{{.Mounts}}|{{.Networks}}|{{.LocalVolumes}}|"
          "{{.Platform}}|{{.HealthStatus}}")
ALL_IMG = ("{{.ID}}|{{.Repository}}|{{.Tag}}|{{.Digest}}|{{.CreatedSince}}|{{.CreatedAt}}|"
           "{{.Size}}|{{.Containers}}|{{.SharedSize}}|{{.UniqueSize}}")
N, I, M = "iot-stack-nodered-1", "iot-stack-influxdb-1", "iot-stack-mosquitto-1"

PS = [
    [], ["-a"], ["--all"], ["-q"], ["-aq"], ["-qa"], ["-q", "--no-trunc"], ["--no-trunc"],
    ["-a", "--no-trunc"], ["-n", "2"], ["-n2"], ["--last=1"], ["--last", "3"], ["-l"],
    ["--latest"], ["-n", "-1"], ["-n", "0"], ["-s"], ["-a", "-s"], ["-as"], ["-aqs"],
    ["--all=false"], ["--all=true"], ["-a", "-f", "status=exited"], ["-f", "status=running"],
    ["-a", "--filter", "status=created"], ["-a", "--filter=status=exited", "-q"],
    ["-a", "--filter", "status=running", "--filter", "name=nodered"],
    ["-a", "-f", "name=old", "-f", "status=created"], ["-a", "-f", "name=iot-stack"],
    ["-f", "ancestor=eclipse-mosquitto:2"], ["-a", "-f", "id=d139"],
    ["-f", "label=com.docker.compose.project=iot-stack"], ["-f", "health=healthy"],
    ["-f", "nosuch=1"], ["-f", "status=bogus"], ["-f", "status"], ["--filter"], ["-f"],
    ["-n", "abc"], ["--last=x"], ["--all=maybe"], ["extra"], ["--", "-a"], ["--nosuchflag"],
    ["-x"], ["-ax"], ["--format"], ["--help"], ["-h"],
    ["--format", "json"], ["-a", "--format", "json"], ["--format", "{{json .}}"],
    ["--format", "table"], ["--format", T], ["-a", "--format", T], ["--format", "table {{.Names}}"],
    ["-a", "--format", "table {{.ID}}\\t{{.Image}}\\t{{.Size}}"],
    ["-a", "--format", ALL_PS], ["-a", "--no-trunc", "--format", ALL_PS],
    ["-a", "--format", "table " + ALL_PS.replace("|", "\\t")],
    ["--format", "{{.Labels}}"], ["--format", "{{.Label \"com.docker.compose.service\"}}"],
    ["--format", "table {{.Names}}\\t{{.Label \"com.docker.compose.service\"}}"],
    ["--format", "{{.Names}}\\t{{.ID}}"], ["--format", "{{.Names}}: {{.Ports}}"],
    ["-a", "--no-trunc", "--format", "{{.ID}} {{.Command}}"], ["--format", "{{.Nope}}"],
    ["--format", "{{.Names"], ["--format", "{{nosuchfunc .Names}}"], ["--format", ""],
    ["-a", "--format", "{{upper .Names}} {{lower .Image}} {{title .State}} {{truncate .ID 4}} "
                       "{{len .Names}}"],
    ["--format", "{{println .Names}}"],
    ["--format", "{{if eq .State \"running\"}}UP{{else}}DOWN{{end}} {{.Names}}"],
    ["-a", "--format", "{{if ne .State \"running\"}}{{.Names}} is {{.State}}{{end}}"],
    ["-a", "--format", "{{range $i, $n := split .Names \"-\"}}[{{$i}}:{{$n}}]{{end}}"],
    ["--format", "{{printf \"%-30s|%s\" .Names .Image}}"],
    ["--format", "{{join (split .Image \":\") \"@\"}}"],
    ["--format", "{{.Names}} {{with .Ports}}has {{.}}{{else}}none{{end}}"],
    ["-q", "--format", "{{.Names}}"], ["--format", "{{.Names}}", "-q"],
    ["--format", "{{$n := .Names}}{{$n}}/{{$n | len}}"],
    ["--format", "{{- .Names -}} "], ["--format", "{{/* nothing */}}{{.ID}}"],
]
IMAGES = [
    [], ["-a"], ["-q"], ["-aq"], ["--no-trunc"], ["-q", "--no-trunc"], ["--digests"],
    ["--digests", "--no-trunc"], ["influxdb"], ["influxdb:2.7-alpine"], ["nodered/node-red"],
    ["nosuch"], ["a", "b"], ["--bogus"], ["-x"], ["--format"], ["--help"],
    ["--format", "json"], ["--format", "table"], ["--format", ALL_IMG],
    ["--format", "table " + ALL_IMG.replace("|", "\\t")], ["--no-trunc", "--format", "{{.ID}}"],
    ["--format", "table {{.Repository}}\\t{{.Tag}}\\t{{.Size}}"], ["--format", "{{.Nope}}"],
    ["--format", "{{.Repository}}:{{.Tag}}"], ["--format", "{{.ID"], ["--format", "{{json .}}"],
    ["-f", "dangling=true"], ["-f", "dangling=false"], ["-f", "reference=influx*"],
    ["-f", "reference=*mosquitto*", "-q"], ["-f", "nosuch=1"], ["-q", "influxdb"],
    ["--digests", "influxdb"], ["--format", "{{.Size}}", "nodered/node-red:4.1"],
    ["--tree"], ["--tree", "-a"], ["--tree", "influxdb"], ["--tree", "nosuch"],
    ["--tree", "--format", "json"], ["--tree", "-q"], ["--tree", "--no-trunc"],
    ["--tree", "--digests"], ["-q", "--format", "{{.Tag}}"], ["-f", "bad"],
]
INSPECT = [
    [], ["nosuch"], [I], [N], [M], ["old"], ["probe"], [I, N], ["nosuch", I], [I, "nosuch", "also-not"],
    ["-s", I], ["--size", "old"], ["influxdb:2.7-alpine"], ["iot-stack_default"],
    ["iot-stack_influxdb-data"], ["bridge"], ["d139ff53533c"], ["--type", "bogus", "x"],
    ["--type", "container", I], ["--type", "container", "influxdb:2.7-alpine"],
    ["--type", "image", "influxdb:2.7-alpine"], ["--type", "image", I],
    ["--type", "network", "iot-stack_default"], ["--type", "volume", "iot-stack_influxdb-data"],
    ["--type", "volume", "nosuch"], ["--type=network", "nosuch"], ["--type"], ["--bogus", I],
    ["--help"],
    ["-f", "json", "old"], ["--format=json", I, "old"], ["-f", "{{json .}}", "old"],
    ["-f", "{{.State.Status}}", I, N], ["--format", "{{.State.Status}}", "nosuch", I],
    ["-f", "{{.Name}}", "d139ff53533c", "4430"], ["-f", "{{.Id}}", I], ["-f", "{{.ID}}", I],
    ["-f", "{{.Name}} {{.RestartCount}} {{.Path}} {{.Args}}", N],
    ["-f", "{{.State.Pid}} {{.State.Running}} {{.State.ExitCode}} {{.State.StartedAt}}", M],
    ["-f", "{{.State.Status}} {{.State.ExitCode}} {{.State.FinishedAt}}", "old"],
    ["-f", "{{.State.Health.Status}} {{len .State.Health.Log}}", N],
    ["-f", "{{.HostConfig.Privileged}} {{.HostConfig.PidMode}} {{json .HostConfig.Binds}}", "probe"],
    ["-f", "{{.HostConfig.Binds}} {{.HostConfig.NetworkMode}} {{.HostConfig.RestartPolicy.Name}}", M],
    ["-f", "{{.Config.Image}} {{.Image}} {{.Config.Hostname}} {{.Config.User}}|{{.Config.WorkingDir}}", N],
    ["-f", "{{.Config.Env}}", I], ["-f", "{{json .Config.Env}}", I], ["-f", "{{index .Config.Env 0}}", I],
    ["-f", "{{range .Config.Env}}{{println .}}{{end}}", I], ["-f", "{{.Config.Cmd}} {{.Config.Entrypoint}}", I],
    ["-f", "{{.Config.Labels}}", M], ["-f", "{{json .Config.Labels}}", M],
    ["-f", "{{index .Config.Labels \"com.docker.compose.service\"}}", M],
    ["-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", I],
    ["-f", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}}/{{$v.MacAddress}} {{end}}", I],
    ["-f", "{{json .NetworkSettings.Networks}}", N], ["-f", "{{json .Mounts}}", M],
    ["-f", "{{range .Mounts}}{{.Type}}:{{.Source}}->{{.Destination}} {{end}}", M],
    ["-f", "{{json .State}}", N], ["-f", "{{json .HostConfig.PortBindings}}", N],
    ["-f", "{{json .NetworkSettings.Ports}}", N],
    ["-f", "{{.Nope}}", I], ["-f", "{{.State.Nope.Deeper}}", I], ["-f", "{{.NetworkSettings.IPAddress}}", N],
    ["-f", "{{.GraphDriver.Name}}", I], ["-f", "{{ .Name", "old"], ["-f", "{{nosuchfunc .Name}}", "old"],
    ["-f", "{{.State.Nope}}", I, N], ["-f", "{{.SizeRw}}", I],
    ["-f", "{{.State.Health.Status}}", N, I, M], ["-f", "{{.State.Health.Status}}", I, N],
    ["-f", "{{.State.Nope}}", "nosuch", I], ["-f", "{{.Name}}{{.State.Nope}}", I],
    ["-f", "{{with .State.Health}}{{.Status}}{{else}}no health check{{end}}", I, N],
    ["-f", "{{.State.Health}}", I], ["-f", "{{json .State.Health}}", I], ["-s", "-f", "{{.SizeRw}} {{.SizeRootFs}}", I],
    ["-f", "{{if .State.Running}}yes{{else}}no{{end}} {{with .State.Health}}{{.Status}}{{end}}", N, "old"],
    ["-f", "{{printf \"%s:%d\" .Name .State.Pid}} {{eq .State.Status \"running\"}} "
           "{{and .State.Running true}} {{not .State.Paused}}", N],
    ["--format={{println .Name}}{{.State.StartedAt}}", N],
    ["--format", "{{.RepoTags}} {{.Size}} {{.Architecture}} {{.Os}}", "influxdb:2.7-alpine"],
    ["--type", "image", "-f", "{{.Id}}", "influxdb:2.7-alpine"],
    ["-f", "{{.Name}} {{.Driver}} {{.Scope}}", "iot-stack_default"],
    ["-f", "{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{end}}", "iot-stack_default"],
    ["-f", "{{.Name}} {{.Mountpoint}} {{.Driver}}", "iot-stack_influxdb-data"],
    ["-f", "{{.Name}}\\t{{.State.Status}}", I],
]
LOGS = [
    [], ["a", "b"], ["nosuch"], [M], [I], [N], ["probe"], ["old"], ["d3775f38b3d4"],
    ["--tail", "3", N], ["-n", "2", I], ["-n2", M], ["--tail=5", M], ["--tail", "all", M],
    ["--tail", "abc", M], ["--tail", "0", M], ["--tail", "-1", M], ["-t", "--tail", "2", M],
    ["--timestamps", "-n", "1", N], ["-tn1", N], ["--details", "--tail", "1", M],
    ["--since", "10m", M], ["--since", "2h", "--tail", "2", M], ["--since", "90m", M],
    ["--until", "1h", "--tail", "2", M], ["--since", "2h", "--until", "30m", M],
    ["--since", "bogus", M], ["--until", "bogus", M], ["--since", "2020-01-01", "--tail", "1", M],
    ["--since", "2020-01-01T00:00:00", "--tail", "1", M], ["--since", "1500000000", "--tail", "1", M],
    [M, "--tail", "1"], ["--bogus", "x"],
    ["-n"], ["--help"], ["-t", "old"],
]

NW, VOL = "iot-stack_default", "iot-stack_influxdb-data"
ALL_NET = "{{.ID}}|{{.Name}}|{{.Driver}}|{{.Scope}}|{{.IPv4}}|{{.IPv6}}|{{.Internal}}|{{.Labels}}|{{.CreatedAt}}"
ALL_VOL = ("{{.Name}}|{{.Driver}}|{{.Scope}}|{{.Mountpoint}}|{{.Labels}}|{{.Links}}|{{.Size}}|"
           "{{.Availability}}|{{.Group}}|{{.Status}}")
ALL_STATS = "{{.Container}}|{{.Name}}|{{.ID}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.BlockIO}}|{{.PIDs}}"
# The read-only commands added 2026-10-13. Each list holds the words after `docker`.
MORE = [
    ["network"], ["network", "--help"], ["network", "bogus"], ["network", "ls"], ["network", "list"],
    ["network", "ls", "--no-trunc"], ["network", "ls", "-q"], ["network", "ls", "-q", "--no-trunc"],
    ["network", "ls", "-f", "driver=bridge"], ["network", "ls", "--filter", "name=iot"],
    ["network", "ls", "-f", "type=custom"], ["network", "ls", "-f", "type=builtin"],
    ["network", "ls", "-f", "scope=local", "-f", "driver=null"], ["network", "ls", "-f", "nosuch=1"],
    ["network", "ls", "-f", "label=com.docker.compose.project=iot-stack"], ["network", "ls", "-f", "bad"],
    ["network", "ls", "--format", "json"], ["network", "ls", "--format", ALL_NET],
    ["network", "ls", "--no-trunc", "--format", "{{.ID}} {{.Name}}"],
    ["network", "ls", "--format", "table " + ALL_NET.replace("|", "\\t")],
    ["network", "ls", "--format", "table {{.Name}}\\t{{.Label \"com.docker.compose.project\"}}"],
    ["network", "ls", "-q", "--format", "{{.Name}}"], ["network", "ls", "--format", "table"],
    ["network", "ls", "--format", "{{.Nope}}"], ["network", "ls", "--format", "{{.Name"],
    ["network", "ls", "extra"], ["network", "ls", "--bogus"], ["network", "ls", "-x"],
    ["network", "ls", "--help"], ["network", "ls", "--format"],
    ["network", "inspect"], ["network", "inspect", "nosuch"], ["network", "inspect", "bridge"],
    ["network", "inspect", NW], ["network", "inspect", "host", "none"], ["network", "inspect", NW, "nosuch"],
    ["network", "inspect", "f5676"], ["network", "inspect", "-v", "none"], ["network", "inspect", "--verbose", NW],
    ["network", "inspect", "-f", "json", "none"], ["network", "inspect", "-f", "{{.Name}} {{.Driver}}", NW, "host"],
    ["network", "inspect", "-f", "{{.Created}}", "bridge"], ["network", "inspect", "-f", "{{.Nope}}", "bridge"],
    ["network", "inspect", "-f", "{{range $id, $c := .Containers}}{{$c.Name}}={{$c.IPv4Address}} {{end}}", NW],
    ["network", "inspect", "-f", "{{json .IPAM.Config}}", NW], ["network", "inspect", "--bogus", NW],
    ["network", "inspect", "--help"],
    ["volume"], ["volume", "bogus"], ["volume", "ls"], ["volume", "list"], ["volume", "ls", "-q"],
    ["volume", "ls", "--format", "json"], ["volume", "ls", "--format", ALL_VOL],
    ["volume", "ls", "--format", "table {{.Name}}\\t{{.Label \"com.docker.compose.volume\"}}\\t{{.Mountpoint}}"],
    ["volume", "ls", "-f", "dangling=true"], ["volume", "ls", "-f", "dangling=false"],
    ["volume", "ls", "-f", "name=influx"], ["volume", "ls", "-f", "driver=local"],
    ["volume", "ls", "-f", "label=com.docker.compose.project=iot-stack"],
    ["volume", "ls", "-f", "label=com.docker.compose.project=iot-stack", "-f", "label=com.docker.compose.volume=nodered-data"],
    ["volume", "ls", "-f", "nosuch=1"], ["volume", "ls", "-q", "--format", "{{.Driver}}"],
    ["volume", "ls", "--format", "{{.Nope}}"], ["volume", "ls", "x"], ["volume", "ls", "--bogus"],
    ["volume", "ls", "--help"],
    ["volume", "inspect"], ["volume", "inspect", "nosuch"], ["volume", "inspect", VOL],
    ["volume", "inspect", VOL, "nosuch", "iot-stack_nodered-data"],
    ["volume", "inspect", "-f", "{{.Mountpoint}}", "iot-stack_nodered-data"],
    ["volume", "inspect", "--format", "json", "iot-stack_nodered-data"],
    ["volume", "inspect", "-f", "{{.CreatedAt}} {{.Labels}} {{.Options}}", "iot-stack_nodered-data"],
    ["volume", "inspect", "-f", "{{.Nope}}", VOL], ["volume", "inspect", "--help"],
    ["version"], ["version", "-f", "json"], ["version", "--format", "{{.Server.Version}} {{.Client.Version}}"],
    ["version", "--format", "{{json .Server}}"], ["version", "--format", "{{json .Client}}"],
    ["version", "-f", "{{.Client.Os}}/{{.Client.Arch}} {{.Server.Os}} {{range .Server.Components}}{{.Name}}={{.Version}} {{end}}"],
    ["version", "x"], ["version", "--bogus"], ["version", "-f", "{{.Nope}}"], ["version", "--help"],
    ["info"], ["system", "info"], ["info", "-f", "json"], ["info", "x"], ["info", "-f", "{{.Nope}}"],
    ["info", "--format", "{{.ServerVersion}} {{.NCPU}} {{.MemTotal}} {{.Containers}} {{.ContainersRunning}} {{.Name}}"],
    ["info", "-f", "{{.Driver}} {{.Swarm.LocalNodeState}} {{.ClientInfo.Context}} {{len .ClientInfo.Plugins}} {{json .Plugins.Volume}}"],
    ["info", "-f", "{{.OperatingSystem}}|{{.KernelVersion}}|{{.Architecture}}|{{.DockerRootDir}}|{{.ID}}"],
    ["info", "--help"], ["info", "--bogus"],
    ["system"], ["system", "bogus"], ["system", "df"], ["system", "df", "-v"], ["system", "df", "--verbose"],
    ["system", "df", "--format", "json"],
    ["system", "df", "--format", "{{.Type}}|{{.TotalCount}}|{{.Active}}|{{.Size}}|{{.Reclaimable}}"],
    ["system", "df", "--format", "table {{.Type}}\\t{{.Size}}"], ["system", "df", "--format", "{{.Nope}}"],
    ["system", "df", "x"], ["system", "df", "--bogus"], ["system", "df", "--help"],
    ["top"], ["top", "nosuch"], ["top", N], ["top", I], ["top", M], ["top", "old"], ["top", "probe"],
    ["top", N, "aux"], ["top", N, "-ef"], ["container", "top", M], ["top", "--help"],
    ["top", "--bogus", "x"], ["top", "-x", N], ["top", "d139ff53533c"],
    ["stats", "--no-stream"], ["stats", "--no-stream", N], ["stats", "--no-stream", "-a"],
    ["stats", "--no-stream", "--no-trunc"], ["stats", "--no-stream", "--format", "json"],
    ["stats", "--no-stream", "nosuch"], ["stats", "--no-stream", "old"],
    ["stats", "--no-stream", "--format", ALL_STATS], ["stats", "--no-stream", "--format", ALL_STATS, I, M],
    ["stats", "--no-stream", "--format", "table {{.Name}}\\t{{.PIDs}}"], ["stats", "--bogus"],
    ["stats", "--no-stream", "-q"], ["container", "stats", "--no-stream"],
    ["stats", "--no-stream", "-a", N, "old"], ["stats", "--no-stream", "--format", "{{.Nope}}"],
    ["stats", "--help"],
    ["container"], ["image"], ["container", "bogus"], ["image", "bogus"],
    ["container", "inspect"], ["container", "inspect", "nosuch"], ["container", "inspect", I, "-f", "{{.Name}}"],
    ["container", "inspect", "influxdb:2.7-alpine"], ["container", "inspect", "-s", "-f", "{{.SizeRw}}", I],
    ["container", "inspect", "--help"],
    ["image", "inspect"], ["image", "inspect", "nosuch"], ["image", "inspect", I],
    ["image", "inspect", "influxdb:2.7-alpine", "-f", "{{.Id}}"], ["image", "inspect", "--help"],
    ["container", "ls", "--help"], ["container", "ls", "--bogus"], ["container", "ls", "x"],
    ["image", "ls", "--help"], ["image", "ls", "a", "b"], ["container", "logs"], ["container", "logs", "--help"],
    ["compose"], ["compose", "--help"], ["compose", "version"], ["compose", "version", "--short"],
    ["compose", "version", "-f", "json"], ["compose", "version", "--help"],
    ["compose", "ls"], ["compose", "ls", "-a"], ["compose", "ls", "-q"], ["compose", "ls", "--format", "json"],
    ["compose", "ls", "--filter", "name=iot"], ["compose", "ls", "--filter", "name=zzz"],
    ["compose", "ls", "x"], ["compose", "ls", "--bogus"], ["compose", "ls", "--help"],
    ["compose", "ps"], ["compose", "-p", "iot-stack", "ps"], ["compose", "-p", "nosuch", "ps"],
    ["compose", "-f", "/root/iot-stack/docker-compose.yml", "ps"], ["compose", "--file", "iot-stack/docker-compose.yml", "ps"],
    ["compose", "-p", "iot-stack", "ps", "-a"], ["compose", "-p", "iot-stack", "ps", "-q"],
    ["compose", "-p", "iot-stack", "ps", "--services"], ["compose", "-p", "iot-stack", "ps", "nodered"],
    ["compose", "-p", "iot-stack", "ps", "nodered", "influxdb"],
    ["compose", "-p", "iot-stack", "ps", "--status", "running"], ["compose", "-p", "iot-stack", "ps", "--status", "exited"],
    ["compose", "-p", "iot-stack", "ps", "--filter", "status=running"], ["compose", "-p", "iot-stack", "ps", "--no-trunc"],
    ["compose", "-p", "iot-stack", "ps", "--format", "table {{.Name}}\\t{{.State}}"],
    ["compose", "-p", "iot-stack", "ps", "--format", "table {{.Service}}\\t{{.Status}}\\t{{.Ports}}"],
    ["compose", "-p", "iot-stack", "ps", "--bogus"], ["compose", "ps", "--help"],
]

CASES = []
for scenario in ("base", "attacked"):
    for args in MORE:
        if scenario == "base" and any(x in ("old", "probe") for x in args):
            continue
        CASES.append((scenario, False, args))
# compose finds its file from the directory it is run in, or above it
for cwd in ("/root/iot-stack", "/root/iot-stack/mosquitto", "/tmp"):
    for argv in (["compose", "ps"], ["compose", "ps", "-q"], ["compose", "ls"]):
        CASES.append(("attacked", False, argv, cwd))
for scenario in ("base", "attacked"):
    for name, group in (("ps", PS), ("images", IMAGES), ("inspect", INSPECT), ("logs", LOGS)):
        for args in group:
            if scenario == "base" and any(x in ("old", "probe") for x in args):
                continue
            CASES.append((scenario, False, [name, *args]))
# On a terminal: the default `images` view is in colour under a legend; the rest is the same.
for scenario in ("base", "attacked"):
    for argv in (["images"], ["images", "-a"], ["images", "influxdb"], ["images", "nosuch"],
                 ["images", "-q"], ["images", "--no-trunc"], ["images", "--tree"], ["ps"], ["ps", "-a"],
                 ["inspect", "-f", "{{.Name}}", I], ["logs", "--tail", "2", N]):
        CASES.append((scenario, True, argv))
for alias in (["container", "ls", "-a"], ["container", "ps", "-q"], ["container", "list"],
              ["image", "ls"], ["image", "list", "-q"], ["container", "logs", "--tail", "1", M]):
    CASES.append(("attacked", False, alias))


# Commands that change the state, checked in sequences: each list is one fresh
# "attacked" machine, the commands run on it in order, on the real client and on ours.
PF = ["ps", "-a", "--format", "{{.Names}} {{.State}} {{.Status}}"]
SEQUENCES = [
    [["stop", "old"], ["stop", "nosuch"], ["stop"], ["stop", "probe"], ["start", "probe"], PF,
     ["start", "old"], ["start", "old"], ["start", "nosuch"], ["start"], ["stop", "-t", "2", "old"],
     ["stop", "--time=0", "old", "probe"], PF, ["rm", "old"], ["rm", "probe", "nosuch"], ["rm"],
     ["rm", N], ["rm", "-f", "-v", "nosuch"], PF, ["volume", "ls", "-q"]],
    [["stop", N], ["ps", "--format", "{{.Names}} {{.Status}}"], PF, ["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}} {{.State.Running}}", N],
     ["start", N], ["ps", "--format", "{{.Names}} {{.Status}}"], ["stop", M, I],
     ["start", M, I, "nosuch"], ["rm", "-f", M], PF, ["volume", "ls", "-q"], ["network", "inspect", "-f", "{{len .Containers}}", NW],
     ["compose", "-p", "iot-stack", "ps", "-a"], ["compose", "ls", "-a"], ["system", "df"], ["info", "-f", "{{.Containers}} {{.ContainersRunning}} {{.ContainersStopped}}"]],
    [["pull", "alpine"], ["pull"], ["pull", "influxdb:2.7-alpine"], ["pull", "-q", "busybox:1.36"],
     ["pull", "-q", "busybox"], ["pull", "nodered/node-red:4.1"], ["pull", "a", "b"], ["pull", "--bogus", "x"],
     ["stop", "--bogus"], ["start", "--help"], ["stop", "--help"], ["rm", "--help"], ["pull", "--help"],
     ["container", "stop", "old"], ["container", "start", "old"], ["container", "rm", "-f", "old"],
     ["image", "pull", "alpine"], ["stop", "-s", "SIGKILL", "probe"], ["rm", "-fv", "probe"], PF,
     ["start", "-x", "old"], ["rm", "--volumes", "--force", N], PF, ["images"], ["stats", "--no-stream", "-a", "--format", "{{.Name}} {{.PIDs}}"]],
    # run and create with an image that is not on the machine: the pull fails
    [["run", "alpine"], ["run", "-d", "--name", "web", "-v", "/:/host", "-p", "8080:80", "ubuntu:22.04", "sleep", "100"],
     ["create", "busybox"], ["run"], ["create"], ["run", "--bogus", "alpine"],
     ["run", "-d", "--privileged", "--pid=host", "--net", "host", "alpine:3.19", "nsenter", "-t", "1", "-m", "sh"],
     PF, ["run", "--name"], ["run", "-v"], ["container", "run", "alpine"], ["container", "create", "alpine"],
     ["run", "-e", "A=1", "--entrypoint", "sh", "docker.io/library/alpine:latest", "-c", "id"],
     ["run", "ghcr.io/x/y"], ["run", "--rm", "nginx:1.27-alpine"], ["create", "--name", "c1", "-it", "debian", "bash"],
     ["run", "-dit", "--restart=always", "library/redis:7"], ["run", "--help"], ["create", "--help"],
     ["run", "-it"], ["run", "-d", "-e", "X=1", "--", "alpine", "true"], ["images", "-q"], PF],
    # create and run -d with an image that IS on the machine: the container exists
    # afterwards, with what every flag asked for
    [["create", "--name", "loc1", "eclipse-mosquitto:2"], ["create", "--name", "loc1", "eclipse-mosquitto:2"],
     ["run", "-d", "--name", "loc1", "eclipse-mosquitto:2"],
     ["run", "-d", "--name", "web", "-p", "8080:80", "-p", "127.0.0.1:9000:9000/udp", "-p", "1883", "-e", "A=1",
      "-v", "/:/host", "-v", "/data", "--restart", "on-failure:3", "-l", "x=y=z", "-w", "/tmp", "-u", "1000",
      "--hostname", "box", "nodered/node-red:4.1"],
     ["run", "-d", "--privileged", "--pid=host", "--net", "host", "--cap-add", "sys_admin", "--cap-drop", "ALL",
      "--entrypoint", "sh", "--init", "--read-only", "-it", "influxdb:2.7-alpine", "-c", "sleep 600"],
     PF, ["ps", "-a", "--no-trunc", "--format", "{{.Names}}|{{.Command}}|{{.Ports}}|{{.Mounts}}|{{.Networks}}"],
     ["inspect", "-f", "{{json .Config}}", "loc1"], ["inspect", "-f", "{{json .HostConfig}}", "loc1"],
     ["inspect", "-f", "{{json .Config}}", "web"], ["inspect", "-f", "{{json .HostConfig}}", "web"],
     ["inspect", "-f", "{{json .NetworkSettings.Ports}} {{json .Mounts}} {{.Path}} {{json .Args}}", "web"],
     ["ps", "-lq"], ["ps", "-l", "--format", "{{.Command}} {{.Networks}} {{.Ports}}"],
     ["create", "--rm", "--restart", "always", "eclipse-mosquitto:2"],
     ["create", "--entrypoint", "", "nodered/node-red:4.1"], ["run", "-d", "--entrypoint", "", "nodered/node-red:4.1"],
     ["create", "-it", "--name", "sh1", "eclipse-mosquitto:2", "sh"], ["inspect", "-f", "{{json .Config}}", "sh1"],
     ["start", "sh1"], ["create", "--name", "x", "eclipse-mosquitto:2"],
     ["run", "-d", "--rm", "--network", "iot-stack_default", "-e", "B=2", "-e", "B=3", "eclipse-mosquitto:2", "sleep", "5"],
     ["ps", "-l", "--format", "{{.Command}} {{.Networks}} {{.Ports}}"],
     ["container", "create", "-l", "plain", "--restart=unless-stopped", "eclipse-mosquitto:2"],
     ["container", "run", "--detach", "eclipse-mosquitto:2"], ["create", "-d", "eclipse-mosquitto:2"],
     ["rm", "-f", "-v", "sh1", "web"], ["volume", "ls", "-q"], ["system", "df"], PF,
     ["network", "inspect", "-f", "{{len .Containers}}", "bridge"], ["images", "-q"]],
    # a network that does not exist (accepted by create, refused at start), and exec
    # where the state alone decides: no such container, a stopped one, a never-started one
    [["create", "--name", "n1", "--network", "nosuch", "eclipse-mosquitto:2"], ["start", "n1"], PF,
     ["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}} {{.State.Error}}", "n1"],
     ["run", "-d", "--name", "n2", "--net", "nosuch", "eclipse-mosquitto:2"], PF,
     ["exec", "nosuch", "ls"], ["exec", "old", "ls"], ["exec", "-it", "probe", "sh"], ["exec", "-d", "probe", "id"],
     ["exec"], ["exec", "probe"], ["container", "exec", "nosuch", "id"], ["exec", "--help"], ["top", "probe"],
     ["start", "n1", "old"], ["rm", "n1", "n2"], PF],
]


def ours(state, clock, case: dict) -> tuple[str, int]:
    """dockercli.py's answer to a recorded case: (output with its final newline, exit)."""
    from honeypot import dockercli
    sess = SimpleNamespace(terminal=case["tty"], cols=case["cols"], cwd=case.get("cwd", "/root"),
                           delay=0.0)
    out, code = dockercli.render(state, ["docker", *case["argv"]], sess, case["now"])
    return (out + "\n" if out else ""), code


_RUNTIMES = re.compile(r"(?m)^ Runtimes: (.*)$")
_TRAFFIC = re.compile(r"\d+(?:\.\d+)?[kMG]?B / \d+(?:\.\d+)?[kMG]?B")


def comparable(case: dict, text: str) -> str:
    """What of an answer can be compared with the real client's, which is everything
    but two things the real client does not fix either.

    `docker info` prints its runtimes in the order Go walks a map, which changes from
    run to run: the words of that line are sorted. `docker stats` asks for every
    container at the same moment and each answer takes 1 to 2 s of the daemon's clock;
    in a recorded run those waits pile up on the oracle's one clock in whatever order
    the requests arrived, so with several containers the traffic counters and the CPU
    share are a little later than a replay's: there the byte counts of NET I/O and
    BLOCK I/O and the CPU figure are masked, and with them the column widths. Names,
    IDs, the columns, PIDS and every error text are compared as they are, and so is
    the whole answer when one container is named."""
    argv = case["argv"]
    if argv[:1] == ["info"] or argv[:2] == ["system", "info"]:
        text = _RUNTIMES.sub(lambda m: " Runtimes: " + " ".join(sorted(m.group(1).split())), text)
    if {"pull", "run", "create"} & set(argv[:2]):     # the resolver's source port is random
        text = re.sub(r"\]:\d+->", "]:<PORT>->", text)
    one = [a for a in argv if a in (N, I, M, "old", "probe", "nosuch")]
    if "stats" in argv[:2] and len(one) != 1:        # one container: compared as it is
        text = _TRAFFIC.sub("<N> / <N>", text)
        text = re.sub(r"\d+\.\d\d%", "<P>", text)
        text = re.sub(r" {2,}", "  ", text)
    return text


def _run_all(Oracle, only: str = ""):
    for scenario in ("base", "attacked"):
        o = Oracle(scenario)
        try:
            for s, tty, argv, *cwd in CASES:
                if s == scenario and " ".join(argv).startswith(only):
                    yield o, {**o.run(argv, tty, cwd=cwd[0] if cwd else "/root"),
                              "scenario": scenario, "t0": o.t0}
        finally:
            o.close()


def run_sequences(Oracle, only: str = "") -> list[dict]:
    """Every sequence on a fresh machine with the real client: [{t0, steps: [case]}]."""
    out = []
    for seq in SEQUENCES:
        if only and not any(" ".join(argv).startswith(only) for argv in seq):
            continue
        o = Oracle("attacked")
        try:
            out.append({"scenario": "attacked", "t0": o.t0,
                        "steps": [{**o.run(argv), "scenario": "attacked", "t0": o.t0} for argv in seq]})
        finally:
            o.close()
    return out


def replay(build, seq: dict) -> list[tuple[dict, tuple[str, int]]]:
    """Our answers to a recorded sequence, on a fresh state of our own."""
    state, _, clock = build(seq["t0"], seq["scenario"])
    out = []
    for case in seq["steps"]:
        try:
            got = ours(state, clock, case)
        except Exception as e:
            got = (f"<{type(e).__name__}: {e}>", -99)
        out.append((case, got))
    return out


def generate(Oracle, path, sequences_only: bool = False) -> int:
    """Records the real client into `path`, with the site's values written as their
    `@@key@@` (honeypot/site.py): the fixture is published, the values are not."""
    from honeypot.site import SITE
    keys = [k for k in SITE.values if not k.startswith("dev_")]
    old = SITE.load_json(path) if path.exists() else {}
    cases = old.get("cases", []) if sequences_only else [case for _, case in _run_all(Oracle)]
    sequences = run_sequences(Oracle)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps({"client": "docker-ce-cli 29.8.1, linux/arm64 (Ground Truth's)",
                       "cases": cases, "sequences": sequences}, indent=1, ensure_ascii=False) + "\n"
    path.write_text(SITE.tokens(text, keys))
    print(f"{len(cases)} cases and {len(sequences)} sequences "
          f"({sum(len(q['steps']) for q in sequences)} steps) recorded -> {path}")
    return 0


def check(Oracle, show: int = 12, only: str = "") -> int:
    bad = 0
    total = 0
    for o, case in _run_all(Oracle, only):
        total += 1
        try:
            got = ours(o.state, o.clock, case)
        except Exception as e:                      # Unsupported included: nothing may escape
            got = (f"<{type(e).__name__}: {e}>", -99)
        if (comparable(case, got[0]), got[1]) != (comparable(case, case["output"]), case["exit"]):
            bad += 1
            if bad <= show:
                print(f"\n--- [{case['scenario']}{', tty' if case['tty'] else ''}] docker "
                      + " ".join(case["argv"]))
                print(f"real client (exit {case['exit']}):\n{case['output']!r}"[:700])
                print(f"ours        (exit {got[1]}):\n{got[0]!r}"[:700])
    from docker_cli_oracle import build
    for seq in run_sequences(Oracle, only):
        for case, got in replay(build, seq):
            total += 1
            if (comparable(case, got[0]), got[1]) != (comparable(case, case["output"]), case["exit"]):
                bad += 1
                if bad <= show:
                    print("\n--- [sequence] docker " + " ".join(case["argv"]))
                    print(f"real client (exit {case['exit']}):\n{case['output']!r}"[:700])
                    print(f"ours        (exit {got[1]}):\n{got[0]!r}"[:700])
    print(f"\n{total - bad} of {total} cases identical to the real client; {bad} differ")
    return 1 if bad else 0
