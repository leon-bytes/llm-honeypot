# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
The lowest level SSH protocol. This handles the key negotiation, the
encryption and the compression. The transport layer is described in
RFC 4253.
"""

from __future__ import annotations

import re
import struct
import time
import uuid
import zlib
from typing import Any

from twisted.conch.ssh import _kex, transport
from twisted.conch.ssh.common import NS, getNS
from twisted.internet.protocol import connectionDone
from twisted.logger import Logger
from twisted.protocols.policies import ProtocolWrapper, TimeoutMixin
from twisted.python import failure, randbytes

from cowrie.core.config import CowrieConfig
from cowrie.core.events import EventLog, transport_events
from cowrie.core.utils import escape_nonprintable, hassh_client


class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    _log = Logger()
    startTime: float = 0.0
    gotVersion: bool = False
    buf: bytes
    transportId: str
    # The session's event emitter, bound in connectionMade (or, under the
    # PROXY protocol, on the first dataReceived) when the running application
    # provides a dispatcher.
    events: EventLog | None = None
    # Set when running behind a PROXY-protocol proxy: cowrie.session.connect is
    # held back until the PROXY header has been parsed and getPeer() reflects
    # the real client.
    _emit_connect_pending: bool = False
    ipv4rex = re.compile(r"^::ffff:(\d+\.\d+\.\d+\.\d+)$")
    auth_timeout: int = CowrieConfig.getint(
        "honeypot", "authentication_timeout", fallback=120
    )
    interactive_timeout: int = CowrieConfig.getint(
        "honeypot", "interactive_timeout", fallback=300
    )
    ourVersionString: bytes  # set by factory
    transport: Any
    outgoingCompression: Any
    _blockedByKeyExchange: Any

    _KEX_STRICT_C = b"kex-strict-c-v00@openssh.com"
    _KEX_STRICT_S = b"kex-strict-s-v00@openssh.com"
    _MSG_PING = 192
    _MSG_PONG = 193
    _SERVER_SIG_ALGS = (
        b"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
        b"sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,"
        b"rsa-sha2-512,rsa-sha2-256"
    )

    def __init__(self) -> None:
        super().__init__()
        self._strict_kex = False
        self._initial_kex_received = False
        self._initial_kex_sent = False
        self._initial_kex_done = False
        self._newkeys_sent = False
        self._strict_expected = transport.MSG_KEXINIT
        self._strict_disconnect = False
        self._initial_ext_info_sent = False
        self._initial_peer_ext_info_c = False
        self._expect_client_ext_info = False
        self._ext_info_in_auth = False
        self._userauth_request_seen = False

    def _strict_failure(self) -> None:
        self._strict_disconnect = True
        self.transport.loseConnection()

    def __repr__(self) -> str:
        """
        Return a pretty representation of this object.

        @return Pretty representation of this object as a string
        @rtype: L{str}
        """
        return f"Cowrie SSH Transport to {self.transport.getPeer().host}"

    def connectionMade(self) -> None:
        """
        Called when the connection is made from the other side.
        We send our version, but wait with sending KEXINIT
        """
        self.buf = b""

        self.transportId = uuid.uuid4().hex[:12]

        if isinstance(self.transport, ProtocolWrapper):
            # A protocol wrapper in front of us (the haproxy: endpoint's PROXY
            # parser) only resolves the real client address once it has read
            # the header, which happens on the first dataReceived(). Defer
            # cowrie.session.connect until then so it carries the real IP
            # rather than the proxy's.
            self._emit_connect_pending = True
        else:
            self._emit_connect()

        self.transport.write(self.ourVersionString + b"\r\n")
        self.currentEncryptions = transport.SSHCiphers(
            b"none", b"none", b"none", b"none"
        )
        self.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")

        self.startTime = time.time()
        self.setTimeout(self.auth_timeout)

    def _emit_connect(self) -> None:
        """
        Bind the session event log and announce cowrie.session.connect using
        the current (possibly PROXY-resolved) peer address.
        """
        src_ip: str = self.transport.getPeer().host
        ipv4_search = self.ipv4rex.search(src_ip)
        if ipv4_search is not None:
            src_ip = ipv4_search.group(1)

        self.events = transport_events(
            self.factory,
            self.transport,
            session=self.transportId,
            protocol="ssh",
            src_ip=src_ip,
        )

    def sendKexInit(self) -> None:
        """
        Don't send key exchange prematurely
        """
        if not self.gotVersion:
            return
        # A client that sends a second KEXINIT before the first key exchange
        # completes drives the base sendKexInit into raising a RuntimeError.
        # Disconnect such a protocol violation cleanly instead.
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            self._log.info("Duplicate KEXINIT during key exchange, disconnecting")
            self._strict_failure()
            return
        # Twisted 26.4.0 has no marker hook. Keep its serializer/state changes,
        # adding strict KEX only to the first wire list, not executable KEX.
        algorithms = list(self.supportedKeyExchanges) + [self._EXT_INFO_S]
        if not self._initial_kex_sent:
            algorithms.append(self._KEX_STRICT_S)
        self.ourKexInitPayload = b"".join(
            [
                bytes((transport.MSG_KEXINIT,)),
                randbytes.secureRandom(16),
                NS(b",".join(algorithms)),
                NS(b",".join(self.supportedPublicKeys)),
                *[
                    NS(b",".join(values))
                    for values in (
                        self.supportedCiphers,
                        self.supportedCiphers,
                        self.supportedMACs,
                        self.supportedMACs,
                        self.supportedCompressions,
                        self.supportedCompressions,
                        self.supportedLanguages,
                        self.supportedLanguages,
                    )
                ],
                b"\x00\x00\x00\x00\x00",
            ]
        )
        self._initial_kex_sent = True
        self._newkeys_sent = False
        self.sendPacket(transport.MSG_KEXINIT, self.ourKexInitPayload[1:])
        self._keyExchangeState = self._KEY_EXCHANGE_REQUESTED
        self._blockedByKeyExchange = []

    def _unsupportedVersionReceived(self, remoteVersion: bytes) -> None:
        """
        Change message to be like OpenSSH
        """
        self.transport.write(b"Protocol major versions differ.\n")
        self.transport.loseConnection()

    def dataReceived(self, data: bytes) -> None:
        """
        First, check for the version string (SSH-2.0-*).  After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.

        @type data: C{str}
        """
        if self._emit_connect_pending:
            # First bytes have arrived, which under the PROXY protocol means
            # the header has been parsed and getPeer() now reflects the real
            # client. Announce the connection before processing the data.
            self._emit_connect_pending = False
            self._emit_connect()

        self.buf = self.buf + data
        if not self.gotVersion:
            if b"\n" not in self.buf:
                return
            self.otherVersionString: bytes = self.buf.split(b"\n")[0].strip()
            if self.events:
                self.events.dispatch(
                    "cowrie.client.version",
                    "Remote SSH version: %(version)s",
                    version=escape_nonprintable(self.otherVersionString),
                )
            m = re.match(rb"SSH-(\d+\.\d+)-(.*)", self.otherVersionString)
            if m is None:
                self._log.info(
                    "Bad protocol version identification: {version!r}",
                    version=self.otherVersionString,
                )
                # OpenSSH sending the same message
                self.transport.write(b"Invalid SSH identification string.\n")
                self.transport.loseConnection()
                return
            self.gotVersion = True
            remote_version = m.group(1)
            if remote_version not in self.supportedVersions:
                self._unsupportedVersionReceived(self.otherVersionString)
                return
            i = self.buf.index(b"\n")
            self.buf = self.buf[i + 1 :]
            self.sendKexInit()
        packet = self.getPacket()
        while packet:
            if self._strict_disconnect:
                return
            messageNum = ord(packet[0:1])
            self.dispatchMessage(messageNum, packet[1:])
            if self._strict_disconnect:
                return
            packet = self.getPacket()

    def dispatchMessage(self, messageNum: int, payload: bytes) -> None:
        if self._strict_disconnect:
            return
        if self._strict_kex and not self._initial_kex_done:
            if messageNum == transport.MSG_DISCONNECT:
                pass
            elif self.ignoreNextPacket and 30 <= messageNum <= 49:
                # RFC 4253's incorrect speculative KEX packet is discarded,
                # without advancing the negotiated method's expected message.
                self.ignoreNextPacket = False
                return
            elif messageNum != self._strict_expected and not (
                self._strict_expected == transport.MSG_KEX_DH_GEX_REQUEST
                and messageNum == transport.MSG_KEX_DH_GEX_REQUEST_OLD
            ):
                self._strict_failure()
                return
            elif messageNum in (
                transport.MSG_KEX_DH_GEX_REQUEST,
                transport.MSG_KEX_DH_GEX_REQUEST_OLD,
            ):
                if _kex.isEllipticCurve(self.kexAlg) or _kex.isFixedGroup(self.kexAlg):
                    self._strict_expected = transport.MSG_NEWKEYS
                else:
                    self._strict_expected = transport.MSG_KEX_DH_GEX_INIT
            elif messageNum == transport.MSG_KEX_DH_GEX_INIT:
                self._strict_expected = transport.MSG_NEWKEYS
        try:
            if self._expect_client_ext_info and messageNum != transport.MSG_EXT_INFO:
                self._expect_client_ext_info = False
            if (
                messageNum == 50  # SSH_MSG_USERAUTH_REQUEST
                and self.service is not None
                and self.service.name == b"ssh-userauth"
                and not self._userauth_request_seen
            ):
                # Validate the three string headers before advertising. This
                # happens after receipt, but before authentication can succeed
                # synchronously and switch the active service.
                rest = payload
                for _ in range(3):
                    if len(rest) < 4:
                        raise struct.error("Truncated USERAUTH_REQUEST")
                    size = struct.unpack("!L", rest[:4])[0]
                    if size > len(rest) - 4:
                        raise struct.error("Truncated USERAUTH_REQUEST string")
                    rest = rest[4 + size:]
                self._userauth_request_seen = True
                if self._initial_peer_ext_info_c and self._ext_info_in_auth:
                    # Do not use sendExtInfo: that hook owns the initial
                    # advertisement, and rekeying may change Twisted's flag.
                    self.sendPacket(
                        transport.MSG_EXT_INFO,
                        struct.pack("!L", 1)
                        + NS(b"server-sig-algs") + NS(self._SERVER_SIG_ALGS),
                    )
            if messageNum in (self._MSG_PING, self._MSG_PONG):
                # getNS alone permits truncated bodies. Require exactly one
                # complete SSH string, with no trailing bytes, before echoing.
                if (
                    len(payload) < 4
                    or struct.unpack("!L", payload[:4])[0] != len(payload) - 4
                ):
                    raise struct.error("Invalid Ping/Pong SSH string")
                if messageNum == self._MSG_PING:
                    # sendPacket queues non-KEX traffic during rekeying, so
                    # PONGs retain arrival order and use the new packet keys.
                    self.sendPacket(self._MSG_PONG, payload)
                # Unsolicited PONGs are harmless and must not reach a service
                # or trigger another response.
                return
            transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)
        except struct.error:
            self._strict_disconnect = True
            # A truncated or garbage message body underflows getNS()/struct
            # parsing inside a handler (any message type: service-request,
            # userauth, channel ops, ...). Real OpenSSH treats this as a fatal
            # protocol error, logging server-side and dropping the connection
            # without a SSH_MSG_DISCONNECT; match that (which also avoids a
            # cowrie-specific disconnect string), and record the probe -- these
            # malformed pre-auth packets are a common exploit/scanner signal.
            if self.events:
                self.events.dispatch(
                    "cowrie.client.malformed_packet",
                    "Malformed SSH packet (message %(messagenum)d, %(datalen)d bytes); disconnecting",
                    messagenum=messageNum,
                    datalen=len(payload),
                    data=payload[:256].hex(),
                )
            self.transport.loseConnection()

    def sendPacket(self, messageType: int, payload: bytes) -> None:
        """
        Override because OpenSSH pads with 0 on KEXINIT
        """
        if self.transport is None:
            return
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            if not self._allowedKeyExchangeMessageType(messageType):
                self._blockedByKeyExchange.append((messageType, payload))
                return

        payload = bytes((messageType,)) + payload
        if self.outgoingCompression:
            payload = self.outgoingCompression.compress(
                payload
            ) + self.outgoingCompression.flush(2)
        bs = self.currentEncryptions.encBlockSize
        # 4 for the packet length and 1 for the padding length
        totalSize = 5 + len(payload)
        lenPad = bs - (totalSize % bs)
        if lenPad < 4:
            lenPad = lenPad + bs
        padding: bytes
        if messageType == transport.MSG_KEXINIT:
            padding = b"\0" * lenPad
        else:
            padding = randbytes.secureRandom(lenPad)

        packet = struct.pack(b"!LB", totalSize + lenPad - 4, lenPad) + payload + padding
        encPacket = self.currentEncryptions.encrypt(
            packet
        ) + self.currentEncryptions.makeMAC(self.outgoingPacketSequence, packet)
        self.transport.write(encPacket)
        self.outgoingPacketSequence += 1
        if messageType == transport.MSG_NEWKEYS:
            self._newkeys_sent = True
            if self._strict_kex:
                self.outgoingPacketSequence = 0

    def ssh_NEWKEYS(self, packet: bytes) -> None:
        if self._strict_kex:
            # getPacket has authenticated and incremented the old receive
            # sequence. Validate before resetting or flushing queued traffic.
            if (
                packet
                or not self._newkeys_sent
                or self._keyExchangeState != self._KEY_EXCHANGE_PROGRESSING
            ):
                self._strict_failure()
                return
            self.incomingPacketSequence = 0
        if not packet and not self._initial_kex_done:
            self._expect_client_ext_info = True
        self._initial_kex_done = True
        self._newkeys_sent = False
        transport.SSHServerTransport.ssh_NEWKEYS(self, packet)

    def sendExtInfo(self, extensions) -> None:
        """Extend Twisted's initial, peer-gated advertisement exactly once."""
        if (
            not self._peerSupportsExtensions
            or self._initial_ext_info_sent
            or self._initial_kex_done
        ):
            return
        advertised = dict(extensions)
        advertised[b"server-sig-algs"] = self._SERVER_SIG_ALGS
        advertised[b"ping@openssh.com"] = b"0"
        # Host-bound authentication is not implemented: do not claim it.
        self._initial_ext_info_sent = True
        transport.SSHServerTransport.sendExtInfo(self, list(advertised.items()))

    def ssh_EXT_INFO(self, packet: bytes) -> None:
        initial = self._expect_client_ext_info
        self._expect_client_ext_info = False
        if len(packet) < 4:
            raise struct.error("Truncated EXT_INFO")
        count = struct.unpack("!L", packet[:4])[0]
        rest = packet[4:]
        if count > len(rest) // 8:
            raise struct.error("Truncated EXT_INFO entries")
        for _ in range(count * 2):
            size = struct.unpack("!L", rest[:4])[0] if len(rest) >= 4 else -1
            if size < 0 or size > len(rest) - 4:
                raise struct.error("Truncated EXT_INFO string")
            rest = rest[4 + size:]
        if rest:
            raise struct.error("Trailing EXT_INFO data")
        transport.SSHServerTransport.ssh_EXT_INFO(self, packet)
        if initial:
            self._ext_info_in_auth = (
                self.peerExtensions.get(b"ext-info-in-auth@openssh.com") == b"0"
            )

    def ssh_KEXINIT(self, packet: bytes) -> Any:
        k = getNS(packet[16:], 10)
        strings, _ = k[:-1], k[-1]
        (kexAlgs, keyAlgs, encCS, _, macCS, _, compCS, _, langCS, _) = (
            s.split(b",") for s in strings
        )

        if not self._initial_kex_received:
            self._initial_kex_received = True
            self._initial_peer_ext_info_c = self._EXT_INFO_C in kexAlgs
            self._strict_kex = self._KEX_STRICT_C in kexAlgs
            if self._strict_kex and self.incomingPacketSequence != 1:
                self._strict_failure()
                return
        elif self._strict_kex and (
            not self._initial_kex_done
            or self._keyExchangeState == self._KEY_EXCHANGE_PROGRESSING
        ):
            self._strict_failure()
            return
        self._newkeys_sent = False
        if self._strict_kex and len(k[-1]) != 5:
            self._strict_failure()
            return

        hasshAlgorithms, hassh = hassh_client(kexAlgs, encCS, macCS, compCS)

        if self.events:
            self.events.dispatch(
                "cowrie.client.kex",
                "SSH client hassh fingerprint: %(hassh)s",
                hassh=hassh,
                hasshAlgorithms=hasshAlgorithms,
                kexAlgs=kexAlgs,
                keyAlgs=keyAlgs,
                encCS=encCS,
                macCS=macCS,
                compCS=compCS,
                langCS=langCS,
            )

        result = transport.SSHServerTransport.ssh_KEXINIT(self, packet)
        if self._strict_disconnect:
            return result
        if self._strict_kex and self.kexAlg is not None:
            # Twisted leaves a peer-initiated exchange in REQUESTED after
            # sending its reply KEXINIT. Both KEXINITs have now been exchanged.
            self._keyExchangeState = self._KEY_EXCHANGE_PROGRESSING
        if self._strict_kex and not self._initial_kex_done:
            if self.kexAlg is None:
                return result
            if _kex.isEllipticCurve(self.kexAlg) or _kex.isFixedGroup(self.kexAlg):
                self._strict_expected = transport.MSG_KEX_DH_GEX_REQUEST_OLD
            else:
                # Both RFC 4419 and its old request form are supported below.
                self._strict_expected = transport.MSG_KEX_DH_GEX_REQUEST
        return result

    def timeoutConnection(self) -> None:
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        self._log.info("Timeout reached in HoneyPotSSHTransport")
        self.transport.loseConnection()

    def setService(self, service):
        """
        Remove login grace timeout, set zlib compression after auth
        """
        # Reset timeout. Not everyone opens shell so need timeout at transport level
        if service.name == b"ssh-connection":
            self.setTimeout(self.interactive_timeout)

        # when auth is successful we enable compression
        # this is called right after MSG_USERAUTH_SUCCESS
        if service.name == b"ssh-connection":
            if self.outgoingCompressionType == b"zlib@openssh.com":
                self.outgoingCompression = zlib.compressobj(6)
            if self.incomingCompressionType == b"zlib@openssh.com":
                self.incomingCompression = zlib.decompressobj()

        transport.SSHServerTransport.setService(self, service)

    def connectionLost(self, reason: failure.Failure | None = connectionDone) -> None:
        """
        This seems to be the only reliable place of catching lost connection
        """
        self.setTimeout(None)
        transport.SSHServerTransport.connectionLost(self, reason)
        if self._emit_connect_pending:
            # A proxied connection whose PROXY header carried no trailing data
            # never reached dataReceived(), so the deferred announce never
            # fired. getPeer() is resolved by now; announce it before closing
            # so the connection is still logged (as a direct one would be).
            self._emit_connect_pending = False
            self._emit_connect()
        self.transport = None
        duration_ms = round((time.time() - self.startTime) * 1000)
        if self.events is not None:
            self.events.session_closed(duration_ms)

    def sendDisconnect(self, reason, desc):
        """
        http://kbyte.snowpenguin.org/portal/2013/04/30/kippo-protocol-mismatch-workaround/
        Workaround for the "bad packet length" error message.

        @param reason: the reason for the disconnect.  Should be one of the
                       DISCONNECT_* values.
        @type reason: C{int}
        @param desc: a description of the reason for the disconnection.
        @type desc: C{str}
        """
        if self._strict_kex:
            self._strict_disconnect = True
        if b"bad packet length" not in desc:
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            # this message is used to detect Cowrie behaviour
            # self.transport.write(b"Packet corrupt\n")
            self._log.info(
                "[SERVER] - Disconnecting with error, code {code} reason: {desc}",
                code=reason,
                desc=desc,
            )
            self.transport.loseConnection()

    def receiveError(self, reasonCode, description):
        """
        Called when we receive a disconnect error message from the other side.

        @param reasonCode: the reason for the disconnect, one of the
                           DISCONNECT_ values.
        @type reasonCode: L{int}
        @param description: a human-readable description of the
                            disconnection.
        @type description: L{str}
        """
        self._log.info(
            "Got remote error, code {code} reason: {description}",
            code=reasonCode,
            description=description,
        )
