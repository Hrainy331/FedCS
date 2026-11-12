import hashlib


def install_peer_pinning(mpc, fingerprints):
    from mpyc import asyncoro

    base = asyncoro.MessageExchanger

    class PinnedExchanger(base):
        def __init__(self, rt, peer_pid=None):
            super().__init__(rt, peer_pid)
            self._pending = bytearray()
            self._certificate_pid = None
            self._registered = False
            self._rejected = False

        def connection_made(self, transport):
            self.transport = transport
            tls = transport.get_extra_info("ssl_object")
            if tls is None:
                self._reject()
                return
            fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            if fingerprint not in fingerprints:
                self._reject()
                return
            self._certificate_pid = fingerprints.index(fingerprint)
            if (self._certificate_pid == self.runtime.pid
                    or (self.peer_pid is not None and self.peer_pid != self._certificate_pid)
                    or (self.peer_pid is None and self._certificate_pid >= self.runtime.pid)):
                self._reject()
                return
            super().connection_made(transport)
            self._registered = self.peer_pid is not None

        def _reject(self):
            self._rejected = True
            self.transport.abort()

        def data_received(self, data):
            if self._rejected:
                return
            if self.peer_pid is None:
                self._pending.extend(data)
                if len(self._pending) < 2:
                    return
                if int.from_bytes(self._pending[:2], "little") != self._certificate_pid:
                    self._reject()
                    return
                extra = 0 if self.runtime.options.no_prss else self.runtime._prss_keys_from_peer(self._certificate_pid)
                if len(self._pending) < 2 + extra:
                    return
                data = bytes(self._pending)
                self._pending.clear()
            super().data_received(data)
            self._registered = self.peer_pid is not None

        def connection_lost(self, exc):
            if self._registered:

                super().connection_lost(None)

    asyncoro.MessageExchanger = PinnedExchanger
    if not mpc.options.ssl or len(mpc.parties) != 7 or mpc.threshold != 1:
        raise ValueError("Refusing insecure runtime options")
