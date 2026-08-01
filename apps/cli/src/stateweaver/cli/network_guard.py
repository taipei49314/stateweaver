"""Process-local egress guard for the socket-free foundation workflow."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from typing import Any, Final, Never, cast

NETWORK_GUARD_VERSION: Final = "python-socket-deny-v2"
_GUARD_LOCK = RLock()


class NetworkEgressDenied(RuntimeError):
    """Raised before a guarded operation can resolve or connect to a network address."""


@dataclass
class NetworkGuardState:
    denied_attempts: int = 0


@contextmanager
def deny_network_egress() -> Iterator[NetworkGuardState]:
    """Deny DNS, stream connects, UDP sends, and server creation within this process."""

    with _GUARD_LOCK:
        state = NetworkGuardState()
        original_socket = socket.socket
        original_getaddrinfo = socket.getaddrinfo
        original_gethostbyname = socket.gethostbyname
        original_gethostbyname_ex = socket.gethostbyname_ex
        original_gethostbyaddr = socket.gethostbyaddr
        original_getnameinfo = socket.getnameinfo
        original_create_connection = socket.create_connection
        original_create_server = socket.create_server

        def blocked() -> Never:
            state.denied_attempts += 1
            raise NetworkEgressDenied("foundation network access is denied")

        class GuardedSocket(socket.socket):
            def bind(self, address: Any) -> None:
                del address
                blocked()

            def listen(self, backlog: int = 0) -> None:
                del backlog
                blocked()

            def connect(self, address: Any) -> None:
                del address
                blocked()

            def connect_ex(self, address: Any) -> int:
                del address
                blocked()

            def sendto(self, *args: Any, **kwargs: Any) -> int:
                del args, kwargs
                blocked()

            def sendmsg(self, *args: Any, **kwargs: Any) -> int:
                del args, kwargs
                blocked()

            def sendmsg_afalg(self, *args: Any, **kwargs: Any) -> int:
                del args, kwargs
                blocked()

        def deny_call(*args: object, **kwargs: object) -> Never:
            del args, kwargs
            blocked()

        mutable_socket = cast(Any, socket)
        mutable_socket.socket = GuardedSocket
        mutable_socket.getaddrinfo = deny_call
        mutable_socket.gethostbyname = deny_call
        mutable_socket.gethostbyname_ex = deny_call
        mutable_socket.gethostbyaddr = deny_call
        mutable_socket.getnameinfo = deny_call
        mutable_socket.create_connection = deny_call
        mutable_socket.create_server = deny_call
        try:
            yield state
        finally:
            mutable_socket.socket = original_socket
            mutable_socket.getaddrinfo = original_getaddrinfo
            mutable_socket.gethostbyname = original_gethostbyname
            mutable_socket.gethostbyname_ex = original_gethostbyname_ex
            mutable_socket.gethostbyaddr = original_gethostbyaddr
            mutable_socket.getnameinfo = original_getnameinfo
            mutable_socket.create_connection = original_create_connection
            mutable_socket.create_server = original_create_server
