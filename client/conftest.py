#
# Copyright 2021 VMware, Inc.
# Portions Copyright (c) 2024-2025, PostgreSQL Global Development Group
# SPDX-License-Identifier: PostgreSQL
#

import contextlib
import ctypes
import datetime
import functools
import ipaddress
import os
import socket
import struct
import sys
import threading

import psycopg2
import psycopg2.extras
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import pq3

BLOCKING_TIMEOUT = 2  # the number of seconds to wait for blocking calls


@pytest.fixture
def server_socket(unused_tcp_port_factory):
    """
    Returns a listening socket bound to an ephemeral port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", unused_tcp_port_factory()))
        s.listen(1)
        s.settimeout(BLOCKING_TIMEOUT)
        yield s


class ClientHandshake(threading.Thread):
    """
    A thread that connects to a local Postgres server using psycopg2. By
    default, once the opening handshake completes, the connection will be
    immediately closed. A _client_cb may be passed in the kwargs to perform
    custom actions after the handshake.
    """

    def __init__(self, *, port, **kwargs):
        super().__init__()

        self.client_cb = kwargs.get("_client_cb")
        if self.client_cb:
            del kwargs["_client_cb"]

        kwargs["port"] = port
        self._kwargs = kwargs

        self.exception = None

    def run(self):
        # Make sure the length of our hostaddr list matches the length of the
        # supplied host list.
        num_hosts = 1
        if "host" in self._kwargs:
            num_hosts = len(self._kwargs["host"].split(","))

        hostaddr = ",".join(["127.0.0.1"] * num_hosts)

        try:
            conn = psycopg2.connect(hostaddr=hostaddr, **self._kwargs)
            with contextlib.closing(conn):
                self._pump_async(conn)

                # Optionally call back into the test.
                if self.client_cb:
                    self.client_cb(conn)

        except Exception as e:
            self.exception = e

    def check_completed(self, timeout=BLOCKING_TIMEOUT):
        """
        Joins the client thread. Raises an exception if the thread could not be
        joined, or if it threw an exception itself. (The exception will be
        cleared, so future calls to check_completed will succeed.)
        """
        self.join(timeout)

        if self.is_alive():
            raise TimeoutError("client thread did not handshake within the timeout")
        elif self.exception:
            e = self.exception
            self.exception = None
            raise e

    def _pump_async(self, conn):
        """
        Polls a psycopg2 connection until it's completed. (Synchronous
        connections will work here too; they'll just immediately return OK.)
        """
        psycopg2.extras.wait_select(conn)


@pytest.fixture
def accept(server_socket):
    """
    Returns a factory function that, when called, returns a pair (sock, client)
    where sock is a server socket that has accepted a connection from client,
    and client is an instance of ClientHandshake. Clients will complete their
    handshakes and cleanly disconnect.

    The default connstring options may be extended or overridden by passing
    arbitrary keyword arguments. Keep in mind that you generally should not
    override the host or port, since they point to the local test server.

    For situations where a client needs to connect more than once to complete a
    handshake, the accept function may be called more than once. (The client
    returned for subsequent calls will always be the same client that was
    returned for the first call.) To avoid interfering with tests, fixtures that
    need to perform their own independent accept() call should call
    accept.reset() to clear the internal client once their work is done.

    Tests must either complete the handshake so that the client thread can be
    automatically joined during teardown, or else call client.check_completed()
    and manually handle any expected errors.
    """
    _, port = server_socket.getsockname()

    default_opts = dict(
        port=port,
        user=pq3.pguser(),
        sslmode="disable",
    )

    class _Accept(object):
        client = None

        def __call__(self, **kwargs):
            if self.client is None:
                opts = dict(default_opts)
                opts.update(kwargs)

                # The server_socket is already listening, so the client thread
                # can be safely started; it'll block on the connection until we
                # accept.
                self.client = ClientHandshake(**opts)
                self.client.start()

            sock, _ = server_socket.accept()
            sock.settimeout(BLOCKING_TIMEOUT)
            return sock, self.client

        def reset(self):
            """
            Joins any current client thread, then resets for a new call.
            """
            if self.client is not None:
                self.client.check_completed()

            self.client = None

    a = _Accept()
    yield a

    if a.client is not None:
        a.client.check_completed()


@pytest.fixture
def conn(accept):
    """
    Returns an accepted, wrapped pq3 connection to a psycopg2 client. The socket
    will be closed when the test finishes, and the client will be checked for a
    cleanly completed handshake.
    """
    sock, client = accept()
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            yield conn


class PQConnInfoOption(ctypes.Structure):
    """The structure returned by PQconndefaults()."""

    _fields_ = [
        ("keyword", ctypes.c_char_p),
        ("envvar", ctypes.c_char_p),
        ("compiled", ctypes.c_char_p),
        ("val", ctypes.c_char_p),
        ("label", ctypes.c_char_p),
        ("dispchar", ctypes.c_char_p),
        ("dispsize", ctypes.c_int),
    ]


def libpq_has_option(optname: str) -> bool:
    """
    Checks PQconndefaults() to see if the given option is supported. Useful for
    skipping tests conditionally.
    """
    libpq = ctypes.cdll.LoadLibrary("libpq.so.5")
    libpq.PQconndefaults.restype = ctypes.POINTER(PQConnInfoOption)

    opts = libpq.PQconndefaults()
    i = 0

    while opts[i].keyword is not None:
        if opts[i].keyword.decode() == optname:
            return True
        i += 1

    return False


@pytest.fixture
def gss_cred_cache():
    """
    Sets up a fake Kerberos credentials cache.
    """
    AES128_CTS_HMAC_SHA256_128 = 19
    KRB_NT_PRINCIPAL = 1
    KRB_NT_SRV_INST = 2
    IPV4 = 2

    def write_data(f, b: bytes):
        f.write(struct.pack(">I", len(b)))
        f.write(b)

    def write_principal(f, typ, realm, *components):
        f.write(
            struct.pack(
                ">II",
                typ,
                len(components),
            )
        )

        write_data(f, realm)
        for c in components:
            write_data(f, c)

    def write_addresses(f, typ, *addresses):
        f.write(struct.pack(">I", len(addresses)))
        for a in addresses:
            f.write(struct.pack(">H", typ))
            write_data(f, a)

    realm = b"EXAMPLE.ORG"

    filename = "krb.ccache"
    with open(filename, "wb") as cache:
        # Header
        cache.write(b"\x05")  # krb5 magic byte
        cache.write(struct.pack(">B", 4))  # format version 4
        cache.write(struct.pack(">H", 0))  # header length (no contents)

        # Default Principal
        write_principal(cache, KRB_NT_PRINCIPAL, realm, b"user")

        # Credential
        write_principal(cache, KRB_NT_PRINCIPAL, realm, b"user")  # client
        write_principal(cache, KRB_NT_SRV_INST, realm, b"server")  # server
        cache.write(struct.pack(">H", AES128_CTS_HMAC_SHA256_128))  # enctype
        write_data(cache, b"x" * 32)  # 256-bit key
        cache.write(
            struct.pack(
                ">IIIIBI",
                0,  # auth time
                0,  # start time
                2**32 - 1,  # end time
                0,  # renew till
                0,  # is_skey
                0,  # ticket flags
            )
        )
        write_addresses(cache, IPV4, b"\x7F\x00\x00\x01")
        cache.write(struct.pack(">I", 0))  # no authorizationdata
        write_data(cache, b"ticket")
        write_data(cache, b"second_ticket")

    os.environ["KRB5CCNAME"] = f"FILE:{os.path.abspath(filename)}"
    try:
        yield
    finally:
        del os.environ["KRB5CCNAME"]


@pytest.fixture
def require_gssapi(accept, gss_cred_cache):
    """Skips a dependent test if libpq doesn't have GSSAPI support."""
    supported = False

    sock, client = accept(gssencmode="prefer")
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            startup = pq3.recv1(conn, cls=pq3.Startup)

            if startup.proto == pq3.protocol(1234, 5680):  # GSSENCRequest
                supported = True

    expected_error = "server closed the connection unexpectedly"
    with pytest.raises(psycopg2.OperationalError, match=expected_error):
        client.check_completed()

    if not supported:
        pytest.skip("client was not built --with-gssapi")

    # Let the test set up its own client.
    accept.reset()


@pytest.fixture(scope="session")
def certpair(tmp_path_factory):
    """
    Yields a (cert, key) pair of file paths that can be used by a TLS server.
    The certificate is issued for "localhost" and its standard IPv4/6 addresses.
    """

    tmpdir = tmp_path_factory.mktemp("certs")
    now = datetime.datetime.now(datetime.timezone.utc)

    # https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    altNames = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(minutes=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(altNames), critical=False)
    ).sign(key, hashes.SHA256())

    # Writing the key with mode 0600 lets us use this from the server side, too.
    keypath = str(tmpdir / "key.pem")
    with open(keypath, "wb", opener=functools.partial(os.open, mode=0o600)) as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    certpath = str(tmpdir / "cert.pem")
    with open(certpath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return certpath, keypath
