import datetime
import functools
import io
import os
import ssl
import sys

import psycopg2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import pq3
import tls

from .conftest import libpq_has_option
from .test_client import finish_handshake


@pytest.fixture
def certpair():
    """
    Yields a (cert, key) pair of file paths that can be used by a TLS server.
    """

    now = datetime.datetime.now(datetime.timezone.utc)

    # https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "example.org")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(minutes=10))
    ).sign(key, hashes.SHA256())

    # Writing the key with mode 0600 lets us use this from the server side, too.
    with open("./key.pem", "wb", opener=functools.partial(os.open, mode=0o600)) as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open("./cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return "./cert.pem", "./key.pem"


def require_libpq_option(opt):
    if not libpq_has_option(opt):
        pytest.skip(f"libpq must support {opt}")


ALPN_PROTO = "postgresql"  # our ALPN protocol identifier


def test_negotiated_ssl(accept, certpair):
    """
    Happy path for standard negotiated TLS.
    """
    sock, client = accept(
        host="example.org",
        sslmode="verify-full",
        sslrootcert=certpair[0],
    )
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(*certpair)
            ctx.set_alpn_protocols([ALPN_PROTO])

            with pq3.tls_handshake(conn, ctx, server_side=True) as tls:
                startup = pq3.recv1(tls, cls=pq3.Startup)
                assert startup.proto == pq3.protocol(3, 0)

                finish_handshake(tls)


def test_direct_ssl(accept, certpair):
    """
    Happy path for sslnegotiation=direct.
    """
    require_libpq_option("sslnegotiation")

    sock, client = accept(
        host="example.org",
        sslnegotiation="direct",
        sslmode="verify-full",
        sslrootcert=certpair[0],
    )
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(*certpair)
            ctx.set_alpn_protocols([ALPN_PROTO])

            tls = pq3._TLSStream(conn, ctx, server_side=True)
            tls.handshake()
            assert tls._ssl.selected_alpn_protocol() == ALPN_PROTO

            tls = pq3._DebugStream(tls, conn._out)

            startup = pq3.recv1(tls, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(3, 0)

            finish_handshake(tls)


def test_direct_ssl_without_alpn(accept, certpair):
    """
    Ensure that the client hangs up on a server that doesn't select our ALPN
    identifier.
    """
    require_libpq_option("sslnegotiation")

    sock, client = accept(
        host="example.org",
        sslnegotiation="direct",
        sslmode="verify-full",
        sslrootcert=certpair[0],
    )
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(*certpair)

            # Don't select the ALPN protocol.
            # ctx.set_alpn_protocols([ALPN_PROTO])

            tls = pq3._TLSStream(conn, ctx, server_side=True)
            tls.handshake()
            assert tls._ssl.selected_alpn_protocol() == None

            # The client shouldn't send anything more.
            assert not tls.read(), "client sent unexpected data"

    expected = "SSL connection was established without ALPN"
    with pytest.raises(psycopg2.OperationalError, match=expected):
        client.check_completed()


def test_direct_ssl_failed_negotiation(accept, certpair):
    """
    Test that the client displays a useful message when attempting direct SSL
    with a server that doesn't support it.
    """
    require_libpq_option("sslnegotiation")

    sock, client = accept(
        host="example.org",
        sslnegotiation="direct",
        sslmode="verify-full",
        sslrootcert=certpair[0],
    )
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            # Emulate an older server: read an 8k block from the socket...
            conn.read(8192)
            conn.flush_debug(prefix="  ")

            # ...then drop the connection.

    with pytest.raises(psycopg2.OperationalError, match="EOF detected"):
        client.check_completed()


def test_gssapi_negotiation(require_gssapi, accept, certpair):
    """
    Test the expected order of fallbacks.
    TODO: it's not clear that this is the _desired_ order of fallbacks.
    """
    require_libpq_option("sslnegotiation")

    sock, client = accept(
        host="example.org",
        gssencmode="prefer",
        sslnegotiation="direct",
        sslmode="verify-full",
        sslrootcert=certpair[0],
    )

    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            # First attempt is GSS.
            startup = pq3.recv1(conn, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(1234, 5680)

            # Reject it.
            conn.write(b"N")
            conn.flush_debug(prefix="  ")

            # Second attempt is standard SSL.
            startup = pq3.recv1(conn, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(1234, 5679)

            # Reject it, too.
            conn.write(b"N")
            conn.flush_debug(prefix="  ")

    # Accept the next connection, which should be direct SSL.
    sock, _ = accept()
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            # Don't complete the handshake, but make sure it's actually a
            # client_hello.
            pkt = pq3.recv1(conn, cls=tls.Plaintext)
            inner = io.BytesIO(pkt.fragment)
            handshake = tls.Handshake.parse_stream(inner)
            assert handshake.msg_type == tls.HandshakeType.client_hello

            # Reject the direct SSL connection by dropping it.

    # TODO: decide on the actual error message
    with pytest.raises(psycopg2.OperationalError, match="TODO"):
        client.check_completed()
