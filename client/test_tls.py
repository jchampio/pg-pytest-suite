import datetime
import ssl
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import pq3

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

    with open("./key.pem", "wb") as f:
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


def test_direct_ssl(accept, certpair):
    sock, client = accept(
        sslnegotiation="requiredirect",
        sslmode="require",
        sslrootcert=certpair[0],
    )
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(*certpair)

            tls = pq3._TLSStream(conn, ctx, server_side=True)

            tls.handshake()
            tls = pq3._DebugStream(tls, conn._out)

            startup = pq3.recv1(tls, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(3, 0)

            finish_handshake(tls)