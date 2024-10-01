import contextlib
import os
import ssl

import psycopg2
import pytest
from psycopg2 import sql

import pq3
from client.test_tls import ALPN_PROTO, certpair


@pytest.fixture()
def ssl_ctx(postgres_instance, certpair):
    """
    Sets up the server with our certificate/key pair.
    TODO: consolidate with setup_validator over in test_oauth.py
    """
    host, port = postgres_instance

    # An ExitStack helps keep track of cleanup.
    with contextlib.ExitStack() as stack:
        conn = psycopg2.connect(host=host, port=port)

        # Close the connection after everything else is done.
        stack.enter_context(contextlib.closing(conn))

        conn.autocommit = True
        c = conn.cursor()

        # Right before we close the connection, tell the server to reload its
        # configuration. This picks up the GUC changes that happen when the
        # stack is unwound.
        stack.callback(c.execute, "SELECT pg_reload_conf();")

        class _SSLContext(object):
            ca = certpair[0]

            def set_gucs(self, **settings):
                """
                Sets arbitrary GUCs and reloads the server. These changes will
                be undone at the end of the test.
                """
                if not settings:
                    return

                for guc, val in settings.items():
                    # Save the previous value.
                    c.execute(sql.SQL("SHOW {};").format(sql.Identifier(guc)))
                    prev = c.fetchone()[0]

                    c.execute(
                        sql.SQL("ALTER SYSTEM SET {} TO %s;").format(
                            sql.Identifier(guc)
                        ),
                        (val,),
                    )

                    # When the stack unwinds, reset the GUC. (The reload will be
                    # taken care of by the pushed call to pg_reload_conf(),
                    # above.)
                    stack.callback(
                        c.execute,
                        sql.SQL("ALTER SYSTEM SET {} TO %s;").format(
                            sql.Identifier(guc)
                        ),
                        (prev,),
                    )

                # Reload to pick up all the settings we've modified.
                c.execute("SELECT pg_reload_conf();")

        ctx = _SSLContext()
        ctx.set_gucs(
            ssl="on",
            ssl_cert_file=os.path.abspath(certpair[0]),
            ssl_key_file=os.path.abspath(certpair[1]),
            ssl_ca_file=os.path.abspath(certpair[0]),
        )

        yield ctx


def test_tls(ssl_ctx, connect):
    """Happy path for SSL."""
    conn = connect()

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ssl_ctx.ca)
    with pq3.tls_handshake(conn, ctx, server_hostname="example.org") as tls:
        pq3.handshake(tls, user=pq3.pguser(), database=pq3.pgdatabase())

        pq3.send(tls, pq3.types.Query, query=b"")
        resp = pq3.recv1(tls)
        assert resp.type == pq3.types.EmptyQueryResponse


@pytest.mark.parametrize(
    "max_version",
    (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3),
)
def test_tls_no_resumption(ssl_ctx, connect, max_version):
    """Make sure the server isn't sending session tickets."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ssl_ctx.ca)
    ctx.maximum_version = max_version

    session = None
    given_ticket = False

    for _ in (1, 2):
        conn = connect()

        with pq3.tls_handshake(
            conn, ctx, server_hostname="example.org", session=session
        ) as tls:
            pq3.handshake(tls, user=pq3.pguser(), database=pq3.pgdatabase())

            session = tls.ssl_socket().session
            given_ticket = given_ticket or session.has_ticket

            pq3.send(tls, pq3.types.Query, query=b"")
            resp = pq3.recv1(tls)
            assert resp.type == pq3.types.EmptyQueryResponse

        conn.close()

    assert not given_ticket


@pytest.fixture(scope="session")
def require_direct_ssl_support(postgres_instance):
    """
    Automatically skips a test if the server doesn't support direct SSL
    connections.
    """
    host, port = postgres_instance
    conn = psycopg2.connect(host=host, port=port)

    with contextlib.closing(conn):
        major = conn.server_version // 10000
        if major < 17:
            pytest.skip("server does not support direct SSL connections")


@pytest.mark.parametrize(
    "protos",
    (
        pytest.param([ALPN_PROTO], id="standard ALPN advertisement"),
        pytest.param(["http/1.1", ALPN_PROTO], id="additional protocols"),
    ),
)
def test_direct_tls(ssl_ctx, connect, require_direct_ssl_support, protos):
    """
    Tests direct TLS connections (i.e. sslnegotiation=requiredirect in libpq).
    """
    conn = connect()
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ssl_ctx.ca)
    ctx.set_alpn_protocols([ALPN_PROTO])

    # TODO: export a helper for this from pq3
    tls = pq3._TLSStream(conn, ctx, server_hostname="example.org")
    tls.handshake()
    assert tls._ssl.selected_alpn_protocol() == ALPN_PROTO

    tls = pq3._DebugStream(tls, conn._out)
    pq3.handshake(tls, user=pq3.pguser(), database=pq3.pgdatabase())

    pq3.send(tls, pq3.types.Query, query=b"")
    resp = pq3.recv1(tls)
    assert resp.type == pq3.types.EmptyQueryResponse


@pytest.mark.parametrize(
    "protos",
    (
        pytest.param([], id="no application protocols"),
        pytest.param(["http/1.1"], id="incorrect application protocol"),
    ),
)
def test_direct_ssl_without_alpn(ssl_ctx, connect, require_direct_ssl_support, protos):
    """
    Make sure the server rejects direct connections without the expected ALPN.
    """
    conn = connect()
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ssl_ctx.ca)

    # Do not set up the expected ALPN.
    ctx.set_alpn_protocols(protos)

    tls = pq3._TLSStream(conn, ctx, server_hostname="example.org")

    with pytest.raises(ssl.SSLError, match="no application protocol"):
        tls.handshake()
