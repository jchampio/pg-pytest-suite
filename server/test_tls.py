import contextlib
import os
import ssl

import psycopg2
import pytest
from psycopg2 import sql

import pq3
from client.test_tls import certpair


@pytest.fixture()
def ssl_ctx(postgres_instance, certpair):
    """
    Sets up the server with our certificate/key pair.
    TODO: consolidate with setup_validator over in test_oauth.py
    """
    host, port = postgres_instance
    conn = psycopg2.connect(host=host, port=port)
    conn.autocommit = True

    settings = {
        "ssl": "on",
        "ssl_cert_file": os.path.abspath(certpair[0]),
        "ssl_key_file": os.path.abspath(certpair[1]),
    }

    with contextlib.closing(conn):
        c = conn.cursor()
        prev = dict()

        for guc, val in settings.items():
            # Save the previous value.
            c.execute(sql.SQL("SHOW {};").format(sql.Identifier(guc)))
            prev[guc] = c.fetchone()[0]

            c.execute(
                sql.SQL("ALTER SYSTEM SET {} TO %s;").format(sql.Identifier(guc)),
                (val,),
            )

        c.execute("SELECT pg_reload_conf();")

        class _SSLContext(object):
            ca = certpair[0]

        yield _SSLContext()

        # Restore the previous values.
        for guc, val in prev.items():
            c.execute(
                sql.SQL("ALTER SYSTEM SET {} TO %s;").format(sql.Identifier(guc)),
                (val,),
            )

        c.execute("SELECT pg_reload_conf();")


def test_tls(ssl_ctx, postgres_instance, connect):
    """Happy path for SSL."""
    conn = connect()

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ssl_ctx.ca)
    with pq3.tls_handshake(conn, ctx, server_hostname="example.org") as tls:
        pq3.handshake(tls, user=pq3.pguser(), database=pq3.pgdatabase())

        pq3.send(tls, pq3.types.Query, query=b"")
        resp = pq3.recv1(tls)
        assert resp.type == pq3.types.EmptyQueryResponse
