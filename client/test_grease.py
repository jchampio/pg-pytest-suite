#
# Copyright (c) 2024-2026, PostgreSQL Global Development Group
# Portions Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: PostgreSQL
#

import base64
import re
import sys

import psycopg2
import pytest
from cryptography.hazmat.primitives import hashes, hmac

import pq3

from .conftest import alt_patterns


def finish_handshake(conn, startup, *, version=None, unsupported=[]):
    """
    Sends the AuthenticationOK message and the standard opening salvo of server
    messages, then asserts that the client immediately sends a Terminate message
    to close the connection cleanly.
    """
    if version or unsupported:
        if version is None:
            version = startup.proto

        pq3.send(
            conn,
            pq3.types.NegotiateProtocolVersion,
            version=version,
            unsupported=unsupported,
        )

    pq3.send(conn, pq3.types.AuthnRequest, type=pq3.authn.OK)
    pq3.send(conn, pq3.types.ParameterStatus, name=b"client_encoding", value=b"UTF-8")
    pq3.send(conn, pq3.types.ParameterStatus, name=b"DateStyle", value=b"ISO, MDY")
    pq3.send(conn, pq3.types.BackendKeyData, pid=1234, key=0)
    pq3.send(conn, pq3.types.ReadyForQuery, status=b"I")


def test_handshake(conn):
    startup = pq3.recv1(conn, cls=pq3.Startup)
    assert startup.proto == pq3.protocol(3, 9999)
    assert b"_pq_.test_protocol_negotiation" in startup.payload

    i = startup.payload.index(b"_pq_.test_protocol_negotiation")
    assert startup.payload[i + 1] == b""

    finish_handshake(
        conn,
        startup,
        version=pq3.protocol(3, 0),
        unsupported=[b"_pq_.test_protocol_negotiation"],
    )

    pkt = pq3.recv1(conn)
    assert pkt.type == pq3.types.Terminate


def test_no_downgrade(accept):
    sock, client = accept()
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            startup = pq3.recv1(conn, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(3, 9999)
            assert b"_pq_.test_protocol_negotiation" in startup.payload

            i = startup.payload.index(b"_pq_.test_protocol_negotiation")
            assert startup.payload[i + 1] == b""

            finish_handshake(conn, startup)

    expected_error = "incorrectly accepted .* without negotiation"
    with pytest.raises(psycopg2.OperationalError, match=expected_error):
        client.check_completed()


@pytest.mark.parametrize(
    "errfields",
    [
        [b"Munsupported protocol version 3.9999"],
        [b"Munknown version code (206607)"],
        [b"Munknown version code: 0x3270f"],
        [b"C08P01", b"Mincorrect handshake"],
    ],
)
@pytest.mark.parametrize("after_auth", [True, False])
def test_direct_error(accept, errfields, after_auth):
    sock, client = accept(password="hi")
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            startup = pq3.recv1(conn, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(3, 9999)
            assert b"_pq_.test_protocol_negotiation" in startup.payload

            i = startup.payload.index(b"_pq_.test_protocol_negotiation")
            assert startup.payload[i + 1] == b""

            if after_auth:
                pq3.send(
                    conn,
                    pq3.types.AuthnRequest,
                    type=pq3.authn.CleartextPassword,
                )

            pq3.send(
                conn,
                pq3.types.ErrorResponse,
                fields=[
                    b"SFATAL",
                    *errfields,
                    b"",
                ],
            )

    errmsg = [f for f in errfields if f.startswith(b"M")][0]
    errmsg = errmsg[1:].decode()

    if after_auth:
        expected_error = re.escape(errmsg)
    else:
        expected_error = re.compile(
            re.escape(errmsg) + ".*This indicates a bug", re.DOTALL
        )

    with pytest.raises(psycopg2.OperationalError, match=expected_error) as e:
        client.check_completed()

    if after_auth:
        assert "This indicates a bug" not in str(e.value)


def test_accept_bad_extension(accept):
    sock, client = accept()
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            startup = pq3.recv1(conn, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(3, 9999)
            assert b"_pq_.test_protocol_negotiation" in startup.payload

            i = startup.payload.index(b"_pq_.test_protocol_negotiation")
            assert startup.payload[i + 1] == b""

            pq3.send(
                conn,
                pq3.types.NegotiateProtocolVersion,
                version=pq3.protocol(3, 0),
            )

    expected_error = 'server did not report the unsupported "_pq_.test_protocol_negotiation" parameter'
    with pytest.raises(psycopg2.OperationalError, match=expected_error):
        client.check_completed()


def test_accept_bad_version(accept):
    sock, client = accept()
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            startup = pq3.recv1(conn, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(3, 9999)
            assert b"_pq_.test_protocol_negotiation" in startup.payload

            i = startup.payload.index(b"_pq_.test_protocol_negotiation")
            assert startup.payload[i + 1] == b""

            pq3.send(
                conn,
                pq3.types.NegotiateProtocolVersion,
                version=startup.proto,
                unsupported=[b"_pq_.test_protocol_negotiation"],
            )

    expected_error = 'server requested "grease"'
    with pytest.raises(psycopg2.OperationalError, match=expected_error):
        client.check_completed()


def test_bad_extension_3_0(accept):
    sock, client = accept(max_protocol_version="3.0")
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            startup = pq3.recv1(conn, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(3, 0)
            assert b"_pq_.test_protocol_negotiation" not in startup.payload

            pq3.send(
                conn,
                pq3.types.NegotiateProtocolVersion,
                version=startup.proto,
                unsupported=[b"_pq_.test_protocol_negotiation"],
            )

    expected_error = "server reported an unsupported parameter that was not requested"
    with pytest.raises(psycopg2.OperationalError, match=expected_error):
        client.check_completed()


def test_bad_version_3_0(accept):
    sock, client = accept(max_protocol_version="3.0")
    with sock:
        with pq3.wrap(sock, debug_stream=sys.stdout) as conn:
            startup = pq3.recv1(conn, cls=pq3.Startup)
            assert startup.proto == pq3.protocol(3, 0)
            assert b"_pq_.test_protocol_negotiation" not in startup.payload

            pq3.send(
                conn,
                pq3.types.NegotiateProtocolVersion,
                version=pq3.protocol(3, 9999),
            )

    expected_error = 'server requested "grease" protocol version'
    with pytest.raises(psycopg2.OperationalError, match=expected_error):
        client.check_completed()
