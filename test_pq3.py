#
# Copyright 2021 VMware, Inc.
# Portions Copyright (c) 2024, PostgreSQL Global Development Group
# SPDX-License-Identifier: PostgreSQL
#

import contextlib
import getpass
import io
import struct
import sys

import pytest
from construct import Container, PaddingError, StreamError, TerminatedError

import pq3


@pytest.mark.parametrize(
    "raw,expected,extra",
    [
        pytest.param(
            b"\x00\x00\x00\x10\x00\x04\x00\x00abcdefgh",
            Container(len=16, proto=0x40000, payload=b"abcdefgh"),
            b"",
            id="8-byte payload",
        ),
        pytest.param(
            b"\x00\x00\x00\x08\x00\x04\x00\x00",
            Container(len=8, proto=0x40000, payload=b""),
            b"",
            id="no payload",
        ),
        pytest.param(
            b"\x00\x00\x00\x09\x00\x04\x00\x00abcde",
            Container(len=9, proto=0x40000, payload=b"a"),
            b"bcde",
            id="1-byte payload and extra padding",
        ),
        pytest.param(
            b"\x00\x00\x00\x0B\x00\x03\x00\x00hi\x00",
            Container(len=11, proto=pq3.protocol(3, 0), payload=[b"hi"]),
            b"",
            id="implied parameter list when using proto version 3.0",
        ),
    ],
)
def test_Startup_parse(raw, expected, extra):
    with io.BytesIO(raw) as stream:
        actual = pq3.Startup.parse_stream(stream)

        assert actual == expected
        assert stream.read() == extra


@pytest.mark.parametrize(
    "packet,expected_bytes",
    [
        pytest.param(
            dict(),
            b"\x00\x00\x00\x08\x00\x00\x00\x00",
            id="nothing set",
        ),
        pytest.param(
            dict(len=10, proto=0x12345678),
            b"\x00\x00\x00\x0A\x12\x34\x56\x78\x00\x00",
            id="len and proto set explicitly",
        ),
        pytest.param(
            dict(proto=0x12345678),
            b"\x00\x00\x00\x08\x12\x34\x56\x78",
            id="implied len with no payload",
        ),
        pytest.param(
            dict(proto=0x12345678, payload=b"abcd"),
            b"\x00\x00\x00\x0C\x12\x34\x56\x78abcd",
            id="implied len with payload",
        ),
        pytest.param(
            dict(payload=[b""]),
            b"\x00\x00\x00\x09\x00\x03\x00\x00\x00",
            id="implied proto version 3 when sending parameters",
        ),
        pytest.param(
            dict(payload=[b"hi", b""]),
            b"\x00\x00\x00\x0C\x00\x03\x00\x00hi\x00\x00",
            id="implied proto version 3 and len when sending more than one parameter",
        ),
        pytest.param(
            dict(payload=dict(user="jsmith", database="postgres")),
            b"\x00\x00\x00\x27\x00\x03\x00\x00user\x00jsmith\x00database\x00postgres\x00\x00",
            id="auto-serialization of dict parameters",
        ),
    ],
)
def test_Startup_build(packet, expected_bytes):
    actual = pq3.Startup.build(packet)
    assert actual == expected_bytes


@pytest.mark.parametrize(
    "raw,expected,extra",
    [
        pytest.param(
            b"*\x00\x00\x00\x08abcd",
            dict(type=b"*", len=8, payload=b"abcd"),
            b"",
            id="4-byte payload",
        ),
        pytest.param(
            b"*\x00\x00\x00\x04",
            dict(type=b"*", len=4, payload=b""),
            b"",
            id="no payload",
        ),
        pytest.param(
            b"*\x00\x00\x00\x05xabcd",
            dict(type=b"*", len=5, payload=b"x"),
            b"abcd",
            id="1-byte payload with extra padding",
        ),
        pytest.param(
            b"R\x00\x00\x00\x08\x00\x00\x00\x00",
            dict(
                type=pq3.types.AuthnRequest,
                len=8,
                payload=dict(type=pq3.authn.OK, body=None),
            ),
            b"",
            id="AuthenticationOk",
        ),
        pytest.param(
            b"R\x00\x00\x00\x12\x00\x00\x00\x0AEXTERNAL\x00\x00",
            dict(
                type=pq3.types.AuthnRequest,
                len=18,
                payload=dict(type=pq3.authn.SASL, body=[b"EXTERNAL", b""]),
            ),
            b"",
            id="AuthenticationSASL",
        ),
        pytest.param(
            b"R\x00\x00\x00\x0D\x00\x00\x00\x0B12345",
            dict(
                type=pq3.types.AuthnRequest,
                len=13,
                payload=dict(type=pq3.authn.SASLContinue, body=b"12345"),
            ),
            b"",
            id="AuthenticationSASLContinue",
        ),
        pytest.param(
            b"R\x00\x00\x00\x0D\x00\x00\x00\x0C12345",
            dict(
                type=pq3.types.AuthnRequest,
                len=13,
                payload=dict(type=pq3.authn.SASLFinal, body=b"12345"),
            ),
            b"",
            id="AuthenticationSASLFinal",
        ),
        pytest.param(
            b"p\x00\x00\x00\x0Bhunter2",
            dict(
                type=pq3.types.PasswordMessage,
                len=11,
                payload=b"hunter2",
            ),
            b"",
            id="PasswordMessage",
        ),
        pytest.param(
            b"K\x00\x00\x00\x0C\x00\x00\x00\x00\x12\x34\x56\x78",
            dict(
                type=pq3.types.BackendKeyData,
                len=12,
                payload=dict(pid=0, key=0x12345678),
            ),
            b"",
            id="BackendKeyData",
        ),
        pytest.param(
            b"C\x00\x00\x00\x08SET\x00",
            dict(
                type=pq3.types.CommandComplete,
                len=8,
                payload=dict(tag=b"SET"),
            ),
            b"",
            id="CommandComplete",
        ),
        pytest.param(
            b"E\x00\x00\x00\x11Mbad!\x00Mdog!\x00\x00",
            dict(type=b"E", len=17, payload=dict(fields=[b"Mbad!", b"Mdog!", b""])),
            b"",
            id="ErrorResponse",
        ),
        pytest.param(
            b"S\x00\x00\x00\x08a\x00b\x00",
            dict(
                type=pq3.types.ParameterStatus,
                len=8,
                payload=dict(name=b"a", value=b"b"),
            ),
            b"",
            id="ParameterStatus",
        ),
        pytest.param(
            b"Z\x00\x00\x00\x05x",
            dict(type=b"Z", len=5, payload=dict(status=b"x")),
            b"",
            id="ReadyForQuery",
        ),
        pytest.param(
            b"Q\x00\x00\x00\x06!\x00",
            dict(type=pq3.types.Query, len=6, payload=dict(query=b"!")),
            b"",
            id="Query",
        ),
        pytest.param(
            b"P\x00\x00\x00\x18ddd\x00SELECT 1;\x00\x00\x01\x00\x00\x00\x02",
            dict(
                type=pq3.types.Parse,
                len=24,
                payload=dict(dest=b"ddd", query=b"SELECT 1;", typids=[2]),
            ),
            b"",
            id="Parse",
        ),
        pytest.param(
            b"P\x00\x00\x00\x18ddd\x00SELECT 1;\x00\x00\x01\x00\x00\x00\x02\xAA\xBB\xCC\xDD",
            dict(
                type=pq3.types.Parse,
                len=24,
                payload=dict(dest=b"ddd", query=b"SELECT 1;", typids=[2]),
            ),
            b"\xAA\xBB\xCC\xDD",
            id="Parse with extra data",
        ),
        pytest.param(
            b"T\x00\x00\x00\x2E\x00\x02"
            + b"a\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\x03\x00\x04\x00\x00\x00\x05\x00\x00"
            + b"b\x00\x00\x00\x00\x05\x00\x04\x00\x00\x00\x03\x00\x02\x00\x00\x00\x01\x00\x01",
            dict(
                type=pq3.types.RowDescription,
                len=46,
                payload=dict(
                    columns=[
                        dict(
                            name=b"a",
                            relid=1,
                            attnum=2,
                            typid=3,
                            typlen=4,
                            atttypmod=5,
                            fmt=pq3.formats.Text,
                        ),
                        dict(
                            name=b"b",
                            relid=5,
                            attnum=4,
                            typid=3,
                            typlen=2,
                            atttypmod=1,
                            fmt=pq3.formats.Binary,
                        ),
                    ]
                ),
            ),
            b"",
            id="RowDescription",
        ),
        pytest.param(
            b"T\x00\x00\x00\x06\x00\x00extra",
            dict(type=pq3.types.RowDescription, len=6, payload=dict(columns=[])),
            b"extra",
            id="RowDescription with extra data",
        ),
        pytest.param(
            b"D\x00\x00\x00\x0B\x00\x01\x00\x00\x00\x01!",
            dict(type=pq3.types.DataRow, len=11, payload=dict(columns=[b"!"])),
            b"",
            id="DataRow",
        ),
        pytest.param(
            b"D\x00\x00\x00\x06\x00\x00extra",
            dict(type=pq3.types.DataRow, len=6, payload=dict(columns=[])),
            b"extra",
            id="DataRow with extra data",
        ),
        pytest.param(
            b"I\x00\x00\x00\x04",
            dict(type=pq3.types.EmptyQueryResponse, len=4, payload=None),
            b"",
            id="EmptyQueryResponse",
        ),
        pytest.param(
            b"I\x00\x00\x00\x04\xFF",
            dict(type=b"I", len=4, payload=None),
            b"\xFF",
            id="EmptyQueryResponse with extra bytes",
        ),
        pytest.param(
            b"X\x00\x00\x00\x04",
            dict(type=pq3.types.Terminate, len=4, payload=None),
            b"",
            id="Terminate",
        ),
        pytest.param(
            b"v\x00\x00\x00\x1A\x00\x00\x00\x03\x00\x00\x00\x02_pq_.1\x00_pq_.2\x00",
            dict(
                type=pq3.types.NegotiateProtocolVersion,
                len=26,
                payload=dict(version=3, unsupported=[b"_pq_.1", b"_pq_.2"]),
            ),
            b"",
            id="NegotiateProtocolVersion",
        ),
        pytest.param(
            b"v\x00\x00\x00\x0C\x00\x00\x00\x03\x00\x00\x00\x00",
            dict(
                type=pq3.types.NegotiateProtocolVersion,
                len=12,
                payload=dict(version=3, unsupported=[]),
            ),
            b"",
            id="NegotiateProtocolVersion with no unsupported",
        ),
        pytest.param(
            b"v\x00\x00\x00\x1A\x00\x00\x00\x03\x00\x00\x00\x02_pq_.1\x00_pq_.2\x00\x00",
            dict(
                type=pq3.types.NegotiateProtocolVersion,
                len=26,
                payload=dict(version=3, unsupported=[b"_pq_.1", b"_pq_.2"]),
            ),
            b"\x00",
            id="NegotiateProtocolVersion with extra bytes",
        ),
    ],
)
def test_Pq3_parse(raw, expected, extra):
    with io.BytesIO(raw) as stream:
        actual = pq3.Pq3.parse_stream(stream)

        assert actual == expected
        assert stream.read() == extra


@pytest.mark.parametrize(
    "fields,expected",
    [
        pytest.param(
            dict(type=b"*", len=5),
            b"*\x00\x00\x00\x05\x00",
            id="type and len set explicitly",
        ),
        pytest.param(
            dict(type=b"*"),
            b"*\x00\x00\x00\x04",
            id="implied len with no payload",
        ),
        pytest.param(
            dict(type=b"*", payload=b"1234"),
            b"*\x00\x00\x00\x081234",
            id="implied len with payload",
        ),
        pytest.param(
            dict(type=pq3.types.AuthnRequest, payload=dict(type=pq3.authn.OK)),
            b"R\x00\x00\x00\x08\x00\x00\x00\x00",
            id="implied len/type for AuthenticationOK",
        ),
        pytest.param(
            dict(
                type=pq3.types.AuthnRequest,
                payload=dict(
                    type=pq3.authn.SASL,
                    body=[b"SCRAM-SHA-256-PLUS", b"SCRAM-SHA-256", b""],
                ),
            ),
            b"R\x00\x00\x00\x2A\x00\x00\x00\x0ASCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00\x00",
            id="implied len/type for AuthenticationSASL",
        ),
        pytest.param(
            dict(
                type=pq3.types.AuthnRequest,
                payload=dict(type=pq3.authn.SASLContinue, body=b"12345"),
            ),
            b"R\x00\x00\x00\x0D\x00\x00\x00\x0B12345",
            id="implied len/type for AuthenticationSASLContinue",
        ),
        pytest.param(
            dict(
                type=pq3.types.AuthnRequest,
                payload=dict(type=pq3.authn.SASLFinal, body=b"12345"),
            ),
            b"R\x00\x00\x00\x0D\x00\x00\x00\x0C12345",
            id="implied len/type for AuthenticationSASLFinal",
        ),
        pytest.param(
            dict(
                type=pq3.types.PasswordMessage,
                payload=b"hunter2",
            ),
            b"p\x00\x00\x00\x0Bhunter2",
            id="implied len/type for PasswordMessage",
        ),
        pytest.param(
            dict(type=pq3.types.BackendKeyData, payload=dict(pid=1, key=7)),
            b"K\x00\x00\x00\x0C\x00\x00\x00\x01\x00\x00\x00\x07",
            id="implied len/type for BackendKeyData",
        ),
        pytest.param(
            dict(type=pq3.types.CommandComplete, payload=dict(tag=b"SET")),
            b"C\x00\x00\x00\x08SET\x00",
            id="implied len/type for CommandComplete",
        ),
        pytest.param(
            dict(type=pq3.types.ErrorResponse, payload=dict(fields=[b"error", b""])),
            b"E\x00\x00\x00\x0Berror\x00\x00",
            id="implied len/type for ErrorResponse",
        ),
        pytest.param(
            dict(type=pq3.types.ParameterStatus, payload=dict(name=b"a", value=b"b")),
            b"S\x00\x00\x00\x08a\x00b\x00",
            id="implied len/type for ParameterStatus",
        ),
        pytest.param(
            dict(type=pq3.types.ReadyForQuery, payload=dict(status=b"I")),
            b"Z\x00\x00\x00\x05I",
            id="implied len/type for ReadyForQuery",
        ),
        pytest.param(
            dict(type=pq3.types.Query, payload=dict(query=b"SELECT 1;")),
            b"Q\x00\x00\x00\x0eSELECT 1;\x00",
            id="implied len/type for Query",
        ),
        pytest.param(
            dict(type=pq3.types.Parse, payload=dict(query=b"SELECT 1;")),
            b"P\x00\x00\x00\x11\x00SELECT 1;\x00\x00\x00",
            id="implied len/type/dest/numtypes for Parse",
        ),
        pytest.param(
            dict(type=pq3.types.Bind, payload=dict()),
            b"B\x00\x00\x00\x0C\x00\x00\x00\x00\x00\x00\x00\x00",
            id="implied parameters for empty Bind",
        ),
        pytest.param(
            dict(type=pq3.types.Describe, payload=dict(variant=pq3.describe.Portal)),
            b"D\x00\x00\x00\x06P\x00",
            id="implied len/type/name for Describe",
        ),
        pytest.param(
            dict(type=pq3.types.Execute, payload=dict()),
            b"E\x00\x00\x00\x09\x00\x00\x00\x00\x00",
            id="implied parameters for empty Execute",
        ),
        pytest.param(
            dict(type=pq3.types.RowDescription, payload=dict(columns=[])),
            b"T\x00\x00\x00\x06\x00\x00",
            id="implied len/type for RowDescription",
        ),
        pytest.param(
            dict(type=pq3.types.DataRow, payload=dict(columns=[b"abcd"])),
            b"D\x00\x00\x00\x0E\x00\x01\x00\x00\x00\x04abcd",
            id="implied len/type for DataRow",
        ),
        pytest.param(
            dict(type=pq3.types.EmptyQueryResponse),
            b"I\x00\x00\x00\x04",
            id="implied len for EmptyQueryResponse",
        ),
        pytest.param(
            dict(type=pq3.types.Terminate),
            b"X\x00\x00\x00\x04",
            id="implied len for Terminate",
        ),
        pytest.param(
            dict(
                type=pq3.types.NegotiateProtocolVersion,
                payload=dict(version=3, unsupported=[b"_pq_.1", b"_pq_.2"]),
            ),
            b"v\x00\x00\x00\x1A\x00\x00\x00\x03\x00\x00\x00\x02_pq_.1\x00_pq_.2\x00",
            id="implied len for NegotiateProtocolVersion",
        ),
        pytest.param(
            dict(type=pq3.types.NegotiateProtocolVersion, payload=dict(version=3)),
            b"v\x00\x00\x00\x0C\x00\x00\x00\x03\x00\x00\x00\x00",
            id="default unsupported for NegotiateProtocolVersion",
        ),
    ],
)
def test_Pq3_build(fields, expected):
    actual = pq3.Pq3.build(fields)
    assert actual == expected


@pytest.mark.parametrize(
    "raw,expected,extra",
    [
        pytest.param(
            b"\x00\x00",
            dict(columns=[]),
            b"",
            id="no columns",
        ),
        pytest.param(
            b"\x00\x01\x00\x00\x00\x04abcd",
            dict(columns=[b"abcd"]),
            b"",
            id="one column",
        ),
        pytest.param(
            b"\x00\x02\x00\x00\x00\x04abcd\x00\x00\x00\x01x",
            dict(columns=[b"abcd", b"x"]),
            b"",
            id="multiple columns",
        ),
        pytest.param(
            b"\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01x",
            dict(columns=[b"", b"x"]),
            b"",
            id="empty column value",
        ),
        pytest.param(
            b"\x00\x02\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            dict(columns=[None, None]),
            b"",
            id="null columns",
        ),
    ],
)
def test_DataRow_parse(raw, expected, extra):
    pkt = b"D" + struct.pack("!i", len(raw) + 4) + raw
    with io.BytesIO(pkt) as stream:
        actual = pq3.Pq3.parse_stream(stream)

        assert actual.type == pq3.types.DataRow
        assert actual.payload == expected
        assert stream.read() == extra


@pytest.mark.parametrize(
    "fields,expected",
    [
        pytest.param(
            dict(),
            b"\x00\x00",
            id="no columns",
        ),
        pytest.param(
            dict(columns=[None, None]),
            b"\x00\x02\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            id="null columns",
        ),
    ],
)
def test_DataRow_build(fields, expected):
    actual = pq3.Pq3.build(dict(type=pq3.types.DataRow, payload=fields))

    expected = b"D" + struct.pack("!i", len(expected) + 4) + expected
    assert actual == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        pytest.param(
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            dict(portal=b"", stmt=b"", fmts=[], params=[], resfmts=[]),
            id="all empty",
        ),
        pytest.param(
            b"p\x00s\x00\x00\x02\x00\x00\x00\x01\x00\x02\xFF\xFF\xFF\xFF\x00\x00\x00\x03123\x00\x01\x00\x01",
            dict(
                portal=b"p",
                stmt=b"s",
                fmts=[pq3.formats.Text, pq3.formats.Binary],
                params=[None, b"123"],
                resfmts=[pq3.formats.Binary],
            ),
            id="all full",
        ),
    ],
)
def test_Bind_parse(raw, expected):
    pkt = b"B" + struct.pack("!i", len(raw) + 4) + raw
    with io.BytesIO(pkt) as stream:
        actual = pq3.Pq3.parse_stream(stream)

        assert actual.type == pq3.types.Bind
        assert actual.payload == expected
        assert not stream.read()


@pytest.mark.parametrize(
    "fields,expected",
    [
        pytest.param(
            dict(),
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            id="all empty",
        ),
        pytest.param(
            dict(portal=b"p"),
            b"p\x00\x00\x00\x00\x00\x00\x00\x00",
            id="only portal",
        ),
        pytest.param(
            dict(stmt=b"s"),
            b"\x00s\x00\x00\x00\x00\x00\x00\x00",
            id="only statement",
        ),
        pytest.param(
            dict(fmts=[pq3.formats.Binary]),
            b"\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00",
            id="only parameter formats",
        ),
        pytest.param(
            dict(params=[None, None]),
            b"\x00\x00\x00\x00\x00\x02\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00",
            id="only NULL parameter values",
        ),
        pytest.param(
            dict(params=[b"123", b"abc"]),
            b"\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03123\x00\x00\x00\x03abc\x00\x00",
            id="other parameter values",
        ),
        pytest.param(
            dict(resfmts=[pq3.formats.Text, pq3.formats.Binary]),
            b"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01",
            id="only result formats",
        ),
    ],
)
def test_Bind_build(fields, expected):
    actual = pq3.Pq3.build(dict(type=pq3.types.Bind, payload=fields))

    expected = b"B" + struct.pack("!i", len(expected) + 4) + expected
    assert actual == expected


@pytest.mark.parametrize(
    "raw,expected,exception",
    [
        pytest.param(
            b"EXTERNAL\x00\xFF\xFF\xFF\xFF",
            dict(name=b"EXTERNAL", len=-1, data=None),
            None,
            id="no initial response",
        ),
        pytest.param(
            b"EXTERNAL\x00\x00\x00\x00\x02me",
            dict(name=b"EXTERNAL", len=2, data=b"me"),
            None,
            id="initial response",
        ),
        pytest.param(
            b"EXTERNAL\x00\x00\x00\x00\x02meextra",
            None,
            TerminatedError,
            id="extra data",
        ),
        pytest.param(
            b"EXTERNAL\x00\x00\x00\x00\xFFme",
            None,
            StreamError,
            id="underflow",
        ),
    ],
)
def test_SASLInitialResponse_parse(raw, expected, exception):
    ctx = contextlib.nullcontext()
    if exception:
        ctx = pytest.raises(exception)

    with ctx:
        actual = pq3.SASLInitialResponse.parse(raw)
        assert actual == expected


@pytest.mark.parametrize(
    "fields,expected",
    [
        pytest.param(
            dict(name=b"EXTERNAL"),
            b"EXTERNAL\x00\xFF\xFF\xFF\xFF",
            id="no initial response",
        ),
        pytest.param(
            dict(name=b"EXTERNAL", data=None),
            b"EXTERNAL\x00\xFF\xFF\xFF\xFF",
            id="no initial response (explicit None)",
        ),
        pytest.param(
            dict(name=b"EXTERNAL", data=b""),
            b"EXTERNAL\x00\x00\x00\x00\x00",
            id="empty response",
        ),
        pytest.param(
            dict(name=b"EXTERNAL", data=b"me@example.com"),
            b"EXTERNAL\x00\x00\x00\x00\x0Eme@example.com",
            id="initial response",
        ),
        pytest.param(
            dict(name=b"EXTERNAL", len=2, data=b"me@example.com"),
            b"EXTERNAL\x00\x00\x00\x00\x02me@example.com",
            id="data overflow",
        ),
        pytest.param(
            dict(name=b"EXTERNAL", len=14, data=b"me"),
            b"EXTERNAL\x00\x00\x00\x00\x0Eme",
            id="data underflow",
        ),
    ],
)
def test_SASLInitialResponse_build(fields, expected):
    actual = pq3.SASLInitialResponse.build(fields)
    assert actual == expected


@pytest.mark.parametrize(
    "client, server",
    [
        pytest.param(
            dict(
                msg_type=pq3.types.Sync,
                built=b"S\x00\x00\x00\x04",
                payload=None,
            ),
            dict(
                msg_type=pq3.types.ParameterStatus,
                built=b"S\x00\x00\x00\x08a\x00b\x00",
                payload=dict(name=b"a", value=b"b"),
            ),
            id="'S' Sync/ParameterStatus",
        ),
        pytest.param(
            dict(
                msg_type=pq3.types.Describe,
                built=b"D\x00\x00\x00\x06S\x00",
                payload=dict(variant=pq3.describe.Statement, name=b""),
            ),
            dict(
                msg_type=pq3.types.DataRow,
                built=b"D\x00\x00\x00\x06\x00\x00",
                payload=dict(columns=[]),
            ),
            id="'D' Describe/DataRow",
        ),
        pytest.param(
            dict(
                msg_type=pq3.types.Execute,
                built=b"E\x00\x00\x00\x0Ap\x00\x00\x00 \x00",
                payload=dict(portal=b"p", maxrows=0x2000),
            ),
            dict(
                msg_type=pq3.types.ErrorResponse,
                built=b"E\x00\x00\x00\x0Ap\x00\x00\x00 \x00",
                payload=dict(fields=[b"p", b"", b"", b" "]),
            ),
            id="'E' Execute/ErrorResponse",
        ),
    ],
)
def test_frontend_backend_type_pairs(client, server):
    """
    For messages that share a type byte (and are differentiated only by whether
    they're sent from the client or the server), make sure they survive a
    parse/build round trip.
    """
    assert (
        int(client["msg_type"])
        == int(server["msg_type"])
        == client["built"][0]
        == server["built"][0]
    ), "message pair must use the same message type byte"

    for testcase, is_client in zip((client, server), (True, False)):
        actual = pq3.Pq3.parse(testcase["built"], is_client=is_client)
        assert actual.type == testcase["msg_type"]
        assert actual.payload == testcase["payload"]

        actual = pq3.Pq3.build(actual, is_client=is_client)
        assert actual == testcase["built"]


@pytest.mark.parametrize(
    "version,expected_bytes",
    [
        pytest.param((3, 0), b"\x00\x03\x00\x00", id="version 3"),
        pytest.param((1234, 5679), b"\x04\xd2\x16\x2f", id="SSLRequest"),
    ],
)
def test_protocol(version, expected_bytes):
    # Make sure the integer returned by protocol is correctly serialized on the
    # wire.
    assert struct.pack("!i", pq3.protocol(*version)) == expected_bytes


@pytest.mark.parametrize(
    "envvar,func,expected",
    [
        ("PGHOST", pq3.pghost, "localhost"),
        ("PGPORT", pq3.pgport, 5432),
        ("PGUSER", pq3.pguser, getpass.getuser()),
        ("PGDATABASE", pq3.pgdatabase, "postgres"),
    ],
)
def test_env_defaults(monkeypatch, envvar, func, expected):
    monkeypatch.delenv(envvar, raising=False)

    actual = func()
    assert actual == expected


@pytest.mark.parametrize(
    "envvars,func,expected",
    [
        (dict(PGHOST="otherhost"), pq3.pghost, "otherhost"),
        (dict(PGPORT="6789"), pq3.pgport, 6789),
        (dict(PGUSER="postgres"), pq3.pguser, "postgres"),
        (dict(PGDATABASE="template1"), pq3.pgdatabase, "template1"),
    ],
)
def test_env(monkeypatch, envvars, func, expected):
    for k, v in envvars.items():
        monkeypatch.setenv(k, v)

    actual = func()
    assert actual == expected
