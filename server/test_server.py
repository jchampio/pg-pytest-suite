#
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: PostgreSQL
#

import pq3


def test_handshake(connect):
    """Basic sanity check."""
    conn = connect()

    pq3.handshake(conn, user=pq3.pguser(), database=pq3.pgdatabase())

    pq3.send(conn, pq3.types.Query, query=b"")

    resp = pq3.recv1(conn)
    assert resp.type == pq3.types.EmptyQueryResponse

    resp = pq3.recv1(conn)
    assert resp.type == pq3.types.ReadyForQuery


def test_row_description(connect):
    conn = connect()

    pq3.handshake(conn, user=pq3.pguser(), database=pq3.pgdatabase())

    q = b"""SELECT oid, typname, typlen FROM pg_type
             WHERE typname IN ('oid', 'name', 'int2')"""
    pq3.send(conn, pq3.types.Query, query=q)

    desc = None
    types = {}

    while True:
        resp = pq3.recv1(conn)
        if resp.type == pq3.types.ReadyForQuery:
            break

        if resp.type == pq3.types.RowDescription:
            desc = resp.payload.columns
        elif resp.type == pq3.types.DataRow:
            oid, typname, typlen = resp.payload.columns
            types[int(oid)] = {
                "name": typname,
                "len": int(typlen),
            }

    assert desc is not None, "server did not send a RowDescription"
    assert len(desc) == 3

    # We should have received descriptors for oid, name, and int2, in that
    # order. Cross-reference against the pg_type entries.
    colnames = (b"oid", b"typname", b"typlen")
    typenames = (b"oid", b"name", b"int2")
    for d, expected_col, expected_type in zip(desc, colnames, typenames):
        assert d.typid in types

        t = types[d.typid]
        assert t["name"] == expected_type

        assert d.name == expected_col
        assert d.typlen == t["len"]
        assert d.fmt == pq3.formats.Text
