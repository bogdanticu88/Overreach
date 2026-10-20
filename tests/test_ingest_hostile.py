"""Hostile and edge-case OpenAPI ingestion.

The ingester must never crash, never fetch an external ref, and must bound its
work on crafted specs. It must also find exit / free-text fields that hide
inside nested objects, arrays and allOf/oneOf/anyOf compositions.
"""
from __future__ import annotations

import json

import pytest

from overreach.ingest import IngestError, load_text


def _spec(paths: dict, components: dict | None = None) -> str:
    doc = {"openapi": "3.0.3", "info": {"title": "h", "version": "1"},
           "paths": paths}
    if components is not None:
        doc["components"] = components
    return json.dumps(doc)


# --- malformed / non-conforming inputs -------------------------------------

def test_not_json_or_yaml_raises_ingesterror():
    with pytest.raises(IngestError):
        load_text("{ this : is : not : valid : ::: ")


def test_top_level_not_mapping_raises():
    with pytest.raises(IngestError):
        load_text("[1, 2, 3]")


def test_paths_not_mapping_raises():
    # A non-empty, non-mapping "paths" is malformed and must be rejected.
    with pytest.raises(IngestError):
        load_text('{"openapi":"3.0.0","info":{"title":"x","version":"1"},"paths":"nope"}')


def test_oversized_spec_rejected():
    big = "x" * (32 * 1024 * 1024 + 1)
    with pytest.raises(IngestError):
        load_text(big)


def test_oversized_file_rejected_before_read(tmp_path):
    # load_path must bound the read, not read the whole file then check.
    from overreach.ingest import load_path
    f = tmp_path / "big.json"
    f.write_bytes(b"x" * (32 * 1024 * 1024 + 1))
    with pytest.raises(IngestError):
        load_path(f)


def test_non_regular_file_rejected(tmp_path):
    # A named pipe reports size 0 and could stream unbounded input; it must be
    # rejected up front (before any read) as a non-regular file.
    import os

    from overreach.ingest import load_path
    fifo = tmp_path / "pipe.json"
    try:
        os.mkfifo(fifo)
    except (AttributeError, OSError):
        pytest.skip("named pipes not supported on this platform")
    with pytest.raises(IngestError):
        load_path(fifo)


def test_garbage_operation_is_skipped_not_fatal():
    # method value is a string, not an operation object: skip it, don't crash.
    api = load_text(_spec({"/a": {"get": "nonsense", "post": {"operationId": "p"}}}))
    assert [op.op_id for op in api.operations] == ["p"]


# --- $ref handling: external, cyclic, repeated -----------------------------

def test_external_ref_is_never_fetched_and_warns():
    api = load_text(_spec({"/a": {"get": {
        "operationId": "a",
        "parameters": [{"$ref": "https://evil.example/boom.json#/x"}],
    }}}))
    assert len(api.operations) == 1
    assert any("external $ref" in w for w in api.warnings)


def test_self_referential_ref_cycle_terminates():
    # Node refers to itself; resolution must terminate via the depth bound.
    components = {"schemas": {"Node": {
        "type": "object",
        "properties": {"child": {"$ref": "#/components/schemas/Node"},
                       "url": {"type": "string", "format": "uri"}},
    }}}
    api = load_text(_spec({"/a": {"post": {
        "operationId": "a",
        "requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Node"}}}},
    }}}, components))
    assert len(api.operations) == 1
    # The exit field inside the recursive schema is still found.
    assert any(f.is_exit for f in api.operations[0].fields)


def test_unresolved_internal_ref_warns_and_survives():
    api = load_text(_spec({"/a": {"post": {
        "operationId": "a",
        "requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Missing"}}}},
    }}}, {"schemas": {}}))
    assert len(api.operations) == 1
    assert any("did not resolve" in w for w in api.warnings)


def test_repeated_reference_fanout_is_bounded():
    # A chain A->B->C... where each level references the previous many times.
    # Depth is bounded and the total-node budget caps amplification; must return.
    schemas: dict = {}
    prev = None
    for i in range(40):
        name = f"S{i}"
        props = {}
        if prev is not None:
            for j in range(8):  # wide fan-out of repeated refs
                props[f"r{j}"] = {"$ref": f"#/components/schemas/{prev}"}
        schemas[name] = {"type": "object", "properties": props}
        prev = name
    api = load_text(_spec({"/a": {"post": {
        "operationId": "a",
        "requestBody": {"content": {"application/json": {
            "schema": {"$ref": f"#/components/schemas/{prev}"}}}},
    }}}, {"schemas": schemas}))
    assert len(api.operations) == 1  # did not hang or explode


# --- nested / composed schema field discovery (the F-4 false-negatives) -----

def test_exit_field_nested_in_object_is_found():
    api = load_text(_spec({"/a": {"post": {
        "operationId": "a",
        "requestBody": {"content": {"application/json": {"schema": {
            "type": "object",
            "properties": {"config": {"type": "object", "properties": {
                "callback_url": {"type": "string"}}}},
        }}}},
    }}}))
    names = {f.name for f in api.operations[0].fields}
    assert "callback_url" in names
    assert any(f.name == "callback_url" and f.is_exit for f in api.operations[0].fields)


def test_exit_field_in_array_items_is_found():
    api = load_text(_spec({"/a": {"post": {
        "operationId": "a",
        "requestBody": {"content": {"application/json": {"schema": {
            "type": "object",
            "properties": {"targets": {"type": "array", "items": {
                "type": "object",
                "properties": {"webhook": {"type": "string", "format": "uri"}}}}},
        }}}},
    }}}))
    assert any(f.name == "webhook" and f.is_exit for f in api.operations[0].fields)


def test_allof_composition_merges_fields():
    api = load_text(_spec({"/a": {"post": {
        "operationId": "a",
        "requestBody": {"content": {"application/json": {"schema": {
            "allOf": [
                {"type": "object", "properties": {"body": {"type": "string"}}},
                {"type": "object", "properties": {"webhook_url": {"type": "string"}}},
            ]}}}},
    }}}))
    names = {f.name for f in api.operations[0].fields}
    assert {"body", "webhook_url"} <= names
    assert any(f.name == "webhook_url" and f.is_exit for f in api.operations[0].fields)


def test_oneof_branches_are_considered_and_warned():
    api = load_text(_spec({"/a": {"post": {
        "operationId": "a",
        "requestBody": {"content": {"application/json": {"schema": {
            "oneOf": [
                {"type": "object", "properties": {"email": {"type": "string"}}},
                {"type": "object", "properties": {"note": {"type": "string"}}},
            ]}}}},
    }}}))
    names = {f.name for f in api.operations[0].fields}
    assert {"email", "note"} <= names
    assert any("oneOf" in w or "anyOf" in w for w in api.warnings)


def test_deep_nesting_is_truncated_not_crashed():
    # Build a schema nested far past the walker's depth bound.
    schema: dict = {"type": "object", "properties": {"leaf": {"type": "string"}}}
    for _ in range(60):
        schema = {"type": "object", "properties": {"n": schema}}
    api = load_text(_spec({"/a": {"post": {
        "operationId": "a",
        "requestBody": {"content": {"application/json": {"schema": schema}}},
    }}}))
    assert len(api.operations) == 1
    assert any("truncated" in w for w in api.warnings)
