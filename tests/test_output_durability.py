import errno
import hashlib
import io
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

import wappalyzer.output as output_module
from wappalyzer.models import (
    CANONICAL_SCHEMA_VERSION,
    Protocol,
    ProtocolResult,
    ProtocolStatus,
    RunSpec,
    RunStatus,
    StageName,
    StageResult,
    StageStatus,
    TLSMetadata,
    TLSTrust,
)
from wappalyzer.output import (
    ArtifactExistsError,
    CanonicalProjector,
    ProjectionIntegrityError,
    build_manifest_bytes,
    publish_manifest,
)
from wappalyzer.runstore import (
    ArtifactSafetyError,
    CompletionPreconditionError,
    LedgerIntegrityError,
    OccurrenceOutboxEntry,
    ProjectionState,
    RunStateError,
    RunStore,
)


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _run_spec(input_bytes):
    return RunSpec(
        input_sha256=_sha256(input_bytes),
        parser_version="endpoint-v1",
        schema_version=CANONICAL_SCHEMA_VERSION,
        serializer_version="canonical-json-v1",
        engine_version="complete-v1",
        redirect_policy_version="redirect-v1",
        tls_policy_version="tls-v1",
        retry_policy_version="retry-v1",
        timeout_policy_version="timeout-v1",
        evidence_limits_sha256="b" * 64,
        fingerprint_sha256="c" * 64,
        extension_sha256="d" * 64,
        runtime_identity="chromium-test",
        scanner_build="build-test",
    )


def _success_empty(endpoint):
    requested_url = f"http://{endpoint.authority}/"
    return ProtocolResult(
        protocol=Protocol.HTTP,
        status=ProtocolStatus.SUCCESS_EMPTY,
        requested_url=requested_url,
        effective_url=requested_url,
        http_status=200,
        tls=TLSMetadata(present=False, trust=TLSTrust.NOT_APPLICABLE),
        stages=(
            StageResult(name=StageName.STATIC, status=StageStatus.SUCCESS_EMPTY),
            StageResult(name=StageName.BROWSER, status=StageStatus.SUCCESS_EMPTY),
        ),
    )


def _executing_store(tmp_path, raw, name="generation"):
    source = tmp_path / f"{name}.txt"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / name, f"run-{name}", _run_spec(raw))
    store.ingest(source)
    store.verify_source(source)
    store.transition(RunStatus.EXECUTING)
    return store


def _terminal_store(tmp_path, raw, name="generation"):
    store = _executing_store(tmp_path, raw, name)
    while True:
        claim = store.claim_endpoint()
        if claim is None:
            break
        store.commit_endpoint(claim, (_success_empty(claim.endpoint),))
    store.transition(RunStatus.PROJECTING)
    return store


def _publish_ready_store(tmp_path, raw=b"invalid\n", name="generation"):
    store = _terminal_store(tmp_path, raw, name)
    CanonicalProjector(store).project()
    store.mark_workers_closed()
    store.reconcile_counts()
    store.transition(RunStatus.PUBLISH_READY)
    return store


def _entry(**changes):
    payload = b'{"record":1}'
    prefix = _sha256(payload + b"\n")
    entry = OccurrenceOutboxEntry(
        occurrence_sequence=0,
        payload=payload,
        byte_length=len(payload),
        payload_sha256=_sha256(payload),
        output_offset=0,
        prefix_sha256=prefix,
    )
    return replace(entry, **changes)


def test_open_projection_repairs_mode_and_supports_platform_without_nofollow(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "canonical.ndjson"
    path.write_bytes(b"durable")
    path.chmod(0o644)
    monkeypatch.delattr(output_module.os, "O_NOFOLLOW")

    descriptor, created = output_module._open_projection(path)
    try:
        assert created is False
        assert os.read(descriptor, 7) == b"durable"
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600
    finally:
        os.close(descriptor)


def test_open_projection_recovers_create_race_without_replacing_winner(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "canonical.ndjson"
    original_open = os.open
    calls = 0

    def racing_open(candidate, flags, mode=0o777):
        nonlocal calls
        if str(candidate) != str(path):
            return original_open(candidate, flags, mode)
        calls += 1
        if calls == 1:
            raise FileNotFoundError(str(path))
        if calls == 2:
            descriptor = original_open(candidate, flags, mode)
            os.write(descriptor, b"winner")
            os.close(descriptor)
            raise FileExistsError(str(path))
        return original_open(candidate, flags, mode)

    monkeypatch.setattr(output_module.os, "open", racing_open)

    descriptor, created = output_module._open_projection(path)
    try:
        assert created is False
        assert os.read(descriptor, 6) == b"winner"
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("failure_point", ["initial", "create", "race_reopen"])
def test_open_projection_maps_symlink_errors_to_artifact_safety(
    tmp_path,
    monkeypatch,
    failure_point,
):
    path = tmp_path / "canonical.ndjson"
    calls = 0

    def unsafe_open(_candidate, _flags, _mode=0o777):
        nonlocal calls
        calls += 1
        if (
            failure_point == "initial"
            or (failure_point == "create" and calls == 2)
            or (failure_point == "race_reopen" and calls == 3)
        ):
            raise OSError(errno.ELOOP, "symlink")
        if calls == 1:
            raise FileNotFoundError(str(path))
        raise FileExistsError(str(path))

    monkeypatch.setattr(output_module.os, "open", unsafe_open)

    with pytest.raises(ArtifactSafetyError, match="unsafe projection path"):
        output_module._open_projection(path)


@pytest.mark.parametrize("failure_point", ["initial", "create", "race_reopen"])
def test_open_projection_preserves_non_alias_io_failures(
    tmp_path,
    monkeypatch,
    failure_point,
):
    path = tmp_path / "canonical.ndjson"
    calls = 0

    def failing_open(_candidate, _flags, _mode=0o777):
        nonlocal calls
        calls += 1
        if (
            failure_point == "initial"
            or (failure_point == "create" and calls == 2)
            or (failure_point == "race_reopen" and calls == 3)
        ):
            raise OSError(errno.EIO, "storage failure")
        if calls == 1:
            raise FileNotFoundError(str(path))
        raise FileExistsError(str(path))

    monkeypatch.setattr(output_module.os, "open", failing_open)

    with pytest.raises(OSError, match="storage failure") as failure:
        output_module._open_projection(path)

    assert failure.value.errno == errno.EIO


def test_open_projection_rejects_hardlink_and_closes_descriptor(tmp_path):
    original = tmp_path / "original"
    projection = tmp_path / "canonical.ndjson"
    original.write_bytes(b"shared")
    os.link(original, projection)

    with pytest.raises(ArtifactSafetyError, match="unalias"):
        output_module._open_projection(projection)

    projection.unlink()
    assert original.read_bytes() == b"shared"


def test_sync_directory_fsyncs_and_closes_without_o_directory(tmp_path, monkeypatch):
    observed = []
    original_fsync = os.fsync

    def tracked_fsync(descriptor):
        observed.append(os.fstat(descriptor).st_ino)
        original_fsync(descriptor)

    monkeypatch.delattr(output_module.os, "O_DIRECTORY")
    monkeypatch.setattr(output_module.os, "fsync", tracked_fsync)

    output_module._sync_directory(tmp_path)

    assert observed == [tmp_path.stat().st_ino]


def test_verified_prefix_rejects_file_shorter_than_durable_cursor():
    state = ProjectionState(1, 4, _sha256(b"data"))

    with pytest.raises(ProjectionIntegrityError, match="shorter"):
        output_module._verified_prefix(io.BytesIO(b"dat"), state)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (_entry(occurrence_sequence=2), "sequence"),
        (_entry(byte_length=999), "length"),
        (_entry(payload_sha256="0" * 64), "digest"),
        (_entry(output_offset=3), "metadata"),
        (_entry(prefix_sha256=None), "metadata"),
    ],
)
def test_validate_entry_rejects_corrupt_outbox_contract(entry, message):
    with pytest.raises(LedgerIntegrityError, match=message):
        output_module._validate_entry(entry, expected_sequence=0, expected_offset=0)


def test_projector_validates_constructor_lifecycle_and_limits(tmp_path):
    raw = b"invalid\n"
    source = tmp_path / "targets.txt"
    source.write_bytes(raw)
    store = RunStore.create(tmp_path / "generation", "run", _run_spec(raw))
    try:
        with pytest.raises(TypeError, match="RunStore"):
            CanonicalProjector(object())
        with pytest.raises(TypeError, match="callable"):
            CanonicalProjector(store, sync_file=object())

        projector = CanonicalProjector(store)
        with pytest.raises(RunStateError, match="execution"):
            projector.project()
        store.ingest(source)
        store.verify_source(source)
        store.transition(RunStatus.EXECUTING)
        with pytest.raises(ValueError, match="positive integer"):
            projector.project(max_records=0)
    finally:
        store.close()


def test_projector_rejects_projection_shorter_than_committed_cursor(tmp_path):
    store = _terminal_store(tmp_path, b"invalid\n")
    try:
        projector = CanonicalProjector(store)
        assert projector.project() == 1
        durable_state = store.projection_state
        projector.path.write_bytes(b"")

        with pytest.raises(ProjectionIntegrityError, match="shorter"):
            CanonicalProjector(store).project()

        assert store.projection_state == durable_state
    finally:
        store.close()


def test_projector_rejects_outbox_prefix_before_advancing_cursor(tmp_path):
    store = _terminal_store(tmp_path, b"invalid\n")
    try:
        store._connection.execute(
            "UPDATE occurrence_outbox SET prefix_sha256 = ? WHERE occurrence_sequence = 0",
            ("0" * 64,),
        )
        initial = store.projection_state

        with pytest.raises(LedgerIntegrityError, match="prefix digest"):
            CanonicalProjector(store).project()

        assert store.projection_state == initial
    finally:
        store.close()


def test_projector_fsyncs_truncated_torn_tail_even_without_new_records(
    tmp_path,
    monkeypatch,
):
    store = _terminal_store(tmp_path, b"invalid\n")
    try:
        projector = CanonicalProjector(store)
        assert projector.project() == 1
        expected = projector.path.read_bytes()
        with projector.path.open("ab") as stream:
            stream.write(b"torn")
        syncs = []

        def tracked_sync(descriptor):
            syncs.append(os.fstat(descriptor).st_size)
            os.fsync(descriptor)

        resumed = CanonicalProjector(store, sync_file=tracked_sync)
        assert resumed.project() == 0

        assert resumed.path.read_bytes() == expected
        assert syncs == [len(expected)]
    finally:
        store.close()


def test_manifest_builder_validates_store_lifecycle_and_projection(tmp_path):
    raw = b"invalid\n"
    store = _terminal_store(tmp_path, raw)
    try:
        with pytest.raises(TypeError, match="RunStore"):
            build_manifest_bytes(object())
        with pytest.raises(RunStateError, match="publish-ready"):
            build_manifest_bytes(store)

        CanonicalProjector(store).project()
        store.mark_workers_closed()
        store.reconcile_counts()
        store.transition(RunStatus.PUBLISH_READY)
        store._connection.execute(
            "UPDATE projection_state SET next_sequence = 0 WHERE singleton = 1"
        )
        with pytest.raises(CompletionPreconditionError, match="not complete"):
            build_manifest_bytes(store)
    finally:
        store.close()


def test_completed_manifest_rebuild_preserves_recorded_event_count(tmp_path):
    store = _publish_ready_store(tmp_path)
    try:
        ready_payload = build_manifest_bytes(store)
        path = publish_manifest(store)
        store.transition(RunStatus.COMPLETE)

        assert build_manifest_bytes(store) == ready_payload
        assert path.read_bytes() == ready_payload
    finally:
        store.close()


def test_manifest_match_handles_absence_content_and_unsafe_aliases(tmp_path):
    path = tmp_path / "manifest.json"
    expected = b'{"manifest":true}\n'
    assert output_module._manifest_matches(path, expected) is None

    path.write_bytes(expected)
    assert output_module._manifest_matches(path, expected) is True
    assert output_module._manifest_matches(path, b"different") is False
    path.unlink()

    victim = tmp_path / "victim"
    victim.write_bytes(expected)
    os.link(victim, path)
    with pytest.raises(ArtifactExistsError, match="unsafe artifact"):
        output_module._manifest_matches(path, expected)
    path.unlink()
    assert victim.read_bytes() == expected


def test_manifest_match_reads_without_nofollow_when_platform_lacks_flag(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "manifest.json"
    payload = b"manifest\n"
    path.write_bytes(payload)
    monkeypatch.delattr(output_module.os, "O_NOFOLLOW")

    assert output_module._manifest_matches(path, payload) is True


def test_manifest_temporary_supports_platform_without_nofollow(tmp_path, monkeypatch):
    monkeypatch.delattr(output_module.os, "O_NOFOLLOW")
    path = output_module._write_manifest_temporary(
        tmp_path / "manifest.json",
        b"durable\n",
    )
    try:
        assert path.read_bytes() == b"durable\n"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        path.unlink()


def test_manifest_temporary_rejects_alias_and_removes_failed_file(
    tmp_path,
    monkeypatch,
):
    original_fstat = os.fstat

    def aliased_fstat(descriptor):
        value = original_fstat(descriptor)
        return os.stat_result(
            (
                value.st_mode,
                value.st_ino,
                value.st_dev,
                2,
                value.st_uid,
                value.st_gid,
                value.st_size,
                value.st_atime,
                value.st_mtime,
                value.st_ctime,
            )
        )

    monkeypatch.setattr(output_module.os, "fstat", aliased_fstat)

    with pytest.raises(ArtifactSafetyError, match="private regular file"):
        output_module._write_manifest_temporary(
            tmp_path / "manifest.json",
            b"payload",
        )

    assert not list(tmp_path.glob(".*.tmp"))


def test_manifest_temporary_cleans_up_after_fsync_failure(tmp_path, monkeypatch):
    def fail_sync(_descriptor):
        raise OSError("injected manifest fsync failure")

    monkeypatch.setattr(output_module.os, "fsync", fail_sync)

    with pytest.raises(OSError, match="injected"):
        output_module._write_manifest_temporary(
            tmp_path / "manifest.json",
            b"payload",
        )

    assert not list(tmp_path.glob(".*.tmp"))


def test_manifest_temporary_tolerates_cleanup_race_after_failure(tmp_path, monkeypatch):
    original_fsync = os.fsync

    def remove_then_fail(descriptor):
        for candidate in tmp_path.glob(".*.tmp"):
            candidate.unlink()
        original_fsync(descriptor)
        raise OSError("injected post-unlink failure")

    monkeypatch.setattr(output_module.os, "fsync", remove_then_fail)

    with pytest.raises(OSError, match="post-unlink"):
        output_module._write_manifest_temporary(
            tmp_path / "manifest.json",
            b"payload",
        )

    assert not list(tmp_path.glob(".*.tmp"))


def test_publish_manifest_validates_store_and_refuses_mismatched_existing_file(tmp_path):
    with pytest.raises(TypeError, match="RunStore"):
        publish_manifest(object())

    store = _publish_ready_store(tmp_path)
    try:
        path = store.generation_path / store.MANIFEST_FILENAME
        path.write_bytes(b"competitor")

        with pytest.raises(ArtifactExistsError, match="already exists"):
            publish_manifest(store)

        assert path.read_bytes() == b"competitor"
        assert store.manifest_recorded is False
    finally:
        store.close()


def test_publish_manifest_recovers_identical_file_after_recording_interruption(tmp_path):
    store = _publish_ready_store(tmp_path)
    try:
        expected = build_manifest_bytes(store)
        path = store.generation_path / store.MANIFEST_FILENAME
        path.write_bytes(expected)

        assert publish_manifest(store) == path
        assert store.manifest_recorded is True
        assert path.read_bytes() == expected
    finally:
        store.close()


def test_publish_manifest_link_race_preserves_competing_file(tmp_path, monkeypatch):
    store = _publish_ready_store(tmp_path)
    path = store.generation_path / store.MANIFEST_FILENAME

    def competing_link(_source, destination, **_kwargs):
        Path(destination).write_bytes(b"competitor")
        raise FileExistsError(destination)

    monkeypatch.setattr(output_module.os, "link", competing_link)
    try:
        with pytest.raises(ArtifactExistsError, match="already exists"):
            publish_manifest(store)

        assert path.read_bytes() == b"competitor"
        assert store.manifest_recorded is False
        assert not list(store.generation_path.glob(".*.tmp"))
    finally:
        store.close()


def test_publish_manifest_fsyncs_directory_and_tolerates_temporary_cleanup_race(
    tmp_path,
    monkeypatch,
):
    store = _publish_ready_store(tmp_path)
    original_link = os.link
    syncs = []

    def link_and_remove_temporary(source, destination, **kwargs):
        original_link(source, destination, **kwargs)
        Path(source).unlink()

    def tracked_directory_sync(path):
        syncs.append(path)

    monkeypatch.setattr(output_module.os, "link", link_and_remove_temporary)
    monkeypatch.setattr(output_module, "_sync_directory", tracked_directory_sync)
    try:
        path = publish_manifest(store)

        assert path.exists()
        assert store.manifest_recorded is True
        assert syncs == [store.generation_path, store.generation_path]
    finally:
        store.close()
