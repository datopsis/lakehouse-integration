"""T11: destructive maintenance must preserve exact rows and referenced S3 objects."""

import json
from urllib.parse import urlsplit

from sail_probe import queries

NAME = "maintenance"
ROWS = [[i, f"row-{i}"] for i in range(12)]


def key(path):
    uri = urlsplit(path)
    assert uri.scheme == "s3" and uri.netloc == "warehouse", path
    return uri.path.lstrip("/")


def listing(h, table):
    prefix = key(table.location()).rstrip("/") + "/"
    return {
        obj["Key"]
        for page in h.s3_client()
        .get_paginator("list_objects_v2")
        .paginate(Bucket="warehouse", Prefix=prefix)
        for obj in page.get("Contents", [])
    }


def references(table):
    """All live manifest entries in ALL retained snapshots, plus their metadata."""
    paths = {key(table.metadata_location)}
    data = set()
    for snapshot in table.metadata.snapshots:
        paths.add(key(snapshot.manifest_list))
        for manifest in snapshot.manifests(table.io):
            paths.add(key(manifest.manifest_path))
            for entry in manifest.fetch_manifest_entry(table.io, discard_deleted=True):
                data.add(key(entry.data_file.file_path))
    return paths | data, data


def exact_error(h, statement, name, message):
    try:
        h.sql(statement)
    except RuntimeError as exc:
        error = json.loads(str(exc))
        assert error["errorName"] == name, error
        assert error["message"] == message, error
        return {"errorName": name, "message": message}
    raise AssertionError("Expected rejection: " + statement)


def read(h):
    assert h.sql(f"SELECT * FROM iceberg.integration.{NAME} ORDER BY id") == ROWS
    table = h.rest_catalog().load_table("integration." + NAME)
    actual = table.scan().to_arrow().sort_by("id").to_pylist()
    assert actual == [dict(zip(("id", "label"), row, strict=True)) for row in ROWS], actual
    assert queries(h, [f"SELECT * FROM qualification.integration.{NAME} ORDER BY id"]) == [ROWS]
    refs, _ = references(table)
    objects = listing(h, table)
    assert refs <= objects, sorted(refs - objects)
    return {"rows": ROWS, "referenced": sorted(refs), "objects": sorted(objects)}


def exercise(h):
    table_name = f"maintenance.integration.{NAME}"
    assert (
        h.sql(
            f"CREATE TABLE {table_name} (id BIGINT, label VARCHAR) "
            "WITH (format='PARQUET', format_version=2)"
        )
        == []
    )
    for start in range(0, 12, 2):
        values = ", ".join(f"({i}, 'row-{i}')" for i in range(start, start + 2))
        assert h.sql(f"INSERT INTO {table_name} VALUES {values}") == [[2]]
    before = read(h)
    table = h.rest_catalog().load_table("integration." + NAME)
    snapshots = {s.snapshot_id for s in table.metadata.snapshots}
    assert len(snapshots) == 7, snapshots  # CREATE and six acknowledged INSERTs.
    old_data = {key(task.file.file_path) for task in table.scan().plan_files()}
    assert len(old_data) >= 6, old_data
    assert h.sql(f'SELECT count(*) FROM maintenance.integration."{NAME}$files"') == [
        [len(old_data)]
    ]
    h.sql(f"ALTER TABLE {table_name} EXECUTE optimize")
    compacted = read(h)
    table = h.rest_catalog().load_table("integration." + NAME)
    current = table.current_snapshot().snapshot_id
    current_data = {key(task.file.file_path) for task in table.scan().plan_files()}
    assert 0 < len(current_data) < len(old_data), (old_data, current_data)
    assert old_data.isdisjoint(current_data), (old_data, current_data)
    assert h.sql(f'SELECT count(*) FROM maintenance.integration."{NAME}$files"') == [
        [len(current_data)]
    ]
    assert {s.snapshot_id for s in table.metadata.snapshots} == snapshots | {current}
    refs_before, all_data = references(table)
    assert all_data - current_data == old_data
    objects_before = listing(h, table)
    assert refs_before <= objects_before

    rejected = {}
    for procedure in ("expire_snapshots", "remove_orphan_files"):
        property_name = procedure.replace("_", "-")
        rejected[procedure] = exact_error(
            h,
            f"ALTER TABLE iceberg.integration.{NAME} EXECUTE {procedure}(retention_threshold => '0s')",
            "INVALID_PROCEDURE_ARGUMENT",
            "Retention specified (0.00s) is shorter than the minimum retention configured in the system (7.00d). "
            f"Minimum retention can be changed with iceberg.{property_name}.min-retention configuration property "
            f"or iceberg.{procedure}_min_retention session property",
        )
    # Default refusals must not mutate snapshots or remove a single object.
    assert listing(h, table) == objects_before
    assert {
        s.snapshot_id for s in h.rest_catalog().load_table("integration." + NAME).metadata.snapshots
    } == snapshots | {current}
    h.sql(f"ALTER TABLE {table_name} EXECUTE expire_snapshots(retention_threshold => '0s')")
    assert h.sql(f'SELECT snapshot_id FROM maintenance.integration."{NAME}$snapshots"') == [
        [current]
    ]
    expired = read(h)
    objects_after = set(expired["objects"])
    assert old_data.isdisjoint(objects_after), sorted(old_data & objects_after)
    assert current_data <= objects_after
    failures = {
        str(snapshot): exact_error(
            h,
            f"SELECT * FROM {table_name} FOR VERSION AS OF {snapshot}",
            "INVALID_ARGUMENTS",
            f"Iceberg snapshot ID does not exists: {snapshot}",
        )
        for snapshot in sorted(snapshots)
    }

    table = h.rest_catalog().load_table("integration." + NAME)
    refs, _ = references(table)
    orphan = key(table.location()).rstrip("/") + "/data/planted-orphan.parquet"
    assert orphan not in refs and orphan not in objects_after
    h.s3_client().put_object(Bucket="warehouse", Key=orphan, Body=b"T11 unreferenced object\n")
    planted = listing(h, table)
    assert planted == objects_after | {orphan}
    h.sql(f"ALTER TABLE {table_name} EXECUTE remove_orphan_files(retention_threshold => '0s')")
    after = read(h)
    assert orphan not in after["objects"]
    assert refs <= set(after["objects"])
    assert references(h.rest_catalog().load_table("integration." + NAME))[0] == refs
    assert h.sql(f'SELECT snapshot_id FROM maintenance.integration."{NAME}$snapshots"') == [
        [current]
    ]
    return {
        "before": before,
        "compacted": compacted,
        "data_files_before": sorted(old_data),
        "data_files_after": sorted(current_data),
        "default_retention_rejections": rejected,
        "expired_snapshots": sorted(snapshots),
        "current_snapshot": current,
        "expired_reads": failures,
        "after_expiry": expired,
        "orphan": orphan,
        "before_orphan_removal": sorted(planted),
        "after_orphan_removal": after,
    }
