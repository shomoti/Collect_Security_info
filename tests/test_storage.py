from cti_collector.storage import StateStore


def test_state_store_save_and_get(tmp_path) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(str(db_path))
    try:
        store.save("https://example.com/a", "CTI-1", "CTI-2", "hash1")
        row = store.get("https://example.com/a")
        assert row is not None
        assert row.jira_intel_key == "CTI-1"
        assert row.jira_validation_key == "CTI-2"
        assert row.content_hash == "hash1"
        assert row.source == ""
        assert row.title_norm == ""
        assert row.content_fp == ""
        assert row.canonical_key == ""
        assert row.update_count == 0
    finally:
        store.close()


def test_state_store_upsert_updates_existing_row(tmp_path) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(str(db_path))
    try:
        store.save("https://example.com/a", "CTI-1", "CTI-2", "hash1")
        store.save("https://example.com/a", "CTI-3", "CTI-4", "hash2")
        row = store.get("https://example.com/a")
        assert row is not None
        assert row.jira_intel_key == "CTI-3"
        assert row.jira_validation_key == "CTI-4"
        assert row.content_hash == "hash2"
        assert row.source == ""
        assert row.title_norm == ""
        assert row.content_fp == ""
        assert row.canonical_key == ""
        assert row.update_count == 0
    finally:
        store.close()


def test_state_store_find_by_content_hash(tmp_path) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(str(db_path))
    try:
        store.save(
            "https://example.com/a",
            "CTI-1",
            "CTI-2",
            "hashX",
            source="S",
            title_norm="abc",
            content_fp="fp1",
            canonical_key="CTI-1",
            update_count=2,
        )
        row = store.find_by_content_hash("hashX")
        assert row is not None
        assert row.jira_validation_key == "CTI-2"
        assert row.source == "S"
        assert row.title_norm == "abc"
        assert row.content_fp == "fp1"
        assert row.canonical_key == "CTI-1"
        assert row.update_count == 2
    finally:
        store.close()


def test_state_store_feedback_upsert_overwrites_same_issue(tmp_path) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(str(db_path))
    try:
        store.upsert_feedback("CTI-1", "CISA", "noise")
        store.upsert_feedback("CTI-1", "CISA", "useful")
        stats = store.get_feedback_stats_by_source()
        assert len(stats) == 1
        assert stats[0].source == "CISA"
        assert stats[0].useful_count == 1
        assert stats[0].noise_count == 0
        assert stats[0].total_count == 1
    finally:
        store.close()


def test_state_store_feedback_stats_group_by_source(tmp_path) -> None:
    db_path = tmp_path / "state.db"
    store = StateStore(str(db_path))
    try:
        store.upsert_feedback("CTI-1", "CISA", "useful")
        store.upsert_feedback("CTI-2", "CISA", "noise")
        store.upsert_feedback("CTI-3", "JVN", "useful")
        stats = {row.source: row for row in store.get_feedback_stats_by_source()}
        assert stats["CISA"].total_count == 2
        assert stats["CISA"].useful_count == 1
        assert stats["CISA"].noise_count == 1
        assert stats["JVN"].total_count == 1
        assert stats["JVN"].useful_count == 1
        assert stats["JVN"].noise_count == 0
    finally:
        store.close()
