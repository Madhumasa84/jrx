"""Edge-case tests for the JRX-01 builder. Run with: pytest eval/jrx-01"""

import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("jrx01_build", HERE / "build_and_audit.py")
build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build)


def _inputs():
    return deepcopy(build.ALL_EVENTS), deepcopy(build.CASES_DEF), deepcopy(build.PROVENANCE)


def _audit(records):
    return build.audit_cases(records, build.ALL_EVENTS, build.CASES_DEF)


def _records():
    return build.build_cases(*_inputs())


def _check(report, case_id):
    return next(c for c in report["checks"] if c["case_id"] == case_id)


# --- committed outputs -------------------------------------------------------


def test_committed_outputs_match_a_fresh_build(tmp_path):
    assert build.main(tmp_path) == 0
    for rel in [
        "cases.jsonl",
        "provenance.json",
        "input_audit_report.json",
        *(f"cases/{c['id']}.json" for c in build.CASES_DEF),
    ]:
        assert (tmp_path / rel).read_bytes() == (HERE / rel).read_bytes(), rel


def test_default_output_dir_is_the_script_dir_not_cwd():
    assert build.OUT_DIR == HERE


def test_all_cases_pass_audit_and_context_ends_before_proposal():
    records = _records()
    report = _audit(records)
    assert report["all_passed"] is True
    for record, cdef in zip(records, build.CASES_DEF, strict=True):
        ids = [ev["event_id"] for ev in record["state"]["recent_context"]]
        cutoff = int(cdef["cutoff_event"][1:])
        assert ids == [f"E{n:02d}" for n in range(1, cutoff)]
        assert record["research"]["decision_position"] == cutoff


def test_written_files_are_not_group_or_world_writable(tmp_path):
    build.main(tmp_path)
    for path in [tmp_path / "cases.jsonl", *tmp_path.glob("cases/*.json")]:
        assert path.stat().st_mode & 0o022 == 0, path


# --- audit leakage checks ----------------------------------------------------


def test_proposal_event_leaking_into_its_own_context_fails():
    records = _records()
    case = records[0]
    cutoff = build.CASES_DEF[0]["cutoff_event"]
    case["state"]["recent_context"].append(
        deepcopy(next(ev for ev in build.ALL_EVENTS if ev["event_id"] == cutoff))
    )
    check = _check(_audit(records), case["id"])
    assert check["future_events_detected"] == [cutoff]
    assert check["input_audit_passed"] is False


def test_proposal_result_leaking_fails():
    records = _records()
    case = records[1]
    idx = next(
        i
        for i, ev in enumerate(build.ALL_EVENTS)
        if ev["event_id"] == build.CASES_DEF[1]["cutoff_event"]
    )
    case["state"]["recent_context"].append(deepcopy(build.ALL_EVENTS[idx + 1]))
    assert _check(_audit(records), case["id"])["input_audit_passed"] is False


def test_dropped_or_edited_context_event_fails():
    records = _records()
    records[2]["state"]["recent_context"].pop(3)
    records[3]["state"]["recent_context"][0]["excerpt"] += " (edited)"
    report = _audit(records)
    for case in records[2:4]:
        check = _check(report, case["id"])
        assert check["context_matches_transcript"] is False
        assert check["input_audit_passed"] is False


@pytest.mark.parametrize("key", build.LEAKAGE_KEYS)
def test_annotation_key_nested_in_state_fails(key):
    records = _records()
    records[0]["state"]["tool_call"]["input"][key] = "x"
    check = _check(_audit(records), records[0]["id"])
    assert check["leakage_detected"] == [key]
    assert check["input_audit_passed"] is False


def test_rationale_text_in_state_fails():
    records = _records()
    case = records[0]
    case["state"]["user_task"] += " " + case["annotation"]["rationale"]
    check = _check(_audit(records), case["id"])
    assert "rationale_text" in check["leakage_detected"]


def test_quoted_key_name_inside_text_is_not_a_false_positive():
    records = _records()
    records[0]["state"]["user_task"] += ' see the "label" field'
    records[0]["state"]["tool_call"]["input"]["command"] += " # label"
    assert _check(_audit(records), records[0]["id"])["leakage_detected"] == []


@pytest.mark.parametrize(
    "where",
    ["state", "annotation", "provenance"],
)
@pytest.mark.parametrize("home", ["/home/alice", "/Users/bob/project", "/home/carol"])
def test_home_path_anywhere_in_record_fails(where, home):
    records = _records()
    case = records[0]
    target = {
        "state": lambda: case["state"].__setitem__("cwd", home),
        "annotation": lambda: case["annotation"].__setitem__("rationale", f"see {home}"),
        "provenance": lambda: case["provenance"].__setitem__("provenance_notes", home),
    }
    target[where]()
    check = _check(_audit(records), case["id"])
    assert check["personal_home_detected"] is True
    assert check["input_audit_passed"] is False


# --- sanitize ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/home/someone/jev_reflex/src", "/work/jev_reflex/src"),
        ("cd /Users/someone && ls", "cd /work && ls"),
        ('"/home/someone"', '"/work"'),
        ("/tmp/home/x", "/tmp/home/x"),
        ("/work/jev_reflex", "/work/jev_reflex"),
        ("~/home/x", "~/home/x"),
        ("/homes/x", "/homes/x"),
    ],
)
def test_sanitize(raw, expected):
    assert build.sanitize(raw) == expected


# --- evidence locations ------------------------------------------------------


STATE = {"a": [{"t": "hello world"}], "n": {"9": "nine"}, "s": "text"}


@pytest.mark.parametrize(
    ("location", "quote", "ok"),
    [
        ("a/0/t", "world", True),
        ("n/9", "nine", True),
        ("s", "text", True),
        ("a/0/t", "", False),
        ("a/0/t", None, False),
        ("a/0/t", 5, False),
        ("a/0/t", "absent", False),
        ("a/1/t", "world", False),
        ("a/-1/t", "world", False),
        ("a/00/t", "world", False),
        ("a/+0/t", "world", False),
        ("a/٠/t", "world", False),
        ("a/0", "world", False),
        ("", "world", False),
        ("a//t", "world", False),
        (None, "world", False),
        ("s/0", "t", False),
    ],
)
def test_evidence_matches(location, quote, ok):
    assert build.evidence_matches(STATE, {"location": location, "quote": quote}) is ok


def test_invalid_evidence_location_fails_audit():
    records = _records()
    records[0]["annotation"]["evidence"][0]["location"] = "recent_context/999/excerpt"
    check = _check(_audit(records), records[0]["id"])
    assert check["invalid_evidence_locations"] == ["recent_context/999/excerpt"]
    assert check["input_audit_passed"] is False


# --- input validation --------------------------------------------------------


def _expect_build_error(mutate, match):
    events, cases, provenance = _inputs()
    mutate(events, cases, provenance)
    with pytest.raises(build.CaseBuildError, match=match):
        build.build_cases(events, cases, provenance)


def test_unknown_cutoff_is_a_clear_error():
    _expect_build_error(
        lambda e, c, p: c[0].__setitem__("cutoff_event", "E99"), "not a tool_call event"
    )


def test_cutoff_on_non_call_event_is_rejected():
    _expect_build_error(
        lambda e, c, p: c[0].__setitem__("cutoff_event", "E12"), "not a tool_call event"
    )


def test_duplicate_case_id_is_rejected():
    _expect_build_error(lambda e, c, p: c.append(deepcopy(c[0])), "duplicate case id")


def test_case_number_must_match_call_position():
    _expect_build_error(lambda e, c, p: c[0].__setitem__("id", "JRX-01-call-06"), "is call")


def test_hand_edited_proposal_is_rejected():
    def mutate(e, c, p):
        c[0]["tool_call"]["input"]["command"] += " --no-header"

    _expect_build_error(mutate, "does not match transcript")


def test_proposal_tool_must_match_transcript():
    _expect_build_error(
        lambda e, c, p: c[0]["tool_call"].__setitem__("tool", "read_file"),
        "does not match transcript",
    )


def test_unparseable_proposal_arguments_are_rejected():
    def mutate(e, c, p):
        next(ev for ev in e if ev["event_id"] == c[0]["cutoff_event"])["excerpt"] = "{bad"

    _expect_build_error(mutate, "not JSON")


def test_duplicate_event_ids_are_rejected():
    _expect_build_error(lambda e, c, p: e.append(deepcopy(e[0])), "unique")


def test_tool_output_before_its_call_is_rejected():
    def mutate(e, c, p):
        e[3], e[4] = e[4], e[3]  # E05 output now precedes E04 call

    _expect_build_error(mutate, "no earlier unanswered")


def test_tool_output_from_a_different_tool_is_rejected():
    _expect_build_error(lambda e, c, p: e[4].__setitem__("source", "read_file"), "unanswered")


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("sampled_calls_count", 4, "sampled_calls_count"),
        ("observed_calls_count", 19, "observed_calls_count"),
        ("observed_calls_count", 21, "observed_calls_count"),
        ("provenance_notes", "21 observed calls, 5 sampled calls", "notes disagree"),
        ("session_id", "JRX-02", "session_id"),
    ],
)
def test_provenance_must_agree_with_cases(field, value, match):
    _expect_build_error(lambda e, c, p: p.__setitem__(field, value), match)


def test_non_contiguous_event_ids_keep_the_cutoff_boundary():
    # Omitting an event (as the collection rules allow) must not shift the boundary.
    events, cases, provenance = _inputs()
    del events[1]  # drop E02, so ids no longer equal list index + 1
    records = build.build_cases(events, cases, provenance)
    for record, cdef in zip(records, cases, strict=True):
        ids = [ev["event_id"] for ev in record["state"]["recent_context"]]
        assert cdef["cutoff_event"] not in ids
        assert ids[-1] < cdef["cutoff_event"]
    report = build.audit_cases(records, events, cases)
    assert all(c["context_matches_transcript"] for c in report["checks"])


# --- writing -----------------------------------------------------------------


def test_failed_audit_writes_nothing(tmp_path, monkeypatch, capsys):
    sentinel = tmp_path / "cases.jsonl"
    sentinel.write_text("last good build\n")
    original = build.build_cases

    def leaky(*args):
        records = original(*args)
        records[0]["state"]["label"] = "allow"
        return records

    monkeypatch.setattr(build, "build_cases", leaky)
    assert build.main(tmp_path) == 1
    assert sentinel.read_text() == "last good build\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cases.jsonl"]
    assert "FAILED (no files written)" in capsys.readouterr().err


def test_build_error_writes_nothing(tmp_path, monkeypatch, capsys):
    bad = deepcopy(build.CASES_DEF)
    bad[0]["cutoff_event"] = "E99"
    monkeypatch.setattr(build, "CASES_DEF", bad)
    assert build.main(tmp_path) == 1
    assert list(tmp_path.iterdir()) == []
    assert "Build failed" in capsys.readouterr().err


def test_stale_case_files_are_removed_but_unrelated_files_kept(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "JRX-01-call-99.json").write_text("{}")
    (cases_dir / "notes.json").write_text("{}")
    assert build.main(tmp_path) == 0
    names = sorted(p.name for p in cases_dir.iterdir())
    assert "JRX-01-call-99.json" not in names
    assert "notes.json" in names
    lines = (tmp_path / "cases.jsonl").read_text().splitlines()
    assert [json.loads(line)["id"] for line in lines] == [c["id"] for c in build.CASES_DEF]


def test_interrupted_write_leaves_previous_file_and_no_temp(tmp_path, monkeypatch):
    target = tmp_path / "out.json"
    target.write_text("old")

    def boom(*_):
        raise OSError("disk full")

    monkeypatch.setattr(build.os, "replace", boom)
    with pytest.raises(OSError):
        build._write_atomic(target, "new")
    assert target.read_text() == "old"
    assert list(tmp_path.iterdir()) == [target]


def test_provenance_counts_only_the_calls_in_the_transcript():
    calls = [event["event_id"] for event in build.ALL_EVENTS if event["type"] == "tool_call"]
    assert len(calls) == 20 and calls[-1] == build.ALL_EVENTS[-1]["event_id"] == "E44"
    assert build.CASES_DEF[-1]["cutoff_event"] == "E44"  # the last sampled call is call 20
    for record in [build.PROVENANCE, *(json.loads(line) for line in _jsonl_lines())]:
        provenance = record.get("provenance", record)
        assert provenance["observed_calls_count"] == 20
        assert provenance["sampled_calls_count"] == 5
        assert "20 observed calls, 5 sampled calls" in provenance["provenance_notes"]


def _jsonl_lines():
    return (HERE / "cases.jsonl").read_text().splitlines()


def test_second_build_is_byte_identical(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    assert build.main(first) == 0 and build.main(second) == 0
    files = sorted(p.relative_to(first) for p in first.rglob("*") if p.is_file())
    assert files == sorted(p.relative_to(second) for p in second.rglob("*") if p.is_file())
    for rel in files:
        assert (first / rel).read_bytes() == (second / rel).read_bytes(), rel
