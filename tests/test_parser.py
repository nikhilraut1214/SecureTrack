from pathlib import Path

import pandas as pd
import pytest

import core.parser as parser_module
from core.parser import parse_login_csv

HEADER = "timestamp,username,ip_address,status\n"
SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_login_logs.csv"


def csv_bytes(*rows: str, header: str = HEADER) -> bytes:
    return (header + "\n".join(rows) + ("\n" if rows else "")).encode("utf-8")


def test_valid_csv():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n2026-10-24 10:00:00,u1,192.0.2.1,FAILED\n",
        source_name="valid.csv",
    )
    assert len(result["data"]) == 1
    assert not result["errors"]
    assert result["data"].iloc[0]["source_row"] == 2
    assert str(result["data"]["timestamp"].dtype) == "datetime64[ns, UTC]"
    assert result["meta"]["valid_rows"] == 1
    assert result["meta"]["source_name"] == "valid.csv"
    assert result["meta"]["start_time"] == "2026-10-24T10:00:00+00:00"


def test_bad_row_reported():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\nbad,u1,nope,UNKNOWN\n"
    )
    assert result["data"].empty
    assert len(result["errors"]) == 1
    reason = result["errors"][0]["reason"]
    assert "invalid timestamp" in reason
    assert "invalid IP address" in reason
    assert "status must be SUCCESS or FAILED" in reason
    assert result["errors"][0]["row"] == 2
    assert result["meta"]["skipped_rows"] == 1


def test_missing_column():
    result = parse_login_csv(
        b"timestamp,username,status\n2026-10-24 10:00:00,u1,FAILED\n"
    )
    assert result["data"].empty
    assert "Missing columns" in result["errors"][0]["reason"]


def test_header_only_is_specific():
    result = parse_login_csv(HEADER.encode())
    assert result["data"].empty
    assert result["errors"][0]["reason"] == "CSV contains a header but no data rows."
    assert result["meta"]["valid_rows"] == 0


def test_empty_file():
    result = parse_login_csv(b"")
    assert result["data"].empty
    assert "empty" in result["errors"][0]["reason"].lower()


def test_whitespace_only_file():
    result = parse_login_csv(b"   \n\n")
    assert result["data"].empty
    assert "empty" in result["errors"][0]["reason"].lower()


def test_bom_is_accepted():
    result = parse_login_csv(
        b"\xef\xbb\xbftimestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00,u1,192.0.2.1,FAILED\n"
    )
    assert len(result["data"]) == 1
    assert not result["errors"]


def test_blank_lines_are_skipped_but_source_rows_are_accurate():
    raw = (
        b"timestamp,username,ip_address,status\n"
        b"\n"
        b"2026-10-24 10:00:00,u1,192.0.2.1,FAILED\n"
        b"   \n"
    )
    result = parse_login_csv(raw)
    assert len(result["data"]) == 1
    assert result["data"].iloc[0]["source_row"] == 3
    assert result["meta"]["blank_rows"] == 2
    assert result["meta"]["data_rows"] == 1
    assert not result["errors"]


def test_extra_columns_are_ignored():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status,session_id\n"
        b"2026-10-24 10:00:00,u1,192.0.2.1,FAILED,abc\n"
    )
    assert len(result["data"]) == 1
    assert list(result["data"].columns) == [
        "timestamp",
        "username",
        "ip_address",
        "status",
        "source_row",
    ]


def test_headers_status_and_whitespace_are_normalised():
    result = parse_login_csv(
        b" Timestamp , USERNAME , ip_address , Status \n"
        b"2026-10-24 10:00:00, u1 , 192.0.2.1 , failed \n"
    )
    assert len(result["data"]) == 1
    row = result["data"].iloc[0]
    assert row["username"] == "u1"
    assert row["status"] == "FAILED"


def test_na_like_username_is_preserved():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00,NA,192.0.2.1,FAILED\n"
    )
    assert len(result["data"]) == 1
    assert result["data"].iloc[0]["username"] == "NA"


def test_ipv6_is_accepted_and_port_is_rejected():
    valid = parse_login_csv(
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00,u1,2001:db8::1,SUCCESS\n"
    )
    assert len(valid["data"]) == 1

    invalid = parse_login_csv(
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00,u1,192.0.2.1:443,SUCCESS\n"
    )
    assert invalid["data"].empty
    assert "invalid IP address" in invalid["errors"][0]["reason"]


def test_iso_timestamp_variants_and_utc_normalisation():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24T10:00:00Z,u1,192.0.2.1,FAILED\n"
        b"2026-10-24T12:00:00+02:00,u2,192.0.2.2,SUCCESS\n"
        b"2026-10-24,u3,192.0.2.3,FAILED\n"
    )
    assert not result["errors"]
    assert len(result["data"]) == 3
    assert str(result["data"]["timestamp"].dtype) == "datetime64[ns, UTC]"
    assert result["data"].iloc[0]["timestamp"] == pd.Timestamp(
        "2026-10-24T00:00:00Z"
    )
    assert result["data"].iloc[1]["timestamp"] == pd.Timestamp(
        "2026-10-24T10:00:00Z"
    )
    assert result["data"].iloc[2]["timestamp"] == pd.Timestamp(
        "2026-10-24T10:00:00Z"
    )


def test_mixed_timezone_offsets_are_normalised_to_utc():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00+00:00,u1,192.0.2.1,FAILED\n"
        b"2026-10-24 12:00:00+02:00,u2,192.0.2.2,FAILED\n"
    )
    assert not result["errors"]
    assert str(result["data"]["timestamp"].dtype) == "datetime64[ns, UTC]"
    assert result["data"]["timestamp"].tolist() == [
        pd.Timestamp("2026-10-24T10:00:00Z"),
        pd.Timestamp("2026-10-24T10:00:00Z"),
    ]
    # Input order is preserved for equal timestamps via source_row.
    assert result["data"]["source_row"].tolist() == [2, 3]


def test_ambiguous_date_is_rejected():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n"
        b"01/02/2026,u1,192.0.2.1,FAILED\n"
    )
    assert result["data"].empty
    assert "invalid timestamp" in result["errors"][0]["reason"]


def test_naive_timestamp_is_treated_as_utc():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00,u1,192.0.2.1,FAILED\n"
    )
    timestamp = result["data"].iloc[0]["timestamp"]
    assert timestamp.tzinfo is not None
    assert timestamp == pd.Timestamp("2026-10-24T10:00:00Z")


def test_invalid_utf8_is_rejected():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n2026-10-24 10:00:00,\xff,192.0.2.1,FAILED\n"
    )
    assert result["data"].empty
    assert "UTF-8" in result["errors"][0]["reason"]


def test_nul_bytes_are_rejected():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n2026-10-24 10:00:00,u1,192.0.2.1,FAILED\x00\n"
    )
    assert result["data"].empty
    assert "Binary content" in result["errors"][0]["reason"]


def test_duplicate_headers_are_rejected():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status,status\n"
        b"2026-10-24 10:00:00,u1,192.0.2.1,FAILED,SUCCESS\n"
    )
    assert result["data"].empty
    assert "Duplicate column names" in result["errors"][0]["reason"]


def test_duplicate_headers_after_case_normalisation_are_rejected():
    result = parse_login_csv(
        b"timestamp,username,ip_address,Status,status\n"
        b"2026-10-24 10:00:00,u1,192.0.2.1,FAILED,SUCCESS\n"
    )
    assert result["data"].empty
    assert "Duplicate column names" in result["errors"][0]["reason"]


def test_upload_size_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(parser_module, "MAX_UPLOAD_BYTES", 10)
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n2026-10-24 10:00:00,u1,192.0.2.1,FAILED\n"
    )
    assert result["data"].empty
    assert "upload limit" in result["errors"][0]["reason"]


def test_row_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(parser_module, "MAX_DATA_ROWS", 2)
    rows = [
        "2026-10-24 10:00:00,u1,192.0.2.1,FAILED",
        "2026-10-24 10:01:00,u1,192.0.2.1,FAILED",
        "2026-10-24 10:02:00,u1,192.0.2.1,FAILED",
    ]
    result = parse_login_csv(csv_bytes(*rows))
    assert result["data"].empty
    assert "maximum is 2" in result["errors"][0]["reason"]


def test_column_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(parser_module, "MAX_COLUMNS", 3)
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00,u1,192.0.2.1,FAILED\n"
    )
    assert result["data"].empty
    assert "maximum is 3" in result["errors"][0]["reason"]


def test_error_list_is_capped_but_total_is_reported(monkeypatch):
    monkeypatch.setattr(parser_module, "MAX_ERRORS_RECORDED", 2)
    rows = [
        "bad,u1,nope,UNKNOWN",
        "bad,u2,nope,UNKNOWN",
        "bad,u3,nope,UNKNOWN",
    ]
    result = parse_login_csv(csv_bytes(*rows))
    assert result["data"].empty
    assert len(result["errors"]) == 2
    assert result["meta"]["error_count"] == 3
    assert result["meta"]["errors_truncated"] is True


def test_username_control_characters_are_rejected():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00,u\x01ser,192.0.2.1,FAILED\n"
    )
    assert result["data"].empty
    assert "control characters" in result["errors"][0]["reason"]


def test_overlong_username_is_rejected():
    username = "u" * (parser_module.MAX_USERNAME_LENGTH + 1)
    result = parse_login_csv(csv_bytes(f"2026-10-24 10:00:00,{username},192.0.2.1,FAILED"))
    assert result["data"].empty
    assert "longer than" in result["errors"][0]["reason"]


def test_sample_file_loads_with_metadata():
    result = parse_login_csv(SAMPLE_PATH)
    assert len(result["data"]) == 12
    assert not result["errors"]
    assert result["meta"]["source_name"] == "sample_login_logs.csv"
    assert result["meta"]["timezone"] == "UTC"
    assert result["meta"]["start_time"] == "2026-10-24T18:30:00+00:00"
    assert result["meta"]["end_time"] == "2026-10-24T18:38:00+00:00"


def test_unsupported_source_type_returns_error():
    result = parse_login_csv(12345)  # type: ignore[arg-type]
    assert result["data"].empty
    assert "Unsupported source type" in result["errors"][0]["reason"]


def test_all_invalid_rows_report_counts():
    rows = [
        "bad,u1,nope,UNKNOWN",
        "bad,u2,nope,UNKNOWN",
    ]
    result = parse_login_csv(csv_bytes(*rows))
    assert result["data"].empty
    assert result["meta"]["valid_rows"] == 0
    assert result["meta"]["skipped_rows"] == 2
    assert result["meta"]["error_count"] == 2
    assert result["meta"]["start_time"] is None


def test_multiline_quoted_fields_are_rejected_to_keep_source_rows_accurate():
    raw = (
        b"timestamp,username,ip_address,status,note\n"
        b'2026-10-24 10:00:00,u1,192.0.2.1,FAILED,"line one\nline two"\n'
        b"2026-10-24 10:00:10,u2,192.0.2.2,FAILED,ok\n"
    )
    result = parse_login_csv(raw)
    assert result["data"].empty
    assert "Multi-line CSV fields" in result["errors"][0]["reason"]


def test_multiline_header_field_is_rejected_to_keep_source_rows_accurate():
    raw = (
        b'timestamp,username,ip_address,status,"note\nmore"\n'
        b"2026-10-24 10:00:00,u1,192.0.2.1,FAILED,ok\n"
    )
    result = parse_login_csv(raw)
    assert result["data"].empty
    assert "Multi-line CSV fields" in result["errors"][0]["reason"]


def test_row_with_only_an_extra_value_is_invalid_not_blank():
    result = parse_login_csv(
        b"timestamp,username,ip_address,status,note\n"
        b",,,,unexpected\n"
        b"2026-10-24 10:00:00,u1,192.0.2.1,FAILED,ok\n"
    )
    assert result["meta"]["data_rows"] == 2
    assert result["meta"]["blank_rows"] == 0
    assert result["meta"]["skipped_rows"] == 1
    assert result["errors"][0]["row"] == 2
    assert "empty username" in result["errors"][0]["reason"]
    assert len(result["data"]) == 1
