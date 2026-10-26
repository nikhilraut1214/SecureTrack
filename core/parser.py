"""CSV parsing and validation for SecureTrack.

The parser is intentionally strict and defensive:

* only UTF-8 (with optional BOM) comma-separated files are accepted;
* timestamps must be ISO 8601 and are normalised to UTC;
* size, row, column, and error-list limits are enforced here as well as in the UI;
* every valid event keeps its original CSV row number for evidence traceability.
"""

from __future__ import annotations

import csv
import ipaddress
from collections import Counter
from io import StringIO
from pathlib import Path
from typing import Any

import pandas as pd

REQUIRED_COLUMNS = ("timestamp", "username", "ip_address", "status")
ALLOWED_STATUSES = {"SUCCESS", "FAILED"}

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_DATA_ROWS = 50_000
MAX_COLUMNS = 50
MAX_ERRORS_RECORDED = 500
MAX_USERNAME_LENGTH = 256

EMPTY_COLUMNS = ["timestamp", "username", "ip_address", "status", "source_row"]


def _empty_data() -> pd.DataFrame:
    """Return an empty frame with stable dtypes and columns."""
    return pd.DataFrame(
        {
            "timestamp": pd.Series(dtype="datetime64[ns, UTC]"),
            "username": pd.Series(dtype="object"),
            "ip_address": pd.Series(dtype="object"),
            "status": pd.Series(dtype="object"),
            "source_row": pd.Series(dtype="int64"),
        }
    )


def _meta(
    source_name: str,
    size_bytes: int,
    *,
    data_rows: int = 0,
    valid_rows: int = 0,
    skipped_rows: int = 0,
    blank_rows: int = 0,
    error_count: int = 0,
    errors_truncated: bool = False,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict[str, Any]:
    return {
        "source_name": source_name,
        "size_bytes": size_bytes,
        "data_rows": data_rows,
        "valid_rows": valid_rows,
        "skipped_rows": skipped_rows,
        "blank_rows": blank_rows,
        "error_count": error_count,
        "errors_truncated": errors_truncated,
        "start_time": start_time,
        "end_time": end_time,
        "timezone": "UTC",
    }


def _fatal(message: str, source_name: str, size_bytes: int) -> dict[str, Any]:
    return {
        "data": _empty_data(),
        "errors": [{"row": "-", "reason": message}],
        "meta": _meta(source_name, size_bytes),
    }


def _iso(value: pd.Timestamp) -> str:
    timestamp = pd.Timestamp(value)
    if timestamp.tzinfo is not None:
        timestamp = timestamp.tz_convert("UTC")
    return timestamp.isoformat()


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _duplicate_header_names(text: str) -> list[str]:
    """Detect duplicated header names before pandas renames the later copies.

    The first physical line is sufficient for ordinary CSV headers. If it is
    malformed (for example, a quoted newline inside a header), the check is
    skipped and pandas' parsed columns are used instead.
    """
    first_line = text.splitlines()[0] if text.splitlines() else ""
    try:
        raw_headers = next(csv.reader([first_line]))
    except (csv.Error, StopIteration):
        return []

    normalised = [str(name).strip().lower() for name in raw_headers]
    counts = Counter(normalised)
    return sorted(name for name, count in counts.items() if count > 1)


def _read_source(
    source: bytes | bytearray | str | Path,
    source_name: str | None,
) -> tuple[bytes | None, str, dict[str, Any] | None]:
    if isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
        return raw, source_name or "Uploaded CSV", None

    if isinstance(source, (str, Path)) or hasattr(source, "__fspath__"):
        path = Path(source)
        name = source_name or path.name
        try:
            raw = path.read_bytes()
        except OSError as exc:
            detail = exc.strerror or "could not be read"
            return None, name, _fatal(f"Could not read file: {detail}.", name, 0)
        return raw, name, None

    return (
        None,
        source_name or "Unknown",
        _fatal(
            "Unsupported source type. Provide CSV bytes or a file path.",
            source_name or "Unknown",
            0,
        ),
    )


def parse_login_csv(
    source: bytes | bytearray | str | Path,
    source_name: str | None = None,
) -> dict[str, Any]:
    """Parse and validate a SecureTrack login CSV.

    Args:
        source: CSV bytes or a local file path.
        source_name: Optional display name (for example, the uploaded filename).

    Returns:
        A dictionary with:
        * ``data``: validated events sorted by timestamp and source row;
        * ``errors``: row-level or file-level validation errors;
        * ``meta``: dataset counts, time range, and truncation information.

    The function never executes uploaded content and never writes uploaded data.
    """
    raw, name, source_error = _read_source(source, source_name)
    if source_error is not None:
        return source_error
    assert raw is not None

    if len(raw) > MAX_UPLOAD_BYTES:
        limit_mb = MAX_UPLOAD_BYTES / (1024 * 1024)
        return _fatal(
            f"File exceeds the {limit_mb:g} MB upload limit.",
            name,
            len(raw),
        )

    if b"\x00" in raw:
        return _fatal("Binary content (NUL bytes) is not supported.", name, len(raw))

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return _fatal(
            "File must be UTF-8 encoded (UTF-8 with BOM is also accepted).",
            name,
            len(raw),
        )

    if not text.strip():
        return _fatal("CSV is empty.", name, len(raw))

    duplicate_headers = _duplicate_header_names(text)
    if duplicate_headers:
        return _fatal(
            "Duplicate column names are not allowed: "
            + ", ".join(duplicate_headers),
            name,
            len(raw),
        )

    try:
        frame = pd.read_csv(
            StringIO(text),
            dtype=str,
            keep_default_na=False,
            skip_blank_lines=False,
            sep=",",
        )
    except pd.errors.EmptyDataError:
        return _fatal("CSV is empty.", name, len(raw))
    except pd.errors.ParserError as exc:
        detail = str(exc).splitlines()[0][:300]
        return _fatal(f"Could not parse CSV: {detail}", name, len(raw))
    except (UnicodeError, ValueError) as exc:
        detail = str(exc).splitlines()[0][:300]
        return _fatal(f"Could not read CSV: {detail}", name, len(raw))

    frame.columns = [str(column).strip().lower() for column in frame.columns]

    if any("\n" in column or "\r" in column for column in frame.columns):
        return _fatal(
            "Multi-line CSV fields are not supported; remove line breaks "
            "from values.",
            name,
            len(raw),
        )

    if len(frame.columns) > MAX_COLUMNS:
        return _fatal(
            f"CSV has {len(frame.columns)} columns; maximum is {MAX_COLUMNS}.",
            name,
            len(raw),
        )

    normalised_headers = list(frame.columns)
    duplicate_after_normalisation = sorted(
        {column for column in normalised_headers if normalised_headers.count(column) > 1}
    )
    if duplicate_after_normalisation:
        return _fatal(
            "Duplicate column names are not allowed: "
            + ", ".join(duplicate_after_normalisation),
            name,
            len(raw),
        )

    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        return _fatal(
            "Missing columns: " + ", ".join(missing),
            name,
            len(raw),
        )

    # A quoted newline makes pandas' logical row numbers diverge from physical
    # CSV lines, which would make source_row traceability misleading. Reject
    # such files rather than silently reporting the wrong evidence row.
    multiline = frame.apply(
        lambda column: column.str.contains(r"[\r\n]", regex=True, na=False)
    ).any()
    if bool(multiline.any()):
        return _fatal(
            "Multi-line CSV fields are not supported; remove line breaks "
            "from values.",
            name,
            len(raw),
        )

    timestamps_text = frame["timestamp"].astype(str).str.strip()
    usernames = frame["username"].astype(str).str.strip()
    ips = frame["ip_address"].astype(str).str.strip()
    statuses = frame["status"].astype(str).str.strip().str.upper()

    # Blank means every column is empty, not only the required ones. Otherwise
    # a malformed row such as ",,,unexpected" would be silently skipped as
    # blank instead of being reported as invalid.
    nonblank = frame.apply(lambda column: column.str.strip() != "").any(axis=1)
    blank = ~nonblank
    data_rows = int(nonblank.sum())
    blank_rows = int(blank.sum())

    if data_rows == 0:
        return _fatal(
            "CSV contains a header but no data rows.",
            name,
            len(raw),
        )

    if data_rows > MAX_DATA_ROWS:
        return _fatal(
            f"CSV contains {data_rows:,} data rows; maximum is {MAX_DATA_ROWS:,}.",
            name,
            len(raw),
        )

    timestamps = pd.to_datetime(
        timestamps_text,
        format="ISO8601",
        utc=True,
        errors="coerce",
    )

    unique_ips = ips[nonblank].unique()
    valid_ips = [ip for ip in unique_ips if _is_valid_ip(ip)]
    valid_ip = ips.isin(valid_ips)

    username_control = usernames.str.contains(
        r"[\x00-\x1f\x7f]", regex=True, na=False
    )
    username_too_long = usernames.str.len() > MAX_USERNAME_LENGTH

    invalid_timestamp = timestamps.isna()
    invalid_username = (usernames == "") | username_control | username_too_long
    invalid_ip = ~valid_ip
    invalid_status = ~statuses.isin(ALLOWED_STATUSES)

    invalid = nonblank & (
        invalid_timestamp
        | invalid_username
        | invalid_ip
        | invalid_status
    )
    valid = nonblank & ~invalid

    invalid_count = int(invalid.sum())
    invalid_positions = frame.index[invalid]
    errors: list[dict[str, Any]] = []

    for idx in invalid_positions[:MAX_ERRORS_RECORDED]:
        reasons: list[str] = []
        if bool(invalid_timestamp.at[idx]):
            reasons.append(
                "invalid timestamp (expected ISO 8601, e.g. "
                "2026-10-24 18:30:00 or 2026-10-24T18:30:00Z)"
            )
        if bool(username_control.at[idx]):
            reasons.append("username contains control characters")
        elif bool(username_too_long.at[idx]):
            reasons.append(f"username is longer than {MAX_USERNAME_LENGTH} characters")
        elif bool((usernames == "").at[idx]):
            reasons.append("empty username")
        if bool(invalid_ip.at[idx]):
            reasons.append("invalid IP address")
        if bool(invalid_status.at[idx]):
            reasons.append("status must be SUCCESS or FAILED")
        errors.append({"row": int(idx) + 2, "reason": "; ".join(reasons)})

    valid_frame = pd.DataFrame(
        {
            "timestamp": timestamps,
            "username": usernames,
            "ip_address": ips,
            "status": statuses,
            "source_row": pd.Series(
                frame.index + 2,
                index=frame.index,
                dtype="int64",
            ),
        }
    ).loc[valid].copy()

    if valid_frame.empty:
        data = _empty_data()
        start_time = None
        end_time = None
    else:
        data = valid_frame.sort_values(
            ["timestamp", "source_row"], kind="mergesort"
        ).reset_index(drop=True)
        start_time = _iso(data["timestamp"].iloc[0])
        end_time = _iso(data["timestamp"].iloc[-1])

    return {
        "data": data,
        "errors": errors,
        "meta": _meta(
            name,
            len(raw),
            data_rows=data_rows,
            valid_rows=int(valid.sum()),
            skipped_rows=invalid_count,
            blank_rows=blank_rows,
            error_count=invalid_count,
            errors_truncated=invalid_count > len(errors),
            start_time=start_time,
            end_time=end_time,
        ),
    }
