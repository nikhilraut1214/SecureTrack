from core.parser import parse_login_csv

def test_valid_csv():
    result = parse_login_csv(b"timestamp,username,ip_address,status\n2026-10-24 10:00:00,u1,192.0.2.1,FAILED\n")
    assert len(result["data"]) == 1 and not result["errors"]

def test_bad_row_reported():
    result = parse_login_csv(b"timestamp,username,ip_address,status\nbad,u1,nope,UNKNOWN\n")
    assert result["data"].empty and len(result["errors"]) == 1

def test_missing_column():
    result = parse_login_csv(b"timestamp,username,status\n2026-10-24 10:00:00,u1,FAILED\n")
    assert "Missing columns" in result["errors"][0]["reason"]
