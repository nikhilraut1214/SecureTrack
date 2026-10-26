from pathlib import Path

from streamlit.testing.v1 import AppTest

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


def test_app_loads_sample_and_renders_without_exceptions():
    app = AppTest.from_file(str(APP_PATH), default_timeout=60)
    app.run()

    assert len(app.exception) == 0
    assert len(app.error) == 0

    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Total events"] == "12"
    assert metrics["Successful"] == "4"
    assert metrics["Failed"] == "8"
    assert metrics["Unique IPs"] == "3"
    assert metrics["Alerts"] == "3"

    assert [tab.label for tab in app.tabs] == [
        "Overview",
        "Log Explorer",
        "Security Alerts",
        "Detection Rules",
    ]


def test_app_alert_summary_has_one_row_per_episode():
    app = AppTest.from_file(str(APP_PATH), default_timeout=60)
    app.run()

    # The first table is the overview IP table; the alert summary is the
    # second table inside the Security Alerts tab. AppTest exposes all
    # dataframes in document order.
    tables = list(app.dataframe)
    assert tables
    assert len(app.exception) == 0

    alert_tables = [
        table for table in tables if "alert_id" in list(table.value.columns)
    ]
    assert len(alert_tables) == 1
    assert len(alert_tables[0].value) == 3
