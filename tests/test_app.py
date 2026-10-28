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
    assert any(
        "Why this alert was generated" in block.value for block in app.markdown
    )


def test_app_clear_and_reload_sample_removes_stale_results():
    app = AppTest.from_file(str(APP_PATH), default_timeout=60)
    app.run()

    app.button(key="clear_dataset_sidebar").click().run()

    assert len(app.exception) == 0
    assert len(app.error) == 0
    assert len(app.metric) == 0
    assert "No dataset loaded" in [item.value for item in app.subheader]
    assert app.session_state["dataset_mode"] == "none"

    app.button(key="load_sample_empty").click().run()

    assert len(app.exception) == 0
    assert len(app.error) == 0
    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Total events"] == "12"
    assert metrics["Alerts"] == "3"
    assert app.session_state["dataset_mode"] == "sample"


def test_app_username_filter_updates_log_and_alert_views():
    app = AppTest.from_file(str(APP_PATH), default_timeout=60)
    app.run()

    username = next(
        item for item in app.text_input if item.label == "Username contains"
    )
    username.set_value("alex").run()

    assert len(app.exception) == 0
    log_table = next(
        table
        for table in app.dataframe
        if "source_row" in list(table.value.columns)
        and len(table.value) == 6
    )
    assert set(log_table.value["username"]) == {"alex"}

    alert_table = next(
        table
        for table in app.dataframe
        if "alert_id" in list(table.value.columns)
    )
    assert len(alert_table.value) == 2
    assert any(
        "Showing 2 of 3 detected alerts" in caption.value
        for caption in app.caption
    )


def test_app_success_status_filter_hides_failed_login_alerts():
    app = AppTest.from_file(str(APP_PATH), default_timeout=60)
    app.run()

    status = next(item for item in app.multiselect if item.label == "Status")
    status.set_value(["SUCCESS"]).run()

    assert len(app.exception) == 0
    assert not [
        table
        for table in app.dataframe
        if "alert_id" in list(table.value.columns)
    ]
    assert any(
        "No detected alerts match the current filters" in item.value
        for item in app.markdown
    )
    assert any(
        button.label == "Clear filters" and button.key == "clear_alert_filters"
        for button in app.button
    )


def test_app_reset_filters_restores_full_log_and_alert_views():
    app = AppTest.from_file(str(APP_PATH), default_timeout=60)
    app.run()

    status = next(item for item in app.multiselect if item.label == "Status")
    status.set_value(["SUCCESS"]).run()
    app.button(key="reset_exploration_filters").click().run()

    assert len(app.exception) == 0
    status = next(item for item in app.multiselect if item.label == "Status")
    assert status.value == ["SUCCESS", "FAILED"]

    log_table = next(
        table
        for table in app.dataframe
        if "source_row" in list(table.value.columns)
        and len(table.value) == 12
    )
    assert len(log_table.value) == 12
    alert_table = next(
        table
        for table in app.dataframe
        if "alert_id" in list(table.value.columns)
    )
    assert len(alert_table.value) == 3
