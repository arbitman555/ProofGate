"""Selecting a demo report must replace the report text area (no live audits)."""

import proofgate.app as app


class _Box:
    def markdown(self, *args, **kwargs):
        pass


class _FakeSt:
    def __init__(self, report_choice):
        self.session_state = {}
        self.writes = []
        self.report_selectbox_kwargs = None
        self._report_choice = report_choice

    def subheader(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def write(self, *args, **kwargs):
        self.writes.append(" ".join(str(a) for a in args))

    def empty(self):
        return _Box()

    def text_input(self, label, value="", *args, **kwargs):
        return value

    def toggle(self, label, value=False, *args, **kwargs):
        return False

    def button(self, *args, **kwargs):
        return False

    def text_area(self, label, key=None, height=None, *args, **kwargs):
        return self.session_state.get(key, "")

    def selectbox(self, label, options, key=None, on_change=None, *args, **kwargs):
        if "demo/reports" in str(label):
            self.report_selectbox_kwargs = {
                "key": key,
                "on_change": on_change,
                "options": list(options),
            }
            self.session_state[key] = self._report_choice
            return self._report_choice
        return options[0] if options else None


def _install_fake(monkeypatch, tmp_path, report_choice):
    (tmp_path / "02_report.md").write_text("old avatar content", encoding="utf-8")
    (tmp_path / "06_report.md").write_text("new sqli content", encoding="utf-8")
    (tmp_path / "runs").mkdir(exist_ok=True)
    monkeypatch.setattr(app, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(app, "RUNS_DEMO", tmp_path / "runs")
    fake = _FakeSt(report_choice)
    monkeypatch.setattr(app, "st", fake)
    return fake


def test_changing_dropdown_replaces_text_area(monkeypatch, tmp_path):
    """Bug scenario: text area holds report 02, user picks 06 -> gets 06."""
    fake = _install_fake(monkeypatch, tmp_path, "02_report.md")
    app.audit_tab()

    on_change = fake.report_selectbox_kwargs["on_change"]
    assert on_change is not None
    assert fake.report_selectbox_kwargs["key"] == "pg_report_choice"
    assert fake.session_state.get("pg_report_choice") == "02_report.md"

    # Simulate the user having report 02 loaded, then picking report 06.
    fake.session_state["pg_text"] = "old avatar content"
    fake.session_state["pg_report_choice"] = "06_report.md"
    on_change()
    assert fake.session_state["pg_text"] == "new sqli content"


def test_auditing_label_shows_selected_filename(monkeypatch, tmp_path):
    fake = _install_fake(monkeypatch, tmp_path, "06_report.md")
    app.audit_tab()
    assert any("Auditing: 06_report.md" in w for w in fake.writes)


def test_no_auditing_label_for_paste_option(monkeypatch, tmp_path):
    fake = _install_fake(monkeypatch, tmp_path, "(paste below)")
    app.audit_tab()
    assert not any("Auditing:" in w for w in fake.writes)
