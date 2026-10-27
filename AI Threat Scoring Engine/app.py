from llm_analysis import generate_analyst_summary
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import html
import json
import sqlite3

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from scorer import score_threat
from predict_threat import predict_threat

st.set_page_config(
    page_title="AI Threat Scoring Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_FILE = BASE_DIR / "sample_logs.csv"
DB_FILE = BASE_DIR / "threat_history.db"

REQUIRED_COLUMNS = [
    "event_id",
    "unusual_country",
    "unknown_ip",
    "failed_attempts",
    "unusual_time",
    "success_after_failures"
]

BOOLEAN_COLUMNS = [
    "unusual_country",
    "unknown_ip",
    "unusual_time",
    "success_after_failures"
]

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
STATUSES = ["New", "Investigating", "Escalated", "Resolved", "False Positive"]

INDICATORS = [
    ("Unknown IP", "Unknown IP"),
    ("Unusual Country", "Unusual Country"),
    ("Unusual Time", "Unusual Time"),
    ("Success After Failures", "Success After Failures")
]

SEVERITY_COLORS = {
    "Critical": "#FF5365",
    "High": "#FF9A45",
    "Medium": "#F5C451",
    "Low": "#35B7FF"
}

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --bg:#040B15;
    --panel:#091827;
    --border:#29475F;
    --blue:#43BFFF;
    --cyan:#9BDEFF;
    --silver:#E5EAF1;
    --muted:#B6C4D2;
    --green:#35E39B;
    --red:#FF5365;
}

.stApp {
    background:radial-gradient(ellipse at 70% 0%,#122B43 0%,transparent 42%),var(--bg);
    color:var(--silver);
    font-family:Inter,Arial,sans-serif;
}

[data-testid="stHeader"] {background:transparent;}
[data-testid="stSidebar"] {
    background:linear-gradient(180deg,#091B2D,#040C17);
    border-right:1px solid var(--border);
}

h1,h2,h3 {color:var(--silver)!important;font-weight:750!important;}
p,label,[data-testid="stCaptionContainer"] {color:var(--muted);}
hr {border-color:var(--border);}

[data-testid="stMetric"] {
    background:linear-gradient(145deg,#10263B,#081523);
    border:1px solid #31516C;
    border-radius:12px;
    padding:14px;
}
[data-testid="stMetricLabel"] {
    color:#D8E2EC!important;
    font-size:.78rem!important;
    font-weight:650!important;
}
[data-testid="stMetricValue"] {
    color:var(--cyan)!important;
    font-weight:800!important;
}

[data-baseweb="select"]>div,
[data-baseweb="input"]>div,
[data-baseweb="textarea"]>div {
    background:#0A1A2B;
    border-color:#34516A;
    border-radius:7px;
}

[data-testid="stDataFrame"] {
    border:1px solid var(--border);
    border-radius:9px;
}

[data-testid="stFileUploader"] {
    background:#091A2B;
    border:1px dashed #4387B4;
    border-radius:10px;
}

div.stButton>button,div.stDownloadButton>button {
    background:linear-gradient(100deg,#103A5B,#14547B);
    color:#F3F8FF;
    border:1px solid #4389B7;
    border-radius:8px;
    font-weight:650;
}
div.stButton>button:hover,div.stDownloadButton>button:hover {
    background:#176493;
    border-color:var(--cyan);
    color:white;
}

.hero {
    background:linear-gradient(110deg,#0C2035,#071321 80%);
    border:1px solid #35536C;
    border-radius:13px;
    padding:22px 24px;
    margin-bottom:14px;
    position:relative;
}
.hero:before {
    content:"";
    position:absolute;
    top:0;left:0;width:4px;height:100%;
    background:linear-gradient(#E5EAF1,#37B9FF);
}
.hero-title {
    color:#E9EDF3;
    font-size:clamp(1.35rem,2.5vw,2.3rem);
    font-weight:800;
    letter-spacing:.5px;
    line-height:1.3;
}
.hero-credit {color:#D5DDE7;font-size:1.05rem;margin-top:7px;}
.hero-credit span {color:#64C9FF;font-weight:750;}
.hero-subtitle {color:#C1CEDB;font-size:.83rem;line-height:1.7;margin-top:9px;}

.section-label {
    color:#A5DFFF;
    font-size:.76rem;
    font-weight:800;
    letter-spacing:1.2px;
    margin:10px 0 13px;
    text-transform:uppercase;
}

.panel {
    background:linear-gradient(145deg,#0B1D30,#061321);
    border:1px solid var(--border);
    border-radius:11px;
    padding:15px;
    margin-bottom:10px;
}
.panel-title {
    color:#B9DFFF;
    font-size:.8rem;
    font-weight:800;
    letter-spacing:.65px;
    margin-bottom:12px;
}

.detail-box {
    background:#081725;
    border:1px solid #28445D;
    border-radius:9px;
    padding:12px;
    margin-bottom:9px;
}
.status-good {color:#35E39B;font-weight:750;}
.status-bad {color:#FF6475;font-weight:750;}
.status-warn {color:#F5C451;font-weight:750;}
.small-muted {color:#B6C4D2;font-size:.78rem;line-height:1.65;}

.footer {
    text-align:center;
    border-top:1px solid #294157;
    padding:17px 0 6px;
    margin-top:20px;
    color:#B6C4D2;
    font-size:.75rem;
}
.footer span {color:#8BD7FF;font-weight:750;}
</style>
""", unsafe_allow_html=True)


def connect_db():
    connection = sqlite3.connect(str(DB_FILE), timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_db():
    with connect_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                run_id TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                score REAL NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL,
                evidence TEXT NOT NULL,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                analyst_notes TEXT NOT NULL DEFAULT ''
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_event_id
            ON alerts(event_id)
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_analyzed_at
            ON alerts(analyzed_at)
        """)


def normalize_boolean(value, column):
    if isinstance(value, str):
        value = value.strip().lower()
        if value in ("true", "false"):
            return value == "true"

    elif isinstance(value, bool):
        return value

    elif type(value).__name__ == "bool_":
        return bool(value)

    elif isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)

    raise ValueError(f"Invalid Boolean Value In {column}: {value!r}")


def normalize_event(row):
    event = row.to_dict()

    for column in BOOLEAN_COLUMNS:
        event[column] = normalize_boolean(event[column], column)

    attempts = pd.to_numeric(
        pd.Series([event["failed_attempts"]]),
        errors="coerce"
    ).iloc[0]

    if pd.isna(attempts) or attempts < 0 or attempts % 1 != 0:
        raise ValueError("Failed Attempts Must Be A Non-Negative Integer.")

    event["failed_attempts"] = int(attempts)

    for column in REQUIRED_COLUMNS:
        if column != "event_id" and pd.isna(event[column]):
            raise ValueError(f"Missing Value In {column}.")

    event_id = str(event["event_id"]).strip()

    if not event_id or event_id.lower() == "nan":
        raise ValueError("Event ID Cannot Be Empty.")

    event["event_id"] = event_id
    return event


def normalize_confidence(value):
    try:
        number = float(value)

        if 0 <= number <= 1:
            return number

        if 0 <= number <= 100:
            return number / 100

    except (TypeError, ValueError):
        pass

    return None


def confidence_text(value):
    confidence = normalize_confidence(value)
    return f"{confidence:.1%}" if confidence is not None else "Unavailable"


def make_fingerprint(alert):
    event_json = json.dumps(
        alert["Event Data"],
        default=str,
        sort_keys=True
    )

    fingerprint_data = json.dumps({
        "event_id": alert["Event ID"],
        "event_data": event_json,
        "score": alert["Score"],
        "severity": alert["Severity"],
        "prediction": alert["ML Prediction"]
    }, sort_keys=True)

    return hashlib.sha256(
        fingerprint_data.encode("utf-8")
    ).hexdigest()


def analyze_dataframe(data):
    missing = [
        column for column in REQUIRED_COLUMNS
        if column not in data.columns
    ]

    if missing:
        raise ValueError("Missing Required Columns: " + ", ".join(missing))

    if data.empty:
        raise ValueError("The CSV Contains No Events.")

    results = []
    errors = []

    for index, row in data.iterrows():
        try:
            event = normalize_event(row)
            rule = score_threat(event)
            ml = predict_threat(event)

            severity = str(rule["severity"]).strip().title()
            prediction = str(ml["prediction"]).strip().title()

            if severity not in SEVERITY_ORDER:
                raise ValueError(f"Unexpected Severity: {severity}")

            if prediction not in ("Benign", "Suspicious"):
                raise ValueError(f"Unexpected ML Prediction: {prediction}")

            score = float(rule["score"])

            if not 0 <= score <= 100:
                raise ValueError("Rule Score Must Be Between 0 And 100.")

            evidence = [
                str(reason) for reason in rule.get("reasons", [])
            ]

            alert = {
                "Event ID": event["event_id"],
                "Score": score,
                "Severity": severity,
                "ML Prediction": prediction,
                "ML Confidence": normalize_confidence(ml.get("confidence")),
                "Detection Evidence": evidence,
                "Failed Attempts": event["failed_attempts"],
                "Unknown IP": event["unknown_ip"],
                "Unusual Country": event["unusual_country"],
                "Unusual Time": event["unusual_time"],
                "Success After Failures": event["success_after_failures"],
                "Event Data": event
            }

            alert["Fingerprint"] = make_fingerprint(alert)
            results.append(alert)

        except Exception as exc:
            errors.append(f"Row {index + 2}: {exc}")

    result = pd.DataFrame(results)

    if not result.empty:
        result["_priority"] = result["Severity"].map({
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1
        })

        result = result.sort_values(
            ["_priority", "Score"],
            ascending=[False, False]
        ).drop(columns="_priority").reset_index(drop=True)

    return result, errors


def save_alerts(alerts, run_id):
    saved = 0
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with connect_db() as connection:
        for _, alert in alerts.iterrows():
            event_json = json.dumps(
                alert["Event Data"],
                default=str,
                sort_keys=True
            )

            cursor = connection.execute("""
                INSERT OR IGNORE INTO alerts (
                    event_id, fingerprint, run_id, analyzed_at,
                    severity, score, prediction, confidence,
                    evidence, event_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["Event ID"],
                alert["Fingerprint"],
                run_id,
                now,
                alert["Severity"],
                alert["Score"],
                alert["ML Prediction"],
                alert["ML Confidence"],
                json.dumps(alert["Detection Evidence"]),
                event_json
            ))

            saved += cursor.rowcount

    return saved


def load_history():
    with connect_db() as connection:
        rows = connection.execute("""
            SELECT * FROM alerts
            ORDER BY analyzed_at DESC, id DESC
        """).fetchall()

    return pd.DataFrame([dict(row) for row in rows])


def update_case(alert_id, status, notes):
    with connect_db() as connection:
        connection.execute("""
            UPDATE alerts
            SET status = ?, analyst_notes = ?
            WHERE id = ?
        """, (status, notes, int(alert_id)))


def clear_history():
    with connect_db() as connection:
        connection.execute("DELETE FROM alerts")


def chart_html(alerts):
    counts = alerts["Severity"].value_counts().to_dict()
    maximum = max([counts.get(s, 0) for s in SEVERITY_ORDER] + [1])
    bars = ""

    for severity in SEVERITY_ORDER:
        count = counts.get(severity, 0)
        height = max(4, count / maximum * 100)
        color = SEVERITY_COLORS[severity]

        bars += f"""
        <div style="flex:1;height:155px;min-width:0;display:flex;
                    flex-direction:column;align-items:center;justify-content:flex-end;">
            <div style="font-size:11px;color:#E1E8F0;margin-bottom:5px;">{count}</div>
            <div style="width:55%;height:{height}%;min-height:4px;
                background:linear-gradient(180deg,{color},{color}99);
                border-radius:3px 3px 0 0;"></div>
            <div style="font-size:10px;color:#D2DCE7;margin-top:7px;">{severity}</div>
        </div>
        """

    predictions = alerts["ML Prediction"].value_counts().to_dict()
    benign = predictions.get("Benign", 0)
    suspicious = predictions.get("Suspicious", 0)
    total = len(alerts)
    benign_pct = benign / total * 100 if total else 0

    return f"""
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;
                font-family:Inter,Arial,sans-serif;">
        <div style="background:linear-gradient(145deg,#0B1D30,#061321);
                    border:1px solid #29455E;border-radius:11px;padding:15px;">
            <div style="color:#B9DFFF;font-size:12px;font-weight:800;
                        margin-bottom:8px;">⬡ ALERTS BY SEVERITY</div>
            <div style="display:flex;align-items:flex-end;gap:9px;
                        border-bottom:1px solid #29445B;padding:0 8px;">
                {bars}
            </div>
        </div>
        <div style="background:linear-gradient(145deg,#0B1D30,#061321);
                    border:1px solid #29455E;border-radius:11px;padding:15px;">
            <div style="color:#B9DFFF;font-size:12px;font-weight:800;margin-bottom:8px;">
                ◉ ML PREDICTION BREAKDOWN
            </div>
            <div style="display:flex;align-items:center;justify-content:center;
                        gap:20px;min-height:165px;flex-wrap:wrap;">
                <div style="width:122px;height:122px;border-radius:50%;
                    background:conic-gradient(#168FF0 0% {benign_pct}%,
                    #FF4658 {benign_pct}% 100%);
                    display:flex;align-items:center;justify-content:center;">
                    <div style="width:78px;height:78px;border-radius:50%;
                        background:#081827;display:flex;flex-direction:column;
                        align-items:center;justify-content:center;">
                        <div style="color:#F0F4F8;font-size:22px;font-weight:800;">{total}</div>
                        <div style="color:#B5C4D4;font-size:10px;">Total</div>
                    </div>
                </div>
                <div style="font-size:12px;color:#D5DFE9;line-height:1.9;">
                    <div><span style="color:#168FF0;">●</span> Benign</div>
                    <div style="padding-left:12px;">{benign} ({benign_pct:.1f}%)</div>
                    <div><span style="color:#FF4658;">●</span> Suspicious</div>
                    <div style="padding-left:12px;">{suspicious} ({100-benign_pct:.1f}%)</div>
                </div>
            </div>
        </div>
    </div>
    """


def indicator(value):
    return "✓" if bool(value) else "✕"


def display_alert_table(data):
    if data.empty:
        st.info("No Alerts Match The Current Filters.")
        return

    shown = data[[
        "Event ID",
        "Score",
        "Severity",
        "ML Prediction",
        "ML Confidence",
        "Failed Attempts"
    ]].copy()

    shown["ML Confidence"] = shown["ML Confidence"].apply(confidence_text)

    st.dataframe(
        shown,
        use_container_width=True,
        hide_index=True,
        height=min(110 + len(shown) * 38, 380),
        column_config={
            "Event ID": st.column_config.TextColumn(
                "Event ID", width="medium"
            ),
            "Score": st.column_config.NumberColumn(
                "Rule Score", width="small"
            ),
            "Severity": st.column_config.TextColumn(
                "Severity", width="small"
            ),
            "ML Prediction": st.column_config.TextColumn(
                "ML Prediction", width="medium"
            ),
            "ML Confidence": st.column_config.TextColumn(
                "ML Confidence", width="medium"
            ),
            "Failed Attempts": st.column_config.NumberColumn(
                "Failed Attempts", width="medium"
            )
        }
    )

    st.caption("Select An Event Below To Inspect Its Evidence And Indicators.")


def render_header():
    left, right = st.columns([4, 1.15])

    with left:
        st.markdown("""
        <div class="hero">
            <div class="hero-title">AI THREAT SCORING ENGINE</div>
            <div class="hero-credit">By <span>Gavin Polynice</span></div>
            <div class="hero-subtitle">
                Security Event Analysis, Machine Learning Predictions, And Threat Prioritization.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with right:
        st.markdown("""
        <div class="panel" style="min-height:125px;">
            <div class="panel-title">System Status</div>
            <div class="status-good">● Operational</div>
            <div class="small-muted" style="margin-top:12px;">
                Local Analysis Engine<br>Ready For Review
            </div>
        </div>
        """, unsafe_allow_html=True)


def render_footer():
    st.markdown("""
    <div class="footer">
        AI Threat Scoring Engine &nbsp;|&nbsp; Developed By
        <span>Gavin Polynice</span><br>
        Local Prototype &nbsp;|&nbsp; Human Review Required
    </div>
    """, unsafe_allow_html=True)


try:
    initialize_db()
except sqlite3.Error as exc:
    st.error(f"Unable To Initialize The Local Database: {exc}")
    st.stop()


st.sidebar.markdown("""
<div style="padding:8px 2px 17px;border-bottom:1px solid #23415C;margin-bottom:14px;">
    <div style="color:#E5EAF1;font-size:1.05rem;font-weight:800;">
        🛡️ THREAT ENGINE
    </div>
    <div style="color:#69CCFF;font-size:.67rem;letter-spacing:.6px;margin-top:5px;">
        SECURITY ANALYSIS PLATFORM
    </div>
</div>
""", unsafe_allow_html=True)

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Alert Investigation",
        "Event History",
        "Reports",
        "Model Evaluation",
        "Settings"
    ],
    label_visibility="collapsed"
)

st.sidebar.divider()
st.sidebar.markdown(
    '<div class="section-label">Data Source</div>',
    unsafe_allow_html=True
)

uploaded_file = st.sidebar.file_uploader(
    "Upload Security Logs",
    type=["csv"]
)

try:
    if uploaded_file:
        source_data = pd.read_csv(uploaded_file)
        source_name = uploaded_file.name
    else:
        source_data = pd.read_csv(SAMPLE_FILE)
        source_name = SAMPLE_FILE.name

    alerts, errors = analyze_dataframe(source_data)

except Exception as exc:
    st.error(f"Unable To Load Or Analyze Events: {exc}")
    st.stop()


st.sidebar.markdown(f"""
<div class="detail-box">
    <div class="small-muted">Current Source</div>
    <div style="color:#76D1FF;font-size:12px;overflow-wrap:anywhere;margin-top:5px;">
        {html.escape(source_name)}
    </div>
    <div class="small-muted" style="margin-top:12px;">Rows Received</div>
    <div style="color:#76D1FF;font-size:17px;font-weight:800;margin-top:4px;">
        {len(source_data)}
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.caption("Alerts Are Stored Locally In SQLite.")

source_signature = hashlib.sha256(
    (
        source_name
        + source_data.to_csv(index=True)
    ).encode("utf-8")
).hexdigest()

if st.session_state.get("saved_source_signature") != source_signature:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

    try:
        saved_count = save_alerts(alerts, run_id) if not alerts.empty else 0
        st.session_state["last_saved_count"] = saved_count
        st.session_state["saved_source_signature"] = source_signature
        st.session_state["run_id"] = run_id
    except sqlite3.Error as exc:
        st.error(f"Unable To Save Alert History: {exc}")

for error in errors:
    st.warning(error)

try:
    history = load_history()
except sqlite3.Error as exc:
    st.error(f"Unable To Read Historical Records: {exc}")
    st.stop()


if page == "Dashboard":
    render_header()

    st.markdown(
        '<div class="section-label">Security Overview</div>',
        unsafe_allow_html=True
    )

    total = len(source_data)
    analyzed = len(alerts)

    suspicious_count = (
        alerts["ML Prediction"].eq("Suspicious").sum()
        if not alerts.empty else 0
    )

    high_count = (
        alerts["Severity"].isin(["High", "Critical"]).sum()
        if not alerts.empty else 0
    )

    metrics = st.columns(4)

    metric_items = [
        ("▤", "TOTAL EVENTS", total, False),
        ("✓", "EVENTS ANALYZED", analyzed, False),
        ("◉", "ML SUSPICIOUS", int(suspicious_count), False),
        ("⚠", "HIGH / CRITICAL", int(high_count), True)
    ]

    for col, (symbol, label, value, danger) in zip(metrics, metric_items):
        color = "#FF5365" if danger else "#43BFFF"
        border = "#853442" if danger else "#31516C"

        background = (
            "linear-gradient(145deg,#29151D,#110D16)"
            if danger else
            "linear-gradient(145deg,#10263B,#081523)"
        )

        with col:
            st.markdown(f"""
            <div style="height:110px;box-sizing:border-box;padding:14px;
                display:flex;align-items:center;gap:12px;border-radius:12px;
                border:1px solid {border};background:{background};">
                <div style="width:43px;height:43px;min-width:43px;border-radius:50%;
                    display:flex;align-items:center;justify-content:center;
                    border:1px solid {color};color:{color};font-size:21px;">
                    {symbol}
                </div>
                <div style="min-width:0;">
                    <div style="color:#D8E2EC;font-size:.69rem;font-weight:750;
                        letter-spacing:.3px;line-height:1.4;">{label}</div>
                    <div style="color:{color};font-size:1.8rem;font-weight:800;
                        margin-top:5px;">{value}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    if not alerts.empty:
        components.html(chart_html(alerts), height=225, scrolling=False)

        st.markdown(
            '<div class="section-label">Priority Alerts</div>',
            unsafe_allow_html=True
        )

        priority = alerts[
            alerts["Severity"].isin(["Critical", "High"])
        ].head(8)

        display_alert_table(priority)

        st.markdown(
            '<div class="section-label">Recent Activity</div>',
            unsafe_allow_html=True
        )

        if not history.empty:
            st.dataframe(
                history[[
                    "analyzed_at", "event_id", "severity",
                    "score", "prediction", "status"
                ]].head(8),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No Historical Activity Has Been Recorded Yet.")

    else:
        st.info("No Events Were Successfully Analyzed.")

    st.caption(f"Source: {source_name} · Rows Received: {total}")
    render_footer()


elif page == "Alert Investigation":
    render_header()
    st.title("Alert Investigation")
    st.caption(
        "Review Evidence, Inspect Event Indicators, And Document Investigation Outcomes."
    )

    if alerts.empty:
        st.info("No Alerts Are Available.")

    else:
        f1, f2, f3 = st.columns([1, 1, 1.3])

        with f1:
            severity_filter = st.multiselect(
                "Severity",
                SEVERITY_ORDER,
                default=SEVERITY_ORDER
            )

        with f2:
            prediction_filter = st.multiselect(
                "ML Prediction",
                ["Benign", "Suspicious"],
                default=["Benign", "Suspicious"]
            )

        with f3:
            search_term = st.text_input(
                "Search Event ID",
                placeholder="Enter An Event ID"
            )

        filtered = alerts[
            alerts["Severity"].isin(severity_filter)
            & alerts["ML Prediction"].isin(prediction_filter)
        ]

        if search_term.strip():
            filtered = filtered[
                filtered["Event ID"].str.contains(
                    search_term.strip(),
                    case=False,
                    na=False
                )
            ]

        st.caption(f"Showing {len(filtered)} Matching Events")
        display_alert_table(filtered)

        if not filtered.empty:
            st.divider()

            selected_fingerprint = st.selectbox(
                "Select Event For Investigation",
                filtered["Fingerprint"].tolist(),
                format_func=lambda fingerprint: filtered.loc[
                    filtered["Fingerprint"].eq(fingerprint), "Event ID"
                ].iloc[0]
            )

            selected = filtered[
                filtered["Fingerprint"] == selected_fingerprint
            ].iloc[0]

            detail_col, case_col = st.columns([1, 1])

            with detail_col:
                st.subheader(f"Event: {selected['Event ID']}")

                a, b, c = st.columns(3)
                a.metric("Rule Score", selected["Score"])
                b.metric("Severity", selected["Severity"])
                c.metric("ML Prediction", selected["ML Prediction"])

                st.markdown("**Detection Evidence**")

                if selected["Detection Evidence"]:
                    for reason in selected["Detection Evidence"]:
                        st.markdown(f"- {reason}")
                else:
                    st.caption("No Detection Reasons Were Returned.")

                st.markdown("**Event Indicators**")

                for label, column in INDICATORS:
                    value = bool(selected[column])
                    symbol = "✓" if value else "✕"
                    css = "status-good" if value else "status-bad"

                    st.markdown(
                        f'<div style="display:flex;justify-content:space-between;'
                        f'padding:7px 0;border-bottom:1px solid #1A3043;">'
                        f'<span>{label}</span>'
                        f'<span class="{css}">{symbol}</span></div>',
                        unsafe_allow_html=True
                    )

                st.write(f"Failed Attempts: **{selected['Failed Attempts']}**")
                st.metric(
                    "Model Confidence",
                    confidence_text(selected["ML Confidence"])
                )

                st.caption(
                    "Model confidence is not proof that an attack occurred."
                )

            with case_col:
                st.subheader("Case Management")

                matching = history[
                    history["fingerprint"] == selected["Fingerprint"]
                ]

                if not matching.empty:
                    saved_record = matching.iloc[0]
                    record_id = int(saved_record["id"])
                    old_status = saved_record["status"]
                    old_notes = saved_record["analyst_notes"]
                else:
                    record_id = None
                    old_status = "New"
                    old_notes = ""

                status_index = (
                    STATUSES.index(old_status)
                    if old_status in STATUSES else 0
                )

                case_status = st.selectbox(
                    "Investigation Status",
                    STATUSES,
                    index=status_index,
                    key=f"status_{selected['Fingerprint']}"
                )

                case_notes = st.text_area(
                    "Analyst Notes",
                    value=old_notes,
                    height=150,
                    placeholder="Document Evidence, Findings, And Follow-Up Actions.",
                    key=f"notes_{selected['Fingerprint']}"
                )

                if st.button(
                    "Save Investigation",
                    use_container_width=True
                ):
                    if record_id is None:
                        st.warning(
                            "This Alert Has Not Been Saved To History. "
                            "Check Database Status And Reload The Page."
                        )
                    else:
                        try:
                            update_case(record_id, case_status, case_notes)
                            st.success("Investigation Notes And Status Saved.")
                            st.rerun()
                        except sqlite3.Error as exc:
                            st.error(f"Unable To Save Investigation: {exc}")

                if selected["Severity"] in ["Critical", "High"]:
                    st.error("Priority Review Recommended.")
                elif selected["Severity"] == "Medium":
                    st.warning("Further Investigation May Be Appropriate.")
                else:
                    st.info("Review The Event In Context.")

    render_footer()


elif page == "Event History":
    render_header()
    st.title("Event History")
    st.caption("Persistent Alert Records Stored In The Local SQLite Database.")

    history = load_history()

    if history.empty:
        st.info("No Historical Events Have Been Recorded Yet.")

    else:
        h1, h2, h3 = st.columns(3)

        h1.metric("Stored Records", len(history))

        h2.metric(
            "Open Cases",
            int(history["status"].isin([
                "New", "Investigating", "Escalated"
            ]).sum())
        )

        h3.metric(
            "Resolved Cases",
            int(history["status"].eq("Resolved").sum())
        )

        severity_filter = st.multiselect(
            "Filter Historical Severity",
            SEVERITY_ORDER,
            default=SEVERITY_ORDER
        )

        status_filter = st.multiselect(
            "Filter Investigation Status",
            STATUSES,
            default=STATUSES
        )

        search_term = st.text_input("Search Historical Event IDs")

        filtered_history = history[
            history["severity"].isin(severity_filter)
            & history["status"].isin(status_filter)
        ]

        if search_term.strip():
            filtered_history = filtered_history[
                filtered_history["event_id"].str.contains(
                    search_term.strip(),
                    case=False,
                    na=False
                )
            ]

        st.dataframe(
            filtered_history[[
                "analyzed_at",
                "event_id",
                "severity",
                "score",
                "prediction",
                "confidence",
                "status",
                "analyst_notes"
            ]],
            use_container_width=True,
            hide_index=True,
            height=min(120 + len(filtered_history) * 38, 500)
        )

        st.download_button(
            "Export Historical Records",
            filtered_history.to_csv(index=False).encode("utf-8"),
            "threat_event_history.csv",
            "text/csv"
        )

    render_footer()


elif page == "Reports":
    render_header()
    st.title("Reports")
    st.caption("Generate Downloadable Summaries Of Analyzed Events And Investigations.")

    history = load_history()

    if alerts.empty and history.empty:
        st.info("No Data Is Available To Report.")

    else:
        report_source = st.radio(
            "Report Data",
            ["Current Analysis", "Historical Records"],
            horizontal=True
        )

        if report_source == "Current Analysis" and not alerts.empty:
            report = alerts.drop(
                columns=["Event Data", "Fingerprint"]
            ).copy()

            report["Detection Evidence"] = report[
                "Detection Evidence"
            ].apply(lambda items: "; ".join(items))

        elif not history.empty:
            report = history.copy()

        else:
            report = pd.DataFrame()

        if not report.empty:
            prediction_column = (
                "ML Prediction" if "ML Prediction" in report.columns
                else "prediction" if "prediction" in report.columns
                else None
            )

            severity_column = (
                "Severity" if "Severity" in report.columns
                else "severity" if "severity" in report.columns
                else None
            )

            score_column = (
                "Score" if "Score" in report.columns
                else "score" if "score" in report.columns
                else None
            )

            suspicious_total = (
                int(report[prediction_column].eq("Suspicious").sum())
                if prediction_column else 0
            )

            high_total = (
                int(report[severity_column].isin(["High", "Critical"]).sum())
                if severity_column else 0
            )

            average_score = (
                float(pd.to_numeric(
                    report[score_column], errors="coerce"
                ).mean())
                if score_column and report[score_column].notna().any()
                else 0
            )

            r1, r2, r3 = st.columns(3)
            r1.metric("Records In Report", len(report))
            r2.metric("Suspicious Predictions", suspicious_total)
            r3.metric("High / Critical Alerts", high_total)

            st.metric("Average Rule Score", round(average_score, 2))

            st.dataframe(
                report.head(100),
                use_container_width=True,
                hide_index=True
            )

            st.download_button(
                "Download Report As CSV",
                report.to_csv(index=False).encode("utf-8"),
                "threat_analysis_report.csv",
                "text/csv",
                use_container_width=True
            )

            st.caption(
                "Reports Summarize Model And Rule Outputs; They Do Not Confirm Attacks."
            )

        else:
            st.info("Choose A Data Source With Available Records.")

    render_footer()


elif page == "Model Evaluation":
    render_header()
    st.title("Model Evaluation")
    st.caption("Evaluate Predictions Against Known Labels In A Separate Test Dataset.")

    st.warning(
        "Use held-out test data that was not used to train the model. "
        "Training-set results can overstate real-world performance."
    )

    test_file = st.file_uploader(
        "Upload Labeled Test Dataset",
        type=["csv"],
        key="evaluation_upload"
    )

    if test_file:
        try:
            test_data = pd.read_csv(test_file)

            label_candidates = [
                column for column in test_data.columns
                if column.strip().lower() in [
                    "label",
                    "target",
                    "actual",
                    "ground_truth",
                    "classification"
                ]
            ]

            if not label_candidates:
                st.error(
                    "The Test CSV Must Include A Label, Target, Actual, "
                    "Ground_Truth, Or Classification Column."
                )

            else:
                label_column = st.selectbox(
                    "Ground-Truth Label Column",
                    label_candidates
                )

                label_map = {
                    "benign": "Benign",
                    "normal": "Benign",
                    "0": "Benign",
                    "suspicious": "Suspicious",
                    "malicious": "Suspicious",
                    "attack": "Suspicious",
                    "1": "Suspicious"
                }

                actual = (
                    test_data[label_column]
                    .astype(str)
                    .str.strip()
                    .str.lower()
                    .map(label_map)
                )

                valid = actual.notna()
                test_data = test_data.loc[valid].copy()
                actual = actual.loc[valid]

                if test_data.empty:
                    st.error("No Recognized Ground-Truth Labels Were Found.")

                else:
                    missing_features = [
                        column for column in REQUIRED_COLUMNS
                        if column not in test_data.columns
                    ]

                    if missing_features:
                        st.error(
                            "Missing Required Features: "
                            + ", ".join(missing_features)
                        )

                    else:
                        predictions = []
                        failures = []

                        for index, row in test_data.iterrows():
                            try:
                                event_row = row.drop(
                                    labels=[label_column],
                                    errors="ignore"
                                )

                                event = normalize_event(event_row)
                                prediction = predict_threat(event)["prediction"]

                                predictions.append(
                                    str(prediction).strip().title()
                                )

                            except Exception as exc:
                                predictions.append("Error")
                                failures.append(
                                    f"Row {index + 2}: {exc}"
                                )

                        evaluation = pd.DataFrame({
                            "Actual": actual.values,
                            "Predicted": predictions
                        })

                        evaluation = evaluation[
                            evaluation["Predicted"].isin([
                                "Benign", "Suspicious"
                            ])
                        ]

                        if evaluation.empty:
                            st.error("No Test Rows Could Be Predicted.")

                        else:
                            from sklearn.metrics import (
                                accuracy_score,
                                precision_score,
                                recall_score,
                                f1_score,
                                confusion_matrix,
                                classification_report
                            )

                            y_true = evaluation["Actual"]
                            y_pred = evaluation["Predicted"]

                            accuracy = accuracy_score(y_true, y_pred)

                            precision = precision_score(
                                y_true,
                                y_pred,
                                pos_label="Suspicious",
                                zero_division=0
                            )

                            recall = recall_score(
                                y_true,
                                y_pred,
                                pos_label="Suspicious",
                                zero_division=0
                            )

                            f1 = f1_score(
                                y_true,
                                y_pred,
                                pos_label="Suspicious",
                                zero_division=0
                            )

                            e1, e2, e3, e4 = st.columns(4)
                            e1.metric("Accuracy", f"{accuracy:.1%}")
                            e2.metric("Suspicious Precision", f"{precision:.1%}")
                            e3.metric("Suspicious Recall", f"{recall:.1%}")
                            e4.metric("Suspicious F1", f"{f1:.1%}")

                            st.subheader("Confusion Matrix")

                            matrix = confusion_matrix(
                                y_true,
                                y_pred,
                                labels=["Benign", "Suspicious"]
                            )

                            st.dataframe(
                                pd.DataFrame(
                                    matrix,
                                    index=[
                                        "Actual Benign",
                                        "Actual Suspicious"
                                    ],
                                    columns=[
                                        "Predicted Benign",
                                        "Predicted Suspicious"
                                    ]
                                ),
                                use_container_width=True
                            )

                            st.subheader("Detailed Evaluation")

                            st.code(classification_report(
                                y_true,
                                y_pred,
                                labels=["Benign", "Suspicious"],
                                zero_division=0
                            ))

                            evaluation["Correct"] = (
                                evaluation["Actual"] == evaluation["Predicted"]
                            )

                            st.dataframe(
                                evaluation,
                                use_container_width=True,
                                hide_index=True
                            )

                            st.download_button(
                                "Download Evaluation Results",
                                evaluation.to_csv(index=False).encode("utf-8"),
                                "model_evaluation_results.csv",
                                "text/csv"
                            )

                            for failure in failures:
                                st.warning(failure)

                            st.caption(
                                f"Evaluation Used {len(evaluation)} Successfully "
                                "Predicted Rows. Results Apply To This Test Dataset."
                            )

        except Exception as exc:
            st.error(f"Unable To Evaluate Dataset: {exc}")

    render_footer()


elif page == "Settings":
    render_header()
    st.title("Settings")
    st.caption("Application Configuration And Local Data Management.")

    st.subheader("Application Information")

    info1, info2 = st.columns(2)

    info1.markdown(f"**Database Location**  \n`{DB_FILE}`")
    info2.markdown(f"**Sample Dataset**  \n`{SAMPLE_FILE}`")

    history = load_history()
    st.metric("Saved Historical Records", len(history))

    st.subheader("Data Management")

    st.info(
        "Historical Records And Analyst Notes Are Stored In SQLite. "
        "Clearing History Permanently Deletes Saved Records."
    )

    confirmation = st.checkbox(
        "I Understand That Clearing History Permanently Deletes Saved Records."
    )

    if st.button(
        "Clear All Historical Records",
        disabled=not confirmation
    ):
        try:
            clear_history()
            st.success("Historical Records Cleared.")
            st.rerun()
        except sqlite3.Error as exc:
            st.error(f"Unable To Clear History: {exc}")

    st.subheader("Detection Engine")
    st.write("Rule-Based Scoring: Connected")
    st.write("Machine Learning Prediction: Connected")
    st.write("Local Database: Connected")
    st.subheader("AI Analyst Summary")


st.subheader("AI Analyst Summary")

st.caption(
    "Generate an evidence-based explanation for a selected security alert. "
    "The LLM supports investigation; it does not prove an attack occurred."
)

if alerts is None or alerts.empty:
    st.info("Analyze a CSV file to generate alerts before requesting an explanation.")
else:
    alert_options = {}

    for _, row in alerts.iterrows():
        label = (
            f"{row['Event ID']} | {row['Severity']} | "
            f"Score {row['Score']}"
        )
        alert_options[label] = row.to_dict()

    selected_label = st.selectbox(
        "Select an alert to explain",
        options=list(alert_options.keys()),
        key="llm_alert_selector",
    )

    if st.button("Generate AI Analyst Summary", key="generate_llm_summary"):
        selected_alert = alert_options[selected_label]

        with st.spinner("Generating explanation with local Ollama model..."):
            llm_result = generate_analyst_summary(selected_alert)

        if llm_result["success"]:
            st.markdown(llm_result["summary"])
        else:
            st.error(llm_result["error"])
        
    st.caption(
        "This Application Does Not Automatically Block Accounts, IP Addresses, "
        "Or Network Traffic. Review Alerts Before Taking Action."
    )

    render_footer()


