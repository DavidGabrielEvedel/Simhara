import json
import tempfile
from pathlib import Path

import streamlit as st

from scanner.code_scanner import scan_python_file
from scanner.ai_analyzer import analyse_finding


st.set_page_config(
    page_title="SIMHARA | Security Terminal",
    page_icon="S",
    layout="wide",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=VT323&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root {
    --bg: #090d0a;
    --panel: #101711;
    --green: #9dff65;
    --yellow: #f2d35e;
    --text: #d5e4d2;
    --muted: #718772;
    --border: #29452b;
    --red: #ff6666;
}

.stApp {
    background: var(--bg);
    color: var(--text);
    font-family: 'IBM Plex Mono', monospace;
}

[data-testid="stHeader"] { background: var(--bg); }

[data-testid="stSidebar"] {
    background: #0c120d;
    border-right: 1px solid var(--border);
}

.block-container {
    max-width: 1500px;
    padding-top: 3rem;
    padding-bottom: 2rem;
}

[data-testid="stHeader"] {
    height: 0;
    background: transparent;
}

[data-testid="stAppViewBlockContainer"] {
    padding-top: 3rem;
}

h1, h2, h3, p, label, li {
    font-family: 'IBM Plex Mono', monospace !important;
}

h1 {
    color: var(--green) !important;
    font-family: 'VT323', monospace !important;
    font-size: 2.8rem !important;
    font-weight: 400 !important;
    letter-spacing: 0.08rem;
    line-height: 1.2 !important;
}

h2, h3 { color: var(--yellow) !important; }

p, label, li { color: var(--text); }

code, pre, .stCode {
    font-family: 'IBM Plex Mono', monospace !important;
}

.terminal-title {
    font-family: 'VT323', monospace;
    font-size: 3.2rem;
    line-height: 1.15;
    letter-spacing: 0.12rem;
    color: var(--green);
    padding-top: 0.2rem;
}

.terminal-subtitle {
    color: var(--muted);
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.06rem;
    line-height: 1.6;
    padding-top: 0.2rem;
    padding-bottom: 0.3rem;
    overflow: visible;
}

.section {
    color: var(--yellow);
    font-size: 0.78rem;
    letter-spacing: 0.12rem;
    margin: 1.2rem 0 0.6rem;
}

.panel {
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 1rem;
}

.stButton > button {
    background: #152319;
    color: var(--green);
    border: 1px solid #477347;
    border-radius: 2px;
    font-family: 'IBM Plex Mono', monospace;
}

.stButton > button:hover {
    background: #203523;
    border-color: var(--green);
    color: var(--green);
}

.stButton > button[kind="primary"] {
    background: var(--green);
    color: #091009;
    border: 1px solid var(--green);
    border-radius: 2px;
}

[data-testid="stMetric"] {
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 0.8rem;
}

[data-testid="stMetricLabel"] {
    color: var(--muted);
}

[data-testid="stMetricValue"] {
    color: var(--green);
    font-family: 'IBM Plex Mono', monospace;
}

[data-testid="stFileUploader"] {
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 0.5rem;
}

[data-testid="stDataFrame"] {
    border: 1px solid var(--border);
}

hr { border-color: var(--border); }

</style>
""", unsafe_allow_html=True)


for key, default in {
    "findings": [],
    "source_text": "",
    "uploaded_name": "",
    "scan_complete": False,
    "analysis": None,
    "analysis_index": None,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


with st.sidebar:
    st.markdown('<div class="terminal-title">SIMHARA</div>', unsafe_allow_html=True)
    st.markdown('<div class="terminal-subtitle">SECURITY OPERATIONS TERMINAL</div>', unsafe_allow_html=True)
    st.divider()

    page = st.radio(
        "NAVIGATION",
        ["Overview", "Source Analysis", "Evaluations"],
    )

    st.divider()
    st.markdown("**SYSTEM CONFIGURATION**")
    st.caption("SCANNER  /  BANDIT")
    st.caption("AI ENGINE / OLLAMA")
    st.caption("MODE     /  LOCAL ANALYSIS")
    st.divider()
    st.caption("AI output requires independent validation.")


st.markdown(
    '<div class="terminal-subtitle">SIMHARA // SECURITY RESEARCH DIVISION</div>',
    unsafe_allow_html=True,
)

st.title(page.upper())


if page == "Overview":
    st.write("Source inspection and AI-assisted vulnerability investigation.")

    findings = st.session_state.findings

    high = sum(f.get("severity") == "HIGH" for f in findings)
    medium = sum(f.get("severity") == "MEDIUM" for f in findings)
    low = sum(f.get("severity") == "LOW" for f in findings)

    a, b, c, d = st.columns(4)
    a.metric("TOTAL FINDINGS", len(findings))
    b.metric("HIGH", high)
    c.metric("MEDIUM", medium)
    d.metric("LOW", low)

    st.markdown('<div class="section">[ CURRENT SESSION ]</div>', unsafe_allow_html=True)

    if st.session_state.scan_complete:
        st.markdown(
            f'<div class="panel">FILE: {st.session_state.uploaded_name}<br>'
            f'FINDINGS: {len(findings)}<br>SCANNER: BANDIT</div>',
            unsafe_allow_html=True,
        )
    else:
        st.info("No completed scan in this session. Open Source Analysis to begin.")


elif page == "Source Analysis":
    st.markdown('<div class="section">[ 01 / SOURCE INPUT ]</div>', unsafe_allow_html=True)

    uploaded = st.file_uploader(
    "Select Python source file",
    type=["py"],
    key="source_upload",
    )

    if uploaded is not None:
     if st.session_state.get("last_uploaded_name") != uploaded.name:
        st.session_state.findings = []
        st.session_state.scan_complete = False
        st.session_state.analysis = None
        st.session_state.analysis_index = None
        st.session_state.last_uploaded_name = uploaded.name

    source = ""

    if uploaded:
        if uploaded.size > 1_048_576:
            st.error("Maximum file size is 1 MB.")
        else:
            try:
                source = uploaded.getvalue().decode("utf-8")
                st.caption(f"FILE: {uploaded.name} | LINES: {len(source.splitlines())}")

                with st.expander("VIEW SOURCE"):
                    st.code(source, language="python")

            except UnicodeDecodeError:
                st.error("File must contain valid UTF-8 text.")

            if st.button(
            "RUN STATIC SCAN",
            type="primary",
            disabled=not source or uploaded is None or uploaded.size > 1_048_576,
        ):
             try:
                with st.spinner("Running Bandit..."):
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / "source.py"
                        path.write_text(source, encoding="utf-8")
                        raw = scan_python_file(path)

                new_findings = [
                    {
                        **finding,
                        "scanner": "Bandit",
                        "file": uploaded.name,
                    }
                    for finding in raw
                ]

                st.session_state.findings = new_findings
                st.session_state.source_text = source
                st.session_state.uploaded_name = uploaded.name
                st.session_state.scan_complete = True
                st.session_state.analysis = None
                st.session_state.analysis_index = None

             except Exception as error:
                st.error("Static scan failed.")
                st.exception(error)

    if st.session_state.scan_complete:
        findings = st.session_state.findings

        st.markdown('<div class="section">[ 02 / SCAN RESULTS ]</div>', unsafe_allow_html=True)

        a, b, c, d = st.columns(4)
        a.metric("FINDINGS", len(findings))
        b.metric("HIGH", sum(f.get("severity") == "HIGH" for f in findings))
        c.metric("MEDIUM", sum(f.get("severity") == "MEDIUM" for f in findings))
        d.metric("LOW", sum(f.get("severity") == "LOW" for f in findings))

        if not findings:
            st.success("No findings reported by Bandit.")
            st.caption("A clean scan does not guarantee secure code.")
        else:
            st.dataframe(
                [
                    {
                        "SCANNER": f.get("scanner"),
                        "RULE": f.get("rule_id"),
                        "SEVERITY": f.get("severity"),
                        "CONFIDENCE": f.get("confidence"),
                        "LOCATION": f"{f.get('file')}:{f.get('line')}",
                        "FINDING": f.get("title"),
                        "CWE": f.get("cwe"),
                    }
                    for f in findings
                ],
                use_container_width=True,
                hide_index=True,
            )

            st.markdown('<div class="section">[ 03 / INVESTIGATION ]</div>', unsafe_allow_html=True)

            labels = [
                f"{f.get('rule_id')} | {f.get('severity')} | LINE {f.get('line')} | {f.get('title')}"
                for f in findings
            ]

            index = st.selectbox(
                "SELECT FINDING",
                range(len(findings)),
                format_func=lambda i: labels[i],
            )

            finding = findings[index]

            left, right = st.columns(2)

            with left:
                st.markdown("### EVIDENCE")
                st.write(finding.get("title"))
                st.caption(
                    f"RULE: {finding.get('rule_id')} | "
                    f"CONFIDENCE: {finding.get('confidence')}"
                )

                lines = st.session_state.source_text.splitlines()
                line = finding.get("line")

                if isinstance(line, int) and 1 <= line <= len(lines):
                    start = max(0, line - 4)
                    end = min(len(lines), line + 3)
                    excerpt = "\n".join(
                     f"{i + 1}: {lines[i]}"
                     for i in range(start, end)
)
                    st.code(excerpt, language="python")
                else:
                    st.warning(f"Invalid scanner line: {line}. Showing full source.")
                    st.code(st.session_state.source_text, language="python")

            with right:
                st.markdown("### AI ANALYSIS")
                st.write("Analyse this finding with the configured local model.")

                if st.button("ANALYSE FINDING", type="primary"):
                    line = finding.get("line")
                    lines = st.session_state.source_text.splitlines()

                    if isinstance(line, int) and line > 0:
                        start = max(0, line - 4)
                        end = min(len(lines), line + 3)
                        context = "\n".join(
                            f"{i+1}: {lines[i]}" for i in range(start, end)
                        )
                    else:
                        context = st.session_state.source_text[:6000]

                    try:
                        with st.spinner("Consulting local model..."):
                            result = analyse_finding(
                                {**finding, "file": st.session_state.uploaded_name},
                                source_context=context,
                            )

                        st.session_state.analysis = result
                        st.session_state.analysis_index = index

                    except Exception as error:
                        st.error("AI analysis failed.")
                        st.code(str(error))

            result = st.session_state.analysis

            if result is not None and st.session_state.analysis_index == index:
                st.divider()
                st.markdown('<div class="section">[ 04 / ANALYSIS REPORT ]</div>', unsafe_allow_html=True)

                for title, key in [
                    ("VULNERABILITY", "vulnerability"),
                    ("EVIDENCE", "evidence"),
                    ("POTENTIAL IMPACT", "impact"),
                    ("REMEDIATION", "remediation"),
                ]:
                    st.markdown(f"### {title}")
                    st.write(result[key])

                st.markdown("### VALIDATION STEPS")
                for number, step in enumerate(result["validation_steps"], 1):
                    st.write(f"{number:02d}  {step}")

                st.markdown("### LIMITATIONS")
                st.write(result["limitations"])

                st.caption("AI-generated recommendations are not verified security fixes.")


elif page == "Evaluations":
    st.markdown('<div class="section">[ MODEL EVALUATION RECORDS ]</div>', unsafe_allow_html=True)

    directory = Path("evaluation_results")
    reports = sorted(
        directory.glob("evaluation_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ) if directory.exists() else []

    if not reports:
        st.info("No saved evaluation reports found.")
    else:
        report = st.selectbox("SELECT REPORT", reports, format_func=lambda p: p.name)

        try:
            st.json(json.loads(report.read_text(encoding="utf-8")))
        except (OSError, ValueError) as error:
            st.error("Could not read evaluation report.")
            st.code(str(error))

        st.caption("Saved model output is not proof of remediation correctness.")


st.divider()
st.markdown(
    '<div class="terminal-subtitle">SIMHARA // STATIC ANALYSIS • LOCAL AI • EVIDENCE-BASED INVESTIGATION</div>',
    unsafe_allow_html=True,
)
