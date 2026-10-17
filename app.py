import json
import tempfile
from pathlib import Path
import pandas as pd
import streamlit as st

from scanner.code_scanner import scan_python_file
from scanner.ai_analyzer import analyse_finding
from scanner.semgrep_scanner import scan_with_semgrep

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
    st.caption("SEMGREP  /  BANDIT")
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
    "Select Source file",
    type=["py", "java", "js", "jsx", "ts", "tsx"],
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
                    suffix=Path(uploaded.name).suffix.lower()
                    language_map={
                        ".py": "python",
                        ".java": "java",
                        ".js": "javascript",
                        ".jsx": "javascript",
                        ".ts": "typescript",
                        ".tsx": "typescript",
                    }
                    st.code(source, language=language_map.get(suffix, "text"))

            except UnicodeDecodeError:
                st.error("File must contain valid UTF-8 text.")

            if st.button(
            "RUN STATIC SCAN",
            type="primary",
            disabled=not source or uploaded is None or uploaded.size > 1_048_576,
        ):
             bandit_findings = []
             semgrep_findings = []
             scanner_errors = []

             with tempfile.TemporaryDirectory() as directory:
                suffix = Path(uploaded.name).suffix.lower()
                path = Path(directory) / f"source{suffix}"
                path.write_bytes(uploaded.getvalue())

    # Python: run Bandit and Semgrep.
    # Java/C/C++: run Semgrep only.
                if suffix == ".py":
                    try:
                        with st.spinner("Running Scanners..."):
                            bandit_raw = scan_python_file(path)

                        bandit_findings = [
                {
                    **finding,
                    "scanner": "Bandit",
                    "file": uploaded.name,
                }
                for finding in bandit_raw
            ]

                    except Exception as error:
                        scanner_errors.append(f"Bandit failed: {error}")

    # Semgrep supports multiple programming languages.
                try:
                    with st.spinner("Running Scanners..."):
                        semgrep_raw = scan_with_semgrep(path)

                    semgrep_findings = [
            {
                **finding,
                "scanner": "Semgrep",
                "file": uploaded.name,
            }
                        for finding in semgrep_raw
        ]

                except Exception as error:
                    scanner_errors.append(f"Semgrep failed: {error}")

             # Combine all successful scanner results
             new_findings = bandit_findings + semgrep_findings

             st.session_state.findings = new_findings
             st.session_state.source_text = source
             st.session_state.uploaded_name = uploaded.name
             
             st.session_state.scan_complete = (
                len(scanner_errors) < 2
            )
             st.session_state.analysis = None
             st.session_state.analysis_index = None

            # Report scanner outcomes
             if suffix == ".py":
                st.success(
                    f"Bandit: {len(bandit_findings)} findings | "
                    f"Semgrep: {len(semgrep_findings)} findings"
                )
             else:
                st.success(
                    f"Semgrep: {len(semgrep_findings)} findings"
                )

             for error in scanner_errors:
                st.error(error)

             if scanner_errors:
                st.warning(
                    "Some scanners failed. Results may be incomplete."
                )

    if st.session_state.scan_complete:
        findings = st.session_state.findings

        st.markdown('<div class="section">[ 02 / SCAN RESULTS ]</div>', unsafe_allow_html=True)

        a, b, c, d = st.columns(4)
        a.metric("FINDINGS", len(findings))
        b.metric("HIGH", sum(f.get("severity") == "HIGH" for f in findings))
        c.metric("MEDIUM", sum(f.get("severity") == "MEDIUM" for f in findings))
        d.metric("LOW", sum(f.get("severity") == "LOW" for f in findings))
        
        st.markdown(
            """
            <style>
            .severity-row {
                display: flex;
                align-items: center;
                gap: 14px;
                margin: 13px 0;
                font-family: 'IBM Plex Mono', monospace;
                font-size: 13px;
            }

            .severity-label {
                width: 85px;
                color: #d5e4d2;
            }

            .severity-track {
                flex: 1;
                height: 12px;
                background: #101711;
                border: 1px solid #29452b;
            }

            .severity-fill {
                height: 100%;
            }

            .severity-count {
                width: 25px;
                text-align: right;
                color: #d5e4d2;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

        max_count = max(
            (sum(f.get("severity") == level for f in findings)
             for level in ["HIGH", "MEDIUM", "LOW"]),
            default=0,
        )

        st.markdown(
            '<div class="section">[ SEVERITY DISTRIBUTION ]</div>',
            unsafe_allow_html=True,
        )

        for level, color in [
            ("HIGH", "#ff6666"),
            ("MEDIUM", "#f2d35e"),
            ("LOW", "#9dff65"),
        ]:
            count = sum(f.get("severity") == level for f in findings)
            width = (count / max_count * 100) if max_count else 0

            st.markdown(
                f"""
                <div class="severity-row">
                    <div class="severity-label">{level}</div>
                    <div class="severity-track">
                        <div class="severity-fill"
                             style="width:{width}%;background:{color};">
                        </div>
                    </div>
                    <div class="severity-count">{count}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
        if not findings:
            st.success("No findings reported by Bandit.")
            st.caption("A clean scan does not guarantee secure code.")
        else:
            st.markdown(
                '<div class="section">[ FILTER FINDINGS ]</div>',
                unsafe_allow_html=True,
            )

            filter_col1, filter_col2 = st.columns(2)

            severity_options = ["HIGH", "MEDIUM", "LOW"]

            with filter_col1:
                selected_severities = st.multiselect(
                    "SEVERITY",
                    options=severity_options,
                    default=severity_options,
                    key="severity_filter",
                )

            available_scanners = sorted({
                f.get("scanner", "Unknown")
                for f in findings
            })

            with filter_col2:
                selected_scanners = st.multiselect(
                    "SCANNER",
                    options=available_scanners,
                    default=available_scanners,
                    key="scanner_filter",
                )

            filtered_findings = [
                f for f in findings
                if (
                    not selected_severities
                    or f.get("severity") in selected_severities
                    )
                and (
                    not selected_scanners
                    or f.get("scanner", "Unknown") in selected_scanners
                )]
            
            st.caption(
                f"DISPLAYING {len(filtered_findings)} OF {len(findings)} FINDINGS"
            )
            st.dataframe(
                [
                    {
                      "SEVERITY": f.get("severity", "UNKNOWN"),
                      "CWE": f.get("cwe") or "Not mapped",
                      "VULNERABILITY": f.get("title", "Potential security issue"),
                      "CONFIDENCE": f.get("confidence", "Unknown"),
                      "SCANNER": f.get("scanner", "Unknown"),
                      "RULE": f.get("rule_id", "UNKNOWN"),   
                    }
                    for f in filtered_findings
                ],
                use_container_width=True,
                hide_index=True,
            )
                        
            if filtered_findings:
                export_data = [
                    {
                        "SEVERITY": f.get("severity", "UNKNOWN"),
                        "VULNERABILITY": f.get("title", ""),
                        "CWE": f.get("cwe") or "Not mapped",
                        "LOCATION": f"{f.get('file', 'Unknown')}:{f.get('line', '?')}",
                        "SCANNER": f.get("scanner", "Unknown"),
                        "CONFIDENCE": f.get("confidence", "Unknown"),
                        "RULE ID": f.get("rule_id", "UNKNOWN"),
                    }
                    for f in findings
                ]

                df = pd.DataFrame(export_data)

                st.download_button(
                    label="DOWNLOAD FINDINGS / CSV",
                    data=df.to_csv(index=False).encode("utf-8"),
                    file_name="simhara_findings.csv",
                    mime="text/csv",
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

                    st.caption(f"REPORTED LOCATION: LINE {finding.get('line')}")
                    st.code(excerpt, language=language_map.get(Path(st.session_state.uploaded_name).suffix.lower(), "text"))

                    st.caption("The reported location is where the scanner detected a pattern. It does not, by itself, prove exploitability.")

                else:
                    st.warning(
                        f"Invalid scanner line: {finding.get('line')}. Showing full source."
                    )
                    st.code(
                        st.session_state.source_text,
                        language=language_map.get(Path(st.session_state.uploaded_name).suffix.lower(), "text"),
                    )

            with right:
                st.markdown("### AI ANALYSIS")
                st.write("Analyse this finding with the configured local model.")

                if st.button("ANALYSE FINDING", type="primary"):
                    lines = st.session_state.source_text.splitlines()

                    # Provide the complete source for small files.
                    # For larger files, use a wider excerpt around the finding.
                    if len(st.session_state.source_text) <= 6000:
                        context = "\n".join(
                            f"{i + 1}: {line}"
                            for i, line in enumerate(lines)
                        )
                    else:
                        line = finding.get("line")

                        if (
                            isinstance(line, int)
                            and 1 <= line <= len(lines)
                        ):
                            start = max(0, line - 15)
                            end = min(len(lines), line + 15)

                            context = "\n".join(
                                f"{i + 1}: {lines[i]}"
                                for i in range(start, end)
                            )
                        else:
                            context = st.session_state.source_text[:6000]

                    try:
                        with st.spinner("Consulting local model..."):
                            result = analyse_finding(
                                {
                                    **finding,
                                    "file": st.session_state.uploaded_name,
                                },
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
