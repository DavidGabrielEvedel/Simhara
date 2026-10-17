import json
import tempfile
from pathlib import Path
import pandas as pd
import streamlit as st
from scanner.trivy_scanner import run_trivy_scan
from scanner.code_scanner import scan_python_file
from scanner.ai_analyzer import analyse_finding
from scanner.semgrep_scanner import scan_with_semgrep
from scanner.nmap_scanner import run_nmap_scan, SCAN_PROFILES
from scanner.web_checks import check_tls, check_headers, check_dns

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
        ["Overview", "Source Analysis", "Scan Operations"],
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


elif page == "Scan Operations":

    st.markdown(
        '<div class="section">[ SECURITY ASSESSMENT ]</div>',
        unsafe_allow_html=True,
    )

    st.caption("SIMHARA // UNIFIED SECURITY OPERATIONS")

    st.markdown("#### TARGET CONFIGURATION")

    target_type = st.selectbox(
        "TARGET TYPE",
        options=[
            "Website / Host",
            "Local Project",
        ],
    )

    if target_type == "Website / Host":

        target = st.text_input(
            "TARGET URL, IP ADDRESS OR HOSTNAME",
            value="127.0.0.1",
            help="Use only systems you own or are authorised to assess.",
        )

        st.caption(
            "Network operations currently support IP addresses and hostnames. "
            "Web, API, TLS and DNS checks will be added next."
        )

    else:

        target = st.text_input(
            "LOCAL PROJECT DIRECTORY OR FILE",
            value=".",
            help="Enter a local file or directory path.",
        )

        st.caption(
            "Local project operations inspect files accessible on this machine."
        )

    st.markdown("#### SELECT SECURITY OPERATIONS")

    if target_type == "Website / Host":

        network_discovery = st.checkbox(
            "Network & Service Discovery",
            help="Identify open TCP ports and detected services using Nmap.",
        )

        firewall_analysis = st.checkbox(
            "Firewall & Filtering Analysis",
            help="Examine TCP port states and possible network filtering.",
        )

        tls_assessment = st.checkbox(
            "TLS / HTTPS Assessment",
            help="Check HTTPS certificates and TLS connections.",
            )

        header_assessment = st.checkbox(
            "HTTP Security Headers",
            help="Check for common HTTP security headers.",
            )

        dns_assessment = st.checkbox(
            "DNS Security Checks",
            help="Resolve hostnames and attempt reverse DNS lookups.",
            
        )

        web_assessment = st.checkbox(
            "Web Application Security",
            help="Dynamic web application testing using OWASP ZAP. Integration pending.",
            
        )

        api_assessment = st.checkbox(
            "API Security Assessment",
            help="Test supported API specifications using OWASP ZAP. Integration pending.",
            
        )

        selected_operations = []

        if network_discovery:
            selected_operations.append("Network & Service Discovery")

        if firewall_analysis:
            selected_operations.append("Firewall & Filtering Analysis")

        if tls_assessment:
            selected_operations.append("TLS / HTTPS Assessment")

        if header_assessment:
            selected_operations.append("HTTP Security Headers")

        if dns_assessment:
            selected_operations.append("DNS Security Checks")
        # These operations become selectable after their integrations
        # have been implemented and tested.

    else:

        secret_detection = st.checkbox(
            "Exposed Secret Detection",
            help="Search supported files for potential exposed credentials.",
        )

        dependency_audit = st.checkbox(
            "Dependency Vulnerability Audit",
            help="Check supported dependency files for known vulnerabilities.",
        )

        configuration_audit = st.checkbox(
            "Configuration Security Audit",
            help="Inspect supported configuration files. Integration pending.",
            disabled=True,
        )

        container_audit = st.checkbox(
            "Container Security Audit",
            help="Assess a supported container image. Integration pending.",
            disabled=True,
        )

        selected_operations = []

        if secret_detection:
            selected_operations.append("Exposed Secret Detection")

        if dependency_audit:
            selected_operations.append("Dependency Vulnerability Audit")

    st.warning(
        "Run scans only against systems and files you are authorised to assess."
    )

    st.markdown("#### EXECUTION")

    if st.button("RUN SELECTED OPERATIONS", type="primary"):

        if not selected_operations:
            st.warning("Select at least one available security operation.")

        else:

            combined_findings = []
            operation_results = []

            progress = st.progress(0)

            for index, operation in enumerate(selected_operations):

                st.write(f"EXECUTING: {operation}")

                try:

                    if operation == "Exposed Secret Detection":

                        with st.spinner("TRIVY SECRET SCAN RUNNING..."):
                            result = run_trivy_scan(
                                target_path=target,
                                scan_type="secret",
                            )

                    elif operation == "Dependency Vulnerability Audit":

                        with st.spinner("TRIVY DEPENDENCY SCAN RUNNING..."):
                            result = run_trivy_scan(
                                target_path=target,
                                scan_type="vuln",
                            )

                    elif operation == "Network & Service Discovery":

                        with st.spinner("NMAP DISCOVERY RUNNING..."):
                            result = run_nmap_scan(
                                target=target,
                                profile="Network & Service Discovery",
                            )

                    elif operation == "Firewall & Filtering Analysis":

                        with st.spinner("NMAP FILTERING ANALYSIS RUNNING..."):
                            result = run_nmap_scan(
                                target=target,
                                profile="Firewall & Filtering Analysis",
                            )
                    elif operation == "TLS / HTTPS Assessment":

                        with st.spinner("TLS ASSESSMENT RUNNING..."):
                            result = check_tls(target)

                    elif operation == "HTTP Security Headers":

                        with st.spinner("HTTP HEADER CHECK RUNNING..."):
                            result = check_headers(target)

                    elif operation == "DNS Security Checks":

                        with st.spinner("DNS CHECK RUNNING..."):
                            result = check_dns(target)

                    else:
                        result = {
                            "success": False,
                            "error": "Operation is not implemented.",
                            "findings": [],
                        }

                    operation_record = {
                        "operation": operation,
                        "success": result["success"],
                        "error": result.get("error"),
                        "finding_count": len(result.get("findings", [])),
                    }

                    operation_results.append(operation_record)

                    if result["success"]:

                        for finding in result.get("findings", []):
                            finding = dict(finding)
                            finding["operation"] = operation
                            combined_findings.append(finding)

                        st.success(
                            f"{operation}: completed — "
                            f"{operation_record['finding_count']} observations."
                        )

                    else:
                        st.error(f"{operation}: failed.")
                        st.code(result.get("error") or "Unknown scanner error.")

                except Exception as error:

                    operation_results.append({
                        "operation": operation,
                        "success": False,
                        "error": str(error),
                        "finding_count": 0,
                    })

                    st.error(f"{operation}: failed unexpectedly.")
                    st.code(str(error))

                progress.progress((index + 1) / len(selected_operations))

            completed = sum(
                1 for item in operation_results if item["success"]
            )

            failed = len(operation_results) - completed

            st.divider()
            st.markdown("#### ASSESSMENT SUMMARY")

            col1, col2, col3 = st.columns(3)

            col1.metric("OPERATIONS SELECTED", len(selected_operations))
            col2.metric("COMPLETED", completed)
            col3.metric("FAILED", failed)

            st.metric("TOTAL OBSERVATIONS", len(combined_findings))

            report = {
                "product": "SIMHARA",
                "target": target,
                "target_type": target_type,
                "selected_operations": selected_operations,
                "operation_results": operation_results,
                "findings": combined_findings,
                "summary": {
                    "operations_selected": len(selected_operations),
                    "operations_completed": completed,
                    "operations_failed": failed,
                    "total_observations": len(combined_findings),
                },
                "interpretation_note": (
                    "Scanner observations are not automatically confirmed "
                    "vulnerabilities. Review the evidence and scanner context."
                ),
            }

            if combined_findings:

                st.markdown("#### FINDINGS")

                st.dataframe(
                    combined_findings,
                    use_container_width=True,
                    hide_index=True,
                )

            elif completed > 0:

                st.info(
                    "No findings were returned by the completed operations. "
                    "This does not guarantee that the target is secure."
                )

            st.download_button(
                "DOWNLOAD ASSESSMENT (JSON)",
                data=json.dumps(report, indent=2),
                file_name="simhara_security_assessment.json",
                mime="application/json",
            )

            if failed:
                st.warning(
                    "Some operations failed. Review their errors in the "
                    "operation results before interpreting this assessment."
                )

    st.caption(
        "SIMHARA // MULTI-ENGINE ASSESSMENT // EVIDENCE-BASED REPORTING"
    )