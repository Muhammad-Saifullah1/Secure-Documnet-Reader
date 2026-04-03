import streamlit as st
import os

from scanner import run_security_scan
from nlp_analyzer import analyze_text
from virustotal import scan_with_virustotal
from reader import display_file_content

st.set_page_config(page_title="Secure Document Reader", layout="wide")

st.title("🛡️ Secure Document Reader")
st.markdown("Advanced Multi-phase Security Scanner and Intelligent Document Reader utilizing Rule-based checking, NLP ML Classification, and VirusTotal integration.")

# Phase 4 API Key Input
api_key = st.sidebar.text_input("VirusTotal API Key (Optional)", type="password", help="Enable Phase 4 Cloud Scans")
st.sidebar.markdown("---")

# Phase 1: File Input
uploaded_file = st.file_uploader("Upload a file to scan and read", type=["pdf", "txt", "docx", "csv", "json", "html", "xml", "md", "log", "png", "jpg"])

if uploaded_file is not None:
    # Extract file metadata and memory object
    filename = uploaded_file.name
    extension = os.path.splitext(filename)[1].lower()
    size_bytes = uploaded_file.size
    raw_bytes = uploaded_file.getvalue()
    
    # Check if models are trained yet
    if not os.path.exists("models/classifier.pkl"):
        st.error("ML Model not found! Please run `python train_model.py` to initialize Phase 3 NLP Analyzer.")
        st.stop()
    
    st.header(f"File Information")
    st.write(f"**Name:** {filename} | **Type:** {extension} | **Size:** {size_bytes} bytes")
    st.markdown("---")
    
    # Phase 2: Security Scanner
    with st.spinner("Executing Phase 2: Rule-based Security Checks..."):
        scan_results = run_security_scan(filename, extension, raw_bytes)
        
    # Preparation: Extract text softly for the NLP module
    text_content = ""
    if extension in ['.txt', '.html', '.xml', '.json', '.md', '.log', '.csv']:
        text_content = raw_bytes.decode('utf-8', errors='ignore')
    elif extension == '.pdf':
        try:
            import fitz
            doc = fitz.open(stream=raw_bytes, filetype="pdf")
            for page in doc: text_content += page.get_text()
        except: pass
    elif extension == '.docx':
        try:
            import docx, io
            doc = docx.Document(io.BytesIO(raw_bytes))
            text_content = " ".join([p.text for p in doc.paragraphs])
        except: pass

    # Phase 3: NLP Analyzer
    with st.spinner("Executing Phase 3: NLP Threat Analysis..."):
        nlp_results = analyze_text(text_content)
        
    # Phase 4: VirusTotal
    vt_results = {"malicious_engines": 0, "total_engines": 0, "permalink": None}
    if api_key:
        with st.spinner("Executing Phase 4: Querying VirusTotal..."):
            vt_results = scan_with_virustotal(raw_bytes, api_key)
            
    # Phase 5: Decision Engine
    vt_malicious = vt_results.get("malicious_engines", 0)
    scanner_threats = len(scan_results['threats'])
    scanner_warnings = len(scan_results['warnings'])
    nlp_score = nlp_results['confidence_score']
    
    final_verdict = "SAFE"
    reason = "All layers passed successfully. No anomalies detected."
    
    if scanner_threats > 0 or nlp_score > 70 or vt_malicious > 0:
        final_verdict = "BLOCKED"
        reason = "Critical threats detected (Rule Scanner, High ML Suspicion, or flagged by AntiVirus Engines)."
    elif scanner_warnings > 0 or (40 < nlp_score <= 70):
        final_verdict = "WARNING"
        reason = "File contains suspicious characteristics (Entropy, minor signatures, or moderate ML Suspicion)."
        
    # Phase 7: Output Results
    st.subheader("Decision Engine Final Verdict (Phase 5)")
    col1, col2, col3 = st.columns(3)
    col1.metric("Final Verdict Status", final_verdict)
    col2.metric("Scanner Threats/Warnings", f"{scanner_threats} / {scanner_warnings}")
    col3.metric("NLP Malicious Confidence", f"{nlp_score:.2f}%")
    
    if final_verdict == "BLOCKED":
        st.error(f"🛑 ACCESS BLOCKED: {reason}")
    elif final_verdict == "WARNING":
        st.warning(f"⚠️ ACTION REQUIRED: {reason}")
    else:
        st.success(f"✅ FILE SAFE: {reason}")
        
    with st.expander("Show Complete Diagnostics & Metadata (Phase 7)"):
        st.write("#### Rule-Based Analysis (Phase 2)")
        if scan_results['threats']:
            for t in scan_results['threats']: st.error(f"Threat: {t}")
        if scan_results['warnings']:
            for w in scan_results['warnings']: st.warning(f"Warning: {w}")
        if not scan_results['threats'] and not scan_results['warnings']:
            st.success("No signature-based anomalies found.")
            
        st.write("#### NLP ML Analysis (Phase 3)")
        st.write(f"- Verdict: **{nlp_results['verdict']}**")
        st.write(f"- Suspicious Keywords: {', '.join(nlp_results['suspicious_words']) if nlp_results['suspicious_words'] else 'None'}")
        st.write(f"- Suspicious Entities/IOCs: {', '.join(nlp_results['suspicious_entities']) if nlp_results['suspicious_entities'] else 'None'}")
        
        st.write("#### VirusTotal Engines (Phase 4)")
        if vt_results.get("error"):
             st.write(f"- Status: {vt_results['error']}")
        else:
             st.write(f"- Engines Marked Malicious: {vt_malicious} out of {vt_results['total_engines']}")
             if vt_results['permalink']:
                 st.markdown(f"🔗 [View Detailed VirusTotal Report]({vt_results['permalink']})")
                 
    # Phase 6: Document Reader
    st.markdown("---")
    st.subheader("Phase 6: Safe Document Reader")
    if final_verdict in ["SAFE", "WARNING"]:
        # Conditionally run
        display_file_content(raw_bytes, extension)
    else:
        st.error("View Access Denied. Document display has been blocked for Phase 6 due to active BLOCKED verdict.")
