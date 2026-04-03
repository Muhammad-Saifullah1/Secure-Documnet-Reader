# 🛡️ Secure Document Reader

> **Advanced Multi-Phase Security Scanner & Intelligent Document Viewer**  
> Combines Rule-Based Analysis, NLP/ML Classification, and VirusTotal Cloud Intelligence to scan and safely read documents.

---

## 📌 Overview

**Secure Document Reader** is a Streamlit-based desktop/web application that scans uploaded files through multiple security layers before displaying their content. It is designed to detect malicious patterns, obfuscated payloads, suspicious entities, and known threats — all before a single byte of document content is rendered to the user.

Built with Python, scikit-learn, spaCy, and the VirusTotal API, this project demonstrates a practical, end-to-end security pipeline suitable for academic, research, and personal use.

---

## 🧱 Architecture — The 7-Phase Pipeline

```
Upload File
    │
    ▼
Phase 1 ──► File Ingestion & Metadata Extraction
    │
    ▼
Phase 2 ──► Rule-Based Security Scanner (scanner.py)
    │         • Extension Blacklist
    │         • Magic Byte / MIME Check
    │         • Dangerous Regex Patterns
    │         • Entropy Analysis
    │         • Binary-in-Text Detection
    ▼
Phase 3 ──► NLP / ML Threat Classifier (nlp_analyzer.py)
    │         • TF-IDF Vectorization
    │         • Naive Bayes Classifier
    │         • spaCy NER (URLs, IPs)
    │         • Regex IOC Extraction
    ▼
Phase 4 ──► VirusTotal Cloud Scan (virustotal.py) [Optional]
    │         • SHA-256 Hash Lookup
    │         • Multi-Engine Malicious Score
    ▼
Phase 5 ──► Decision Engine — SAFE / WARNING / BLOCKED
    │
    ▼
Phase 6 ──► Safe Document Reader (reader.py) [If SAFE or WARNING]
    │         • PDF, DOCX, CSV, JSON, HTML, XML, Images, TXT
    ▼
Phase 7 ──► Full Diagnostics Report
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 Rule-Based Scanner | Detects blacklisted extensions, dangerous regex patterns, and byte anomalies |
| 🧠 ML Classifier | Naive Bayes + TF-IDF model trained on safe vs. malicious text patterns |
| 🕵️ NLP Entity Extraction | spaCy NER + regex fallback for IP addresses, URLs, and IOCs |
| 🌐 VirusTotal Integration | SHA-256 hash lookup against 70+ antivirus engines |
| 📊 Entropy Analysis | Flags high-entropy content that may indicate packed or obfuscated files |
| 📄 Multi-Format Reader | Renders PDF, DOCX, CSV, JSON, HTML, XML, images, TXT, MD, LOG |
| 🔒 Verdict Gating | Document content is only displayed if verdict is SAFE or WARNING |
| 📋 Full Diagnostics | Expandable report showing all phase results and IOC lists |

---

## 📁 Project Structure

```
secure-document-reader/
│
├── app.py                  # Main Streamlit app — orchestrates all phases
├── scanner.py              # Phase 2: Rule-based security checks
├── nlp_analyzer.py         # Phase 3: ML/NLP malicious text classifier
├── virustotal.py           # Phase 4: VirusTotal API integration
├── reader.py               # Phase 6: Safe multi-format document renderer
├── train_model.py          # Trains and saves the ML model locally
├── requirements.txt        # Python dependencies
├── models/                 # Auto-generated after training
│   ├── classifier.pkl      # Trained Naive Bayes classifier
│   └── vectorizer.pkl      # Fitted TF-IDF vectorizer
└── README.md
```

---

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/secure-document-reader.git
cd secure-document-reader
```

### 2. Create a Virtual Environment (Recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Download the spaCy Language Model

```bash
python -m spacy download en_core_web_sm
```

### 5. Train the ML Model

> ⚠️ This step is **required** before running the app. It generates the `models/` folder with trained `.pkl` files.

```bash
python train_model.py
```

Expected output:
```
Training NLP ML model for malicious text classification...
Model trained and saved locally in 'models' folder.
```

### 6. Run the App

```bash
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`.

---

## 🔑 VirusTotal API (Optional — Phase 4)

To enable cloud-based antivirus scanning:

1. Register for a free account at [virustotal.com](https://www.virustotal.com)
2. Go to your profile and copy your **API Key**
3. Paste it in the **sidebar** of the running app under *"VirusTotal API Key (Optional)"*

> **Note:** The free tier uses SHA-256 hash lookups only. Files not previously submitted to VirusTotal will return a "not found" result. Full file upload is not implemented in this version.

---

## 📂 Supported File Types

| Category | Extensions |
|---|---|
| Documents | `.pdf`, `.docx`, `.txt`, `.md`, `.log` |
| Data | `.csv`, `.json` |
| Web / Markup | `.html`, `.xml` |
| Images | `.png`, `.jpg` |

---

## 🚦 Verdict Levels

| Verdict | Condition | Action |
|---|---|---|
| ✅ **SAFE** | No threats, no warnings, low ML score | File is displayed in reader |
| ⚠️ **WARNING** | Warnings present or moderate ML score (40–70%) | File is displayed with alert |
| 🛑 **BLOCKED** | Threats found, ML score >70%, or VirusTotal flags | File display is denied |

---

## 🧠 ML Model Details

- **Algorithm:** Multinomial Naive Bayes
- **Vectorizer:** TF-IDF (`sklearn.feature_extraction.text.TfidfVectorizer`)
- **Training Data:** Small curated dataset of safe vs. malicious text patterns
- **Labels:** `0 = Safe`, `1 = Malicious`
- **Threshold:** Score > 70% → MALICIOUS, 40–70% → SUSPICIOUS

> 💡 The model is intentionally simple for demonstration. For production use, replace the training data with a large, labeled corpus (e.g., VirusShare, PhishTank datasets).

---

## 🔧 Extending the Project

Some ideas to take this further:

- [ ] Add full VirusTotal file upload (not just hash lookup)
- [ ] Expand the ML training dataset with real malware/phishing samples
- [ ] Add YARA rule scanning support
- [ ] Implement user authentication and scan history logging
- [ ] Add support for `.zip`, `.tar`, `.xlsx` formats
- [ ] Deploy on Streamlit Cloud or Docker

---

## 🐛 Known Issues & Notes

- `python-magic` requires `libmagic` to be installed on the system. On Windows, install `python-magic-bin` instead:
  ```bash
  pip install python-magic-bin
  ```
- spaCy may fail to load on some Windows systems due to DLL conflicts with PyTorch. The app handles this gracefully and falls back to regex-only entity extraction.
- The ML model is trained on a **very small dataset** and may produce inaccurate confidence scores on real-world files. This is by design for educational purposes.

---

## 📦 Requirements

```
streamlit
PyMuPDF
python-docx
spacy
scikit-learn
requests
pandas
Pillow
```

---

## 👨‍💻 Author

**Saif** — CS Student | AI/ML Developer  
Muhammad Nawaz Sharif University of Agriculture, Pakistan  

---

