---
title: AI Security Analyzer
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: gradio
sdk_version: 5.14.0
app_file: app.py
pinned: false
license: mit
short_description: Scan your ChatGPT & Claude exports for security threats, PII leaks, & prompt injection
tags:
  - security
  - chatgpt
  - claude
  - privacy
  - prompt-injection
  - pii-detection
  - owasp
  - llm-security
  - cybersecurity
  - gdpr
  - kvkk
---

# 🛡️ AI Security Analyzer

**Find out what's hiding in your ChatGPT & Claude conversations.**

AI Security Analyzer is a robust threat detection pipeline that allows users to upload their **ChatGPT ZIP exports** or **Claude JSON exports** to instantly receive a comprehensive security and privacy analysis. It scans your data across **7 critical security dimensions**—ranging from prompt injection attacks and exposed credentials to personal information leaks and adversarial AI manipulation patterns.

**Supports:** English, German, Turkish language contexts for accurate false-positive reduction.

[![OWASP Top 10 LLM](https://img.shields.io/badge/OWASP-Top_10_LLM_2025-blue)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-orange)](https://atlas.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## 📑 Table of Contents
- [Features](#-features)
- [How to Use](#-how-to-use)
- [Privacy & Data Handling](#-privacy--data-handling)
- [Detection Pipeline Details](#-detection-pipeline-details)
- [Project Architecture & Structure](#-project-architecture--structure)
- [Installation & Local Setup](#-installation--local-setup)
- [Usage (CLI & GUI)](#-usage-cli--gui)
- [References](#-references)
- [License & Disclaimer](#-license--disclaimer)

---

## 🌟 Features

| Security Check | What It Answers | Backing Framework |
|---|---|---|
| 🔓 **Prompt Injection** | Did anyone try to hijack the AI? | OWASP LLM01:2025 |
| 🔑 **Passwords & Keys** | Are passwords or API keys exposed? | OWASP LLM06:2025 |
| 👤 **Personal Info** | Is sensitive personal data visible in chats? | OWASP LLM06:2025 |
| 📊 **Anomaly Detection** | Are there strange or adversarial patterns? | MITRE ATLAS |
| 📢 **Advertising & Manipulation** | Is the AI pushing products or biased? | DarkBench / ICLR 2025 |
| 🧠 **Training Data Memorization** | Is the AI repeating memorized verbatim text? | Min-K% Prob / ICLR 2024 |
| 🎯 **Custom Instructions** | Personalized ChatGPT system instructions based on your usage | — |

**Additional Deliverables:**
- **Interactive Dashboard:** 10 rich tabs mapping out your vulnerabilities.
- **Sharable Reports:** Generate detailed JSON and highly readable PDF security reports.
- **Custom System Prompts:** Auto-generates tailored AI personas and instructions based on the user's historical queries to improve future LLM interactions.

---

## 🚀 How to Use

### Analyze ChatGPT Data
1. Go to **ChatGPT → Settings → Data Controls → Export Data**.
2. Download the resulting `.zip` file from your email inbox.
3. Upload the full ZIP directly to the application dashboard.
4. Explore the results across the interactive Gradio UI tabs.
5. Download your JSON or PDF reports for archiving or auditing.

### Analyze Claude Data
1. Go to **Claude → Settings → Account → Export Data**.
2. Download the JSON export file.
3. Upload the JSON file directly to the application dashboard.
4. Explore the results across the interactive Gradio UI tabs.
5. Download your JSON or PDF reports for archiving or auditing.

---

## 🔒 Privacy & Data Handling

> **Your data never leaves your session.** 
> All files are extracted securely to an ephemeral directory defined by the `GRADIO_TEMP_DIR` environment variable. 
> 
> The app incorporates hard limits (e.g., 1.5GB total uncompressed size, 8,000 files maximum) to protect against resource exhaustion and zip bombs—typical threats in public Hugging Face Spaces. Files are processed **entirely in memory** and are **never stored, logged, or sent to third parties.**
> 
> You can manually wipe your session data from memory and disk at any time using the **🚨 Wipe Session Data** button located in the app GUI.

---

## 🔍 Detection Pipeline Details

### 1. Prompt Injection (6 Attack Types)
A multi-layered heuristic and pattern-matching system detects:
- Phrase-based jailbreaks and System Prompt Leaks.
- Encoding attacks (Base64, Hex evasion).
- Role-play dominance and framing.
- Multi-turn escalation attacks (e.g., Crescendo-style).
- Benign context suppression logic to minimize false positives.

### 2. PII & Credentials (19 Categories)
Identifies and extracts high-risk information:
- Emails, Phone Numbers, and Social Security Numbers (SSN).
- Credit Cards (validated against the Luhn algorithm) & IBANs (MOD-97).
- API Keys (OpenAI, AWS, GitHub) and Private/Public keys.
- Crypto wallets, JWT tokens, and exposed plaintext passwords.

### 3. Anomaly Detection (7 Patterns)
Performs deep statistical analysis:
- Z-score analysis for abnormal message lengths.
- High-entropy string detection (often indicative of obfuscation).
- Burst messaging rates.
- Rapid language switching.
- Adversarial suffix detection typical in GCG/AutoDAN patterns.

### 4. Advertising & Manipulation (7 Types)
Based on the latest DarkBench standards:
- Scans for promotional language scoring and heavy brand bias.
- Detects affiliate links, sycophancy, "sneaking", and suspicious user retention tactics.

### 5. Membership Inference
Identifies if the LLM is spitting out pre-trained data:
- Min-K% Prob proxy detection via character n-gram rarity.
- Verbatim block detection.
- Cross-conversation fingerprinting.

---

## 🏗️ Project Architecture & Structure

```text
.
├── app.py                      # Main Gradio application interface
├── main.py                     # CLI entry point
├── detectors/                  # Core logic & algorithms for threat detection
│   ├── pii_detector.py         # Personal Identifiable Information logic
│   ├── prompt_injection.py     # Jailbreak and injection heuristics
│   ├── anomaly_detector.py     # Statistical & entropy pattern analysis
│   └── ...
├── extractors/                 # Parsers for HTML, JSON, Office docs, etc.
├── generate_pdf_report.py      # PDF rendering logic for the final report
└── generate_custom_instructions.py # AI persona instruction generation
```

---

## 💻 Installation & Local Setup

### Prerequisites
- Python 3.9 to 3.11 recommended.
- Git.

### Setup Instructions
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/ai-security-analyzer.git
   cd ai-security-analyzer
   ```

2. **Create a Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🎮 Usage (CLI & GUI)

### 1. Running the Web UI (Gradio)
To start the sleek, interactive Gradio interface locally:
```bash
python app.py
```
*The Web UI usually runs on `http://127.0.0.1:7860/`.*

### 2. Running via Command Line (CLI)
For quick headless analysis, use `main.py`:
```bash
python main.py path/to/conversations.json --output security_report.json
```
If you wish to disable complex transformer-based analysis to speed up the run:
```bash
python main.py path/to/conversations.json --no-transformer --output security_report.json
```

---

## 📚 References

The methodologies in this application are heavily grounded in the latest LLM security research:
- **PromptShield** (arXiv:2501.15145) — Robust prompt injection detection.
- **HackAPrompt** (EMNLP 2023) — Large-scale 600K+ prompt injection dataset analysis.
- **DarkBench** (ICLR 2025) — Exposing dark patterns in LLM interactions.
- **Min-K% Prob** (ICLR 2024, arXiv:2310.16789) — Effective training data memorization detection.
- **OWASP Top 10 for LLM Applications 2025** — Industry-standard security risks.
- **MITRE ATLAS** — Adversarial Threat Landscape for AI Systems (15 tactics, 66 techniques).

---

## ⚖️ License & Disclaimer

**License:** Distributed under the [MIT License](https://opensource.org/licenses/MIT). Provided for educational and research purposes.

**Disclaimer:** This tool is intended strictly for **defensive use** to help users audit and secure their own exported data. It is not designed to attack, exploit, or disrupt external LLM services.
