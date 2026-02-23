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
short_description: Scan your ChatGPT exports for security threats, PII leaks & prompt injection
tags:
  - security
  - chatgpt
  - privacy
  - prompt-injection
  - pii-detection
  - owasp
  - llm-security
---

# 🛡️ AI Security Analyzer

**Find out what's hiding in your ChatGPT conversations.**

Upload your ChatGPT `conversations.json` export and instantly get a comprehensive security analysis covering **7 critical questions** about your data — from prompt injection attacks to exposed passwords, personal information leaks, and AI manipulation patterns.

[![OWASP Top 10 LLM](https://img.shields.io/badge/OWASP-Top_10_LLM_2025-blue)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-orange)](https://atlas.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## What You Get

| Security Check | What It Answers | Framework |
|---|---|---|
| 🔓 **Prompt Injection** | Did anyone try to hijack the AI? | OWASP LLM01:2025 |
| 🔑 **Passwords & Keys** | Are passwords or API keys exposed? | OWASP LLM06:2025 |
| 👤 **Personal Info** | Is personal data visible in chats? | OWASP LLM06:2025 |
| 📊 **Anomaly Detection** | Are there strange patterns? | MITRE ATLAS |
| 📢 **Advertising & Manipulation** | Is the AI pushing products? | DarkBench / ICLR 2025 |
| 🧠 **Training Data Memorization** | Is memorized text being repeated? | Min-K% Prob / ICLR 2024 |
| 🎯 **Custom Instructions** | Personalized ChatGPT instructions based on your usage | — |

Plus a **downloadable PDF report** and a **personalized Custom Instruction** generated from your conversation patterns.

---

## How to Use

### Quick Demo (no data needed)
Download `example_conversations.json` from the **Files** tab — it contains 10 sample conversations with planted security issues (prompt injections, exposed API keys, PII, manipulation, and more). Upload it to see the analyzer in action.

### Analyze Your Own Data
1. Go to **ChatGPT → Settings → Data Controls → Export Data**
2. Download the ZIP from your email, extract `conversations.json`
3. Upload it and click **Analyze My Data**
4. Explore the results across 10 interactive tabs
5. Download your PDF reports

---

## Privacy

> **Your data never leaves your session.** Files are processed entirely in memory and are never stored, logged, or sent to third parties. Everything is deleted when your session ends.

---

## Detection Pipeline

### Prompt Injection (6 attack types)
Multi-layer detection: phrase-based heuristics → regex patterns → benign context suppression. Detects jailbreaks, system prompt leaks, encoding attacks, role-play attacks, and multi-turn escalation (Crescendo-style).

### PII & Credentials (19 categories)
Email, phone, SSN, credit cards (Luhn-validated), IBAN (MOD-97), API keys (OpenAI, AWS, GitHub), passwords, JWTs, crypto wallets, and more. Extensive false-positive filtering.

### Anomaly Detection (7 patterns)
Statistical z-score analysis for message lengths, high-entropy detection, burst messages, language switching, adversarial suffix detection (GCG/AutoDAN patterns).

### Advertising & Manipulation (7 types)
Based on DarkBench (ICLR 2025): promotional language scoring, brand bias, affiliate links, sycophancy, sneaking, user retention, and anthropomorphism patterns.

### Membership Inference
Min-K% Prob proxy via character n-gram rarity, verbatim block detection, and cross-conversation fingerprinting.

---

## References

- **PromptShield** (arXiv:2501.15145) — AUC 0.998 injection detection
- **HackAPrompt** (EMNLP 2023) — 600K+ prompt injection dataset
- **DarkBench** (ICLR 2025) — Dark patterns in 48% of LLM interactions
- **Min-K% Prob** (ICLR 2024, arXiv:2310.16789) — Training data detection
- **OWASP Top 10 for LLM Applications 2025**
- **MITRE ATLAS** — 15 tactics, 66 techniques for adversarial AI

---

## Run Locally

```bash
pip install -r requirements.txt
python app.py
```

Or use the CLI:
```bash
python main.py conversations.json --no-transformer --output security_report.json
```

---

## License

MIT License — For educational and research purposes.

**Disclaimer:** This tool is for defensive use only. It is designed to analyze your own conversation history.
