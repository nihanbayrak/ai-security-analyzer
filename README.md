# AI Security Analyzer

Scans your exported ChatGPT or Claude conversations for prompt injection attempts, exposed passwords and API keys, and personal data such as email addresses, phone numbers, card numbers and IBANs.

You give it a ChatGPT export ZIP or a Claude export JSON. It gives you a local Gradio dashboard and a JSON or PDF report. Each finding shows where it was found, the matched text with a masked version, a severity and confidence score, the OWASP LLM Top 10 or MITRE ATLAS category, and a suggested action. Detection uses patterns, heuristics and small local models, and is tuned for English, German and Turkish text.

What it does not do:

- It does not upload your export. By default all analysis runs on your machine. The local models (GPT-2 and a DeBERTa prompt-injection classifier) are downloaded from Hugging Face once.
- One exception: if you set `HF_TOKEN`, an optional second check sends each finding, including up to 200 characters of the matched text, to the Hugging Face Inference API for review. Leave `HF_TOKEN` unset to keep all text on your machine.
- It does not prove a conversation is safe. It flags known patterns, so it will miss some things and flag some harmless ones.
- It does not test or attack live AI services.

[![OWASP Top 10 LLM](https://img.shields.io/badge/OWASP-Top_10_LLM_2025-blue)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-orange)](https://atlas.mitre.org/)

## Contents

- [What it checks](#what-it-checks)
- [How to use it](#how-to-use-it)
- [Privacy and data handling](#privacy-and-data-handling)
- [Detection details](#detection-details)
- [Project structure](#project-structure)
- [Installation](#installation)
- [Running it](#running-it)
- [References](#references)
- [License and disclaimer](#license-and-disclaimer)

## What it checks

Each check is its own module in `detectors/`. The table lists what each one looks for and the framework it maps to.

| Check | What it looks for | Framework |
|---|---|---|
| Prompt injection | Attempts to override the model's instructions | OWASP LLM01:2025 |
| Secrets | Passwords and API keys pasted into chats | OWASP LLM06:2025 |
| Personal data | Emails, phone numbers, ID numbers, cards, IBANs | OWASP LLM06:2025 |
| Anomalies | Unusual message lengths, bursts, adversarial suffixes | MITRE ATLAS |
| Advertising and manipulation | Product pushing, sycophancy, retention tactics | DarkBench (ICLR 2025) |
| Memorization | Long passages the model may be repeating verbatim | Min-K% Prob (ICLR 2024) |
| Custom instructions | Suggested ChatGPT custom instructions based on your usage | none |

The dashboard has one tab per area. Reports can be saved as JSON or PDF.

## How to use it

### ChatGPT export
1. In ChatGPT, open Settings, Data Controls, Export Data.
2. Download the `.zip` file from the email ChatGPT sends you.
3. Upload the ZIP in the app.
4. Review the results in the dashboard tabs.
5. Download the JSON or PDF report if you want to keep it.

### Claude export
1. In Claude, open Settings, Account, Export Data.
2. Download the JSON export.
3. Upload the JSON file in the app.
4. Review the results in the dashboard tabs.
5. Download the JSON or PDF report if you want to keep it.

## Privacy and data handling

Uploaded files are extracted to a temporary directory set by the `GRADIO_TEMP_DIR` environment variable. The app does not write your conversations anywhere else and does not log them.

Extraction has hard limits (1.5 GB total uncompressed size, at most 8,000 files) to guard against zip bombs and resource exhaustion.

Nothing is sent to a third party unless you set `HF_TOKEN`. With it set, each finding, including up to 200 characters of the matched text, goes to the Hugging Face Inference API for a second review.

The **Wipe Session Data** button in the app deletes the session's files from memory and disk.

## Detection details

### 1. Prompt injection (6 attack types)
- Known jailbreak phrases and system prompt leak attempts.
- Encoded payloads (Base64, hex).
- Role-play framing used to take over the conversation.
- Multi-turn escalation (Crescendo style).
- Context rules that suppress matches in harmless contexts, to cut false positives.

### 2. Personal data and credentials (19 categories)
- Emails, phone numbers and social security numbers.
- Credit cards (checked with the Luhn algorithm) and IBANs (checked with MOD-97).
- API keys (OpenAI, AWS, GitHub) and private keys.
- Crypto wallets, JWT tokens and plaintext passwords.

### 3. Anomalies (7 patterns)
- Z-scores for unusually long or short messages.
- High-entropy strings, which often mean obfuscated content.
- Bursts of messages in a short time.
- Rapid switching between languages.
- Adversarial suffixes of the kind GCG and AutoDAN produce.

### 4. Advertising and manipulation (7 types)
Based on the DarkBench categories:
- Promotional language and brand bias.
- Affiliate links, sycophancy, sneaking and retention tactics.

### 5. Memorization
Flags text the model may have repeated from its training data:
- A Min-K% Prob proxy using character n-gram rarity.
- Long verbatim blocks.
- The same passage appearing across conversations.

## Project structure

```text
.
├── app.py                      # Gradio app
├── model.py                    # Data models (Finding, Message, etc.)
├── scoring.py                  # Risk scoring
├── report.py                   # PDF and JSON reports
├── ingest.py                   # ZIP extraction with size limits
├── theme.py                    # Dark UI theme
├── detectors/                  # Detection modules
│   ├── pii.py                  # Personal data (SSN, credit cards, IBAN)
│   ├── secrets.py              # API keys and credentials (15+ types)
│   ├── injection.py            # Prompt injection and jailbreaks
│   ├── dark.py                 # Dark patterns and manipulation
│   ├── hallucination.py        # Hallucination checks
│   └── context_filter.py       # False positive reduction
├── extractors/                 # Export parsers
│   ├── common.py               # Detects ChatGPT or Claude format
│   ├── json_html.py            # ChatGPT parser
│   └── claude_parser.py        # Claude parser
├── controllers/                # Validation
│   ├── context_validator.py    # Role-based context checks
│   ├── credit_card.py          # Luhn check
│   └── iban.py                 # MOD-97 check
└── supervisors/                # Optional LLM review (needs HF_TOKEN)
    └── *.py                    # One reviewer per detection area
```

## Installation

Requires Python 3.9 to 3.11 and Git.

```bash
git clone https://github.com/nihanbayrak/ai-security-analyzer.git
cd ai-security-analyzer
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running it

### Web UI
```bash
python app.py
```
The UI runs at `http://127.0.0.1:7860/`.

### Command line
```bash
python main.py path/to/conversations.json --output security_report.json
```
To skip the transformer models and run faster:
```bash
python main.py path/to/conversations.json --no-transformer --output security_report.json
```

## References

- **PromptShield** (arXiv:2501.15145): prompt injection detection.
- **HackAPrompt** (EMNLP 2023): a dataset of 600K+ prompt injection attempts.
- **DarkBench** (ICLR 2025): dark patterns in LLM conversations.
- **Min-K% Prob** (ICLR 2024, arXiv:2310.16789): detecting training data memorization.
- **OWASP Top 10 for LLM Applications 2025**.
- **MITRE ATLAS**: adversarial threat landscape for AI systems (15 tactics, 66 techniques).

## License and disclaimer

**License:** MIT, see [LICENSE](LICENSE). Provided for educational and research use.

**Disclaimer:** This tool is for auditing your own exported data. It is not built to attack or disrupt any AI service.
