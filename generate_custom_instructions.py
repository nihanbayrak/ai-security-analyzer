"""
generate_custom_instructions.py

Reads outputs/messages_tagged.csv (and optionally sessions_summary.csv),
analyses AI/ML/LLM conversations, image generation behaviour, and prompt
injection patterns, then writes:
  - outputs/custom_instructions_report.md   (always)
  - outputs/custom_instructions_report.pdf  (with --pdf flag, requires fpdf2)

Usage:
    python scripts/generate_custom_instructions.py
    python scripts/generate_custom_instructions.py --pdf
    python scripts/generate_custom_instructions.py \
        --tagged  outputs/messages_tagged.csv \
        --sessions outputs/sessions_summary.csv \
        --out     outputs/custom_instructions_report
"""

import argparse
import re
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Optional

import pandas as pd


# ── Keyword taxonomies ─────────────────────────────────────────────────────────

AI_ML_LLM_KW = [
    "llm", "gpt", "claude", "gemini", "mistral", "llama", "falcon", "phi",
    "transformer", "attention", "bert", "t5", "rag", "retrieval augmented",
    "prompt", "fine-tun", "lora", "qlora", "peft", "embedding", "vector",
    "token", "context window", "inference", "quantization", "gguf", "ggml",
    "neural", "deep learning", "machine learning", "gradient", "loss function",
    "backprop", "epoch", "batch size", "overfitting", "regularization",
    "hyperparameter", "training", "dataset", "benchmark", "evaluation",
    "accuracy", "f1", "roc", "precision", "recall",
    "langchain", "llamaindex", "hugging face", "huggingface", "openai",
    "anthropic", "ollama", "vllm", "triton", "torchserve", "mlflow",
    "wandb", "weights & biases", "dvc", "airflow", "kubeflow",
    "pytorch", "tensorflow", "keras", "jax", "sklearn", "scikit",
    "agent", "tool use", "function calling", "chain of thought", "cot",
    "autogen", "crewai", "langgraph", "knowledge graph",
    "vector store", "pinecone", "weaviate", "chroma", "qdrant",
]

RESEARCH_KW = [
    "paper", "arxiv", "literature", "survey", "sota", "state of the art",
    "baseline", "ablation", "experiment", "hypothesis", "methodology",
    "review", "compare", "benchmark", "reproduce", "replicate",
]

BRAINSTORM_KW = [
    "idea", "brainstorm", "approach", "strategy", "design", "architecture",
    "proposal", "plan", "roadmap", "explore", "consider", "alternative",
    "tradeoff", "pros and cons", "what if", "could we", "how would",
]

CODE_KW = [
    "python", "javascript", "typescript", "sql", "bash", "script",
    "function", "class", "error", "stack trace", "debug", "refactor",
    "implement", "api", "endpoint", "pipeline", "notebook", "pytest",
    "docker", "kubernetes", "terraform", "ci/cd", "github actions",
]

TONE_DIRECT_KW  = ["just", "directly", "short", "brief", "tldr", "concise"]
TONE_EXPLAIN_KW = ["explain", "why", "how does", "understand", "detail", "step by step"]
TONE_EXAMPLE_KW = ["example", "show me", "demo", "sample", "snippet"]

# ── Image generation signals ───────────────────────────────────────────────────
IMAGE_TOOL_SIGNALS = ["dall·e displayed", "dalle displayed", "image has been generated",
                      "generated image", "image generation complete"]
IMAGE_STYLE_KW = {
    "photorealistic": ["photorealistic", "realistic", "photo", "photograph"],
    "illustration":   ["illustration", "cartoon", "anime", "drawing", "sketch", "art"],
    "logo_icon":      ["logo", "icon", "badge", "brand", "minimal", "flat"],
    "diagram":        ["diagram", "chart", "flowchart", "infographic", "map"],
    "portrait":       ["portrait", "face", "headshot", "person", "character"],
    "landscape":      ["landscape", "scene", "environment", "background", "city"],
}
IMAGE_SUBJECT_KW = {
    "business":   ["business", "office", "corporate", "professional", "team"],
    "technology": ["technology", "tech", "robot", "ai", "data", "code", "circuit"],
    "nature":     ["nature", "forest", "mountain", "ocean", "animal", "plant"],
    "abstract":   ["abstract", "pattern", "texture", "geometric", "colorful"],
}

# ── Prompt injection patterns ──────────────────────────────────────────────────
INJECTION_PATTERNS = {
    "jailbreak": [
        r"ignore (previous|all|your) instructions",
        r"\byou are DAN\b", r"\bDAN mode\b", r"do anything now",
        r"\bjailbreak\b", r"bypass (safety|filter|restriction)",
        r"pretend (you (are|have)|there (are|is) no)",
        r"act as (if|though) you (are|were|have no)",
        r"forget (your|all) (previous )?instructions",
        r"disregard (your|all|previous) (instructions|rules|guidelines)",
    ],
    "role_injection": [
        r"from now on (you are|your name is|act as)",
        r"you are now (a |an |the )?(new |different |unrestricted |unfiltered )",
        r"your new (role|identity|name|purpose) is",
        r"switch (to|into) .*(mode|role|persona)",
        r"^\s*\[system\]", r"<\|system\|>",
        r"<<SYS>>", r"\[INST\]",
    ],
    "prompt_leaking": [
        r"(repeat|show|print|reveal|output|tell me) (your|the) (system )?prompt",
        r"what (are|were) your instructions",
        r"what (is|was) (in )?your (system|initial) (prompt|message)",
        r"summarize your (instructions|prompt|system message)",
    ],
    "separator_injection": [
        r"```\s*system\s*(prompt|message|instruction)?",
        r"\n---\s*system\b",
        r"\[\[(SYSTEM|INST|SYS|USER|ASSISTANT)\]\]",
        r"<\|im_start\|>", r"<\|im_end\|>", r"<\|endoftext\|>",
        r"###\s*(system|instruction)\b",
        r"<system>\s*(prompt|message|instruction|you are)",
    ],
    "override_attempt": [
        r"override (your|all|safety)", r"unlimited mode",
        r"developer mode", r"admin mode", r"god mode",
        r"disable (safety|filter|restriction|guardrail)",
        r"unrestricted (mode|access|output)",
    ],
}


INJECTION_CAT_LABELS = {
    "jailbreak": "Jailbreak",
    "role_injection": "Role injection",
    "prompt_leaking": "Prompt leaking",
    "separator_injection": "Separator injection",
    "override_attempt": "Override attempt",
}

_STOPWORDS = {
    "the", "and", "for", "are", "you", "that", "this", "with",
    "have", "from", "not", "but", "they", "what", "can", "use",
    "how", "all", "one", "also", "get", "its", "more", "would",
    "when", "there", "will", "than", "been", "which", "just",
    "was", "has", "had", "may", "let", "per", "via", "any",
    "our", "his", "her", "their", "your", "out", "too", "very",
    "strong", "href", "span", "div", "img", "nbsp", "class", "style",
    "table", "tbody", "thead", "html", "http", "https",
    "price", "name", "item", "field", "value", "column", "row",
    "true", "false", "null", "none", "type", "list", "text",
    "def", "var", "int", "str", "bool", "len", "return", "print",
    "envs", "lib", "site", "opt", "conda", "usr", "local", "bin",
    "packages", "pkg", "dist", "path", "home",
    "der", "die", "das", "und", "ist", "von", "fur", "mit", "des",
    "den", "dem", "ein", "eine", "einem",
}

_AI_SIGNAL: set = set()
for _kw in AI_ML_LLM_KW + RESEARCH_KW + BRAINSTORM_KW:
    for _word in _kw.split():
        if len(_word) >= 3:
            _AI_SIGNAL.add(_word)
_AI_SIGNAL.update([
    "machine", "learning", "data", "science", "artificial", "intelligence",
    "language", "generative", "openai", "model", "models", "neural",
    "analysis", "analytics", "algorithm", "algorithms", "pipeline",
    "classification", "regression", "clustering", "prediction",
    "architecture", "deployment", "inference", "generation",
    "conversation", "chatbot", "chatgpt", "assistant",
])


def count_kw(text: str, keywords: list) -> int:
    t = text.lower()
    return sum(1 for k in keywords if k in t)


def classify_domain(text: str) -> str:
    scores = {
        "ai_ml_llm":     count_kw(text, AI_ML_LLM_KW),
        "research":      count_kw(text, RESEARCH_KW),
        "brainstorming": count_kw(text, BRAINSTORM_KW),
        "coding":        count_kw(text, CODE_KW),
    }
    # Require at least 2 hits for ai_ml_llm to avoid false positives from
    # product/contract text that incidentally contains one AI keyword.
    if scores["ai_ml_llm"] >= 2:
        return "ai_ml_llm"
    # Other categories stay at threshold 1 (they have tighter, less ambiguous keywords).
    for domain in ("research", "brainstorming", "coding"):
        if scores[domain] >= 1:
            return domain
    return "general"


def top_n_phrases(texts: pd.Series, n: int = 20) -> list:
    counter: Counter = Counter()
    for t in texts.dropna():
        words = [w for w in re.findall(r"\b[a-zA-Z]{3,14}\b", t.lower())
                 if w not in _STOPWORDS]
        for i in range(len(words) - 1):
            counter[f"{words[i]} {words[i+1]}"] += 1
        for i in range(len(words) - 2):
            counter[f"{words[i]} {words[i+1]} {words[i+2]}"] += 1

    # Keep only phrases that:
    #   1. occur more than once
    #   2. contain at least one genuine AI/ML signal word
    #   3. have no stopword in any position
    filtered = {
        p: c for p, c in counter.items()
        if c > 1
        and any(w in _AI_SIGNAL for w in p.split())
        and not any(w in _STOPWORDS for w in p.split())
    }
    return sorted(filtered.items(), key=lambda x: x[1], reverse=True)[:n]


def infer_tone_preferences(user_texts: pd.Series) -> dict:
    direct  = user_texts.apply(lambda t: count_kw(t, TONE_DIRECT_KW)).sum()
    explain = user_texts.apply(lambda t: count_kw(t, TONE_EXPLAIN_KW)).sum()
    example = user_texts.apply(lambda t: count_kw(t, TONE_EXAMPLE_KW)).sum()
    total   = direct + explain + example or 1
    return {
        "concise":  round(100 * direct  / total),
        "detailed": round(100 * explain / total),
        "examples": round(100 * example / total),
    }


def ascii_safe(text: str) -> str:
    """Transliterate unicode to closest ASCII for PDF rendering."""
    return unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode("ascii")


# ── Image metadata analysis ────────────────────────────────────────────────────

def analyse_images(df: pd.DataFrame) -> dict:
    """
    Detect real image generation events from tool messages (DALL-E signals)
    and extract metadata from the user prompts that triggered them.
    """
    tool_df = df[df["role"] == "tool"].copy()
    tool_df["text"] = tool_df["text"].fillna("").astype(str)

    # Confirmed DALL-E generations
    dalle_mask = tool_df["text"].str.lower().apply(
        lambda t: any(sig in t for sig in IMAGE_TOOL_SIGNALS)
    )
    dalle_events = tool_df[dalle_mask]
    confirmed_count = len(dalle_events)

    # Match each DALL-E event back to the preceding user message in the same conversation
    df_sorted = df.copy()
    df_sorted["timestamp_utc"] = pd.to_datetime(
        df_sorted["timestamp_utc"], utc=True, errors="coerce"
    )

    image_prompts: list[str] = []
    for _, event in dalle_events.iterrows():
        conv_id = event["conversation_id"]
        event_ts = event["timestamp_utc"] if pd.notna(event.get("timestamp_utc")) else None
        conv_user = df_sorted[
            (df_sorted["conversation_id"] == conv_id) & (df_sorted["role"] == "user")
        ]
        if event_ts is not None and len(conv_user) > 0:
            before = conv_user[
                pd.to_datetime(conv_user["timestamp_utc"], utc=True, errors="coerce") <= event_ts
            ]
            if len(before) > 0:
                prompt = before.iloc[-1]["text"]
                if isinstance(prompt, str) and len(prompt.strip()) > 5:
                    image_prompts.append(prompt.strip())

    # Style and subject breakdown
    style_counts: Counter = Counter()
    subject_counts: Counter = Counter()
    for p in image_prompts:
        t = p.lower()
        for style, kws in IMAGE_STYLE_KW.items():
            if any(k in t for k in kws):
                style_counts[style] += 1
        for subj, kws in IMAGE_SUBJECT_KW.items():
            if any(k in t for k in kws):
                subject_counts[subj] += 1

    # Top prompt phrases
    top_img_phrases = top_n_phrases(pd.Series(image_prompts), n=10)

    # Sample prompts (ASCII-safe for PDF, trimmed)
    samples = [p[:200] for p in image_prompts[:6]]

    return {
        "confirmed_dalle_count": confirmed_count,
        "prompt_count":          len(image_prompts),
        "style_counts":          dict(style_counts),
        "subject_counts":        dict(subject_counts),
        "top_phrases":           top_img_phrases,
        "sample_prompts":        samples,
    }


# ── Prompt injection analysis ──────────────────────────────────────────────────

def analyse_prompt_injection(df: pd.DataFrame) -> dict:
    """
    Scan all user messages for known prompt injection / jailbreak patterns.
    Returns counts per category, risk level, flagged examples with matched
    pattern info, and per-pattern hit counts for full transparency.
    """
    user_texts = df[df["role"] == "user"]["text"].fillna("").astype(str)

    findings: dict[str, list[dict]] = {cat: [] for cat in INJECTION_PATTERNS}
    cat_counts: Counter = Counter()
    pattern_counts: Counter = Counter()

    for text in user_texts:
        t_lower = text.lower()
        for category, patterns in INJECTION_PATTERNS.items():
            for pat in patterns:
                m = re.search(pat, t_lower)
                if m:
                    cat_counts[category] += 1
                    pattern_counts[f"{category}::{pat}"] += 1
                    if len(findings[category]) < 5:
                        findings[category].append({
                            "text": text[:250].strip(),
                            "matched_pattern": pat,
                            "matched_string": m.group()[:100],
                        })
                    break

    total_flagged = sum(cat_counts.values())
    total_msgs = len(user_texts) or 1
    flag_rate = round(100 * total_flagged / total_msgs, 2)

    # Risk level with explicit thresholds
    if flag_rate == 0:
        risk_level = "None"
    elif flag_rate < 0.5:
        risk_level = "Low"
    elif flag_rate < 2:
        risk_level = "Medium"
    else:
        risk_level = "High"

    # Build reasoning text from actual data
    risk_thresholds = "0% = None | <0.5% = Low | <2% = Medium | >=2% = High"
    if total_flagged == 0:
        reasoning = (
            f"All {total_msgs:,} user messages were scanned against {sum(len(v) for v in INJECTION_PATTERNS.values())} "
            f"regex patterns across 5 attack categories. No matches were found. "
            f"Flag rate is 0.0%, which maps to risk level 'None' "
            f"(thresholds: {risk_thresholds})."
        )
    else:
        cat_detail = ", ".join(
            f"{cat_counts[c]} in {c}" for c in sorted(cat_counts, key=cat_counts.get, reverse=True)
        )
        reasoning = (
            f"Scanned {total_msgs:,} user messages against {sum(len(v) for v in INJECTION_PATTERNS.values())} "
            f"regex patterns across 5 categories. "
            f"Found {total_flagged} flagged messages ({cat_detail}). "
            f"Flag rate is {flag_rate}%, which maps to risk level '{risk_level}' "
            f"(thresholds: {risk_thresholds})."
        )

    # Per-pattern breakdown for full transparency
    pattern_detail = {}
    for key, cnt in pattern_counts.most_common():
        cat, pat = key.split("::", 1)
        pattern_detail.setdefault(cat, []).append({"pattern": pat, "hits": cnt})

    result = {
        "total_flagged":   total_flagged,
        "total_msgs":      total_msgs,
        "flag_rate_pct":   flag_rate,
        "risk_level":      risk_level,
        "risk_thresholds": risk_thresholds,
        "reasoning":       reasoning,
        "category_counts": dict(cat_counts),
        "pattern_detail":  pattern_detail,
        "examples":        {k: v for k, v in findings.items() if v},
        "total_patterns":  sum(len(v) for v in INJECTION_PATTERNS.values()),
        "total_categories": len(INJECTION_PATTERNS),
    }
    return result


# ── Sample Q&A extraction ─────────────────────────────────────────────────────

def _truncate_for_display(text: str, max_len: int = 350) -> str:
    """Truncate text for display, avoiding mid-word cuts."""
    text = (text or "").strip().replace("\n", " ")
    if len(text) <= max_len:
        return text
    cut = text[:max_len].rfind(" ")
    return (text[:cut] if cut > max_len // 2 else text[:max_len]) + "…"


def extract_sample_qa(
    df_msg: pd.DataFrame,
    ai_conv_ids,
    n: int = 8,
) -> list[dict]:
    """
    Extract user question + assistant answer pairs from conversations.
    Prioritizes AI/ML conversations. Returns list of {question, answer, title}.
    """
    df = df_msg[["conversation_id", "conversation_title", "role", "text", "timestamp_utc"]].copy()
    df["text"] = df["text"].fillna("").astype(str)
    df = df.sort_values(["conversation_id", "timestamp_utc"]).reset_index(drop=True)

    pairs: list[dict] = []
    ai_ids_set = {str(x) for x in ai_conv_ids} if ai_conv_ids is not None else set()

    for conv_id, grp in df.groupby("conversation_id"):
        rows = grp.reset_index(drop=True)
        for i in range(len(rows) - 1):
            u_row = rows.iloc[i]
            a_row = rows.iloc[i + 1]
            if u_row["role"] == "user" and a_row["role"] == "assistant":
                q = _truncate_for_display(u_row["text"], 350)
                a = _truncate_for_display(a_row["text"], 450)
                title = (u_row.get("conversation_title") or "").strip() or "(no title)"
                if len(q) > 15 and len(a) > 20:
                    pairs.append({
                        "question": q,
                        "answer": a,
                        "title": title,
                        "is_ai_ml": str(conv_id) in ai_ids_set,
                    })

    ai_pairs = [p for p in pairs if p["is_ai_ml"]]
    other_pairs = [p for p in pairs if not p["is_ai_ml"]]
    selected = (ai_pairs[:n] if len(ai_pairs) >= n else
                ai_pairs + other_pairs[: n - len(ai_pairs)])
    for p in selected:
        p.pop("is_ai_ml", None)
    return selected[:n]


# ── Core analysis ──────────────────────────────────────────────────────────────

def analyse(df_msg: pd.DataFrame, df_ses: Optional[pd.DataFrame]) -> dict:
    user_df = df_msg[df_msg["role"] == "user"].copy()
    user_df["text"] = user_df["text"].fillna("").astype(str)

    user_df["domain"] = user_df["text"].apply(classify_domain)
    domain_counts    = user_df["domain"].value_counts().to_dict()
    total_user_msgs  = len(user_df)

    ai_df = user_df[user_df["domain"] == "ai_ml_llm"]

    ai_sub: Counter = Counter()
    for _, row in ai_df.iterrows():
        t = row["text"].lower()
        tagged = False
        if count_kw(t, RESEARCH_KW):
            ai_sub["research"] += 1
            tagged = True
        if count_kw(t, BRAINSTORM_KW):
            ai_sub["brainstorming"] += 1
            tagged = True
        if count_kw(t, CODE_KW):
            ai_sub["code"] += 1
            tagged = True
        if not tagged:
            ai_sub["concept_explanation"] += 1

    ai_conv_ids   = ai_df["conversation_id"].unique()
    sample_titles = (
        df_msg[df_msg["conversation_id"].isin(ai_conv_ids)]["conversation_title"]
        .dropna().unique().tolist()[:25]
    )

    sample_qa = extract_sample_qa(df_msg, ai_conv_ids, n=8)

    tone        = infer_tone_preferences(user_df["text"])
    avg_len_all = round(float(user_df["text"].str.len().mean()))
    avg_len_ai  = round(float(ai_df["text"].str.len().mean())) if len(ai_df) else 0

    ses_stats: dict = {}
    if df_ses is not None and len(df_ses) > 0:
        for col in ["duration_min", "messages", "turns", "tokens_total"]:
            if col in df_ses.columns:
                ses_stats[col] = round(float(df_ses[col].median()), 1)

    peak_hour = -1
    if "timestamp_utc" in df_msg.columns:
        ts = pd.to_datetime(df_msg["timestamp_utc"], utc=True, errors="coerce")
        hour_counts = ts.dt.hour.value_counts()
        if len(hour_counts):
            peak_hour = int(hour_counts.idxmax())

    image_stats     = analyse_images(df_msg)
    injection_stats = analyse_prompt_injection(df_msg)

    return {
        "total_user_msgs":  total_user_msgs,
        "domain_counts":    domain_counts,
        "ai_sub_counts":    dict(ai_sub),
        "top_phrases_ai":   top_n_phrases(ai_df["text"], n=20),
        "tone":             tone,
        "avg_len_all":      avg_len_all,
        "avg_len_ai":       avg_len_ai,
        "ses_stats":        ses_stats,
        "peak_hour":        peak_hour,
        "sample_titles":    sample_titles,
        "sample_qa":        sample_qa,
        "image_stats":      image_stats,
        "injection_stats":  injection_stats,
    }


# ── Markdown report ────────────────────────────────────────────────────────────

def build_markdown(stats: dict) -> str:
    dc       = stats["domain_counts"]
    total    = stats["total_user_msgs"] or 1
    tone     = stats["tone"]
    ai_pct   = round(100 * dc.get("ai_ml_llm", 0) / total)
    sub      = stats["ai_sub_counts"]
    sub_total = sum(sub.values()) or 1
    img      = stats["image_stats"]
    inj      = stats["injection_stats"]

    lines: list[str] = []
    lines += [
        "# Custom Instruction Generation Report",
        "",
        "_Generated by `generate_custom_instructions.py` — source: conversation history export._",
        "",
        "---",
        "",
        "## 1. Conversation Profile Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total user messages analysed | {total} |",
        f"| AI / ML / LLM share | {ai_pct}% |",
        f"| Average message length (all topics) | {stats['avg_len_all']} chars |",
        f"| Average message length (AI topics) | {stats['avg_len_ai']} chars |",
    ]
    if stats["peak_hour"] >= 0:
        lines.append(f"| Peak usage hour (UTC) | {stats['peak_hour']}:00 |")
    for k, v in stats["ses_stats"].items():
        lines.append(f"| Session median {k} | {v} |")
    lines.append("")

    # Domain breakdown
    lines += ["## 2. Domain Breakdown", ""]
    for domain, cnt in sorted(dc.items(), key=lambda x: x[1], reverse=True):
        pct = round(100 * cnt / total)
        bar = "█" * max(1, pct // 5)
        lines.append(f"- **{domain}** — {cnt} msgs ({pct}%)  {bar}")
    lines.append("")

    # AI sub-categories
    lines += ["## 3. AI / ML / LLM Sub-Category Breakdown", ""]
    for sub_cat, cnt in sorted(sub.items(), key=lambda x: x[1], reverse=True):
        pct = round(100 * cnt / sub_total)
        lines.append(f"- **{sub_cat}** — {cnt} msgs ({pct}%)")
    lines.append("")

    # Tone
    lines += [
        "## 4. Inferred Tone Preferences",
        "",
        f"- Concise / direct answers : **{tone['concise']}%**",
        f"- Detailed explanations    : **{tone['detailed']}%**",
        f"- Examples / snippets      : **{tone['examples']}%**",
        "",
    ]

    # Top phrases
    lines += ["## 5. Top Recurring Topics (AI/ML conversations)", ""]
    for phrase, cnt in stats["top_phrases_ai"][:15]:
        lines.append(f"- `{phrase}` ({cnt}×)")
    lines.append("")

    # Sample titles
    lines += ["## 6. Sample AI/ML/LLM Conversation Titles", ""]
    for t in stats["sample_titles"][:20]:
        lines.append(f"- {t}")
    lines.append("")

    # Sample Q&A (from your data)
    sample_qa = stats.get("sample_qa", [])
    if sample_qa:
        lines += ["## 6a. Sample Questions & Answers (from your data)", ""]
        for i, pa in enumerate(sample_qa, 1):
            lines.append(f"**{i}. _{pa.get('title', '')}_**")
            lines.append("")
            lines.append(f"- **Q:** {pa['question']}")
            lines.append("")
            lines.append(f"- **A:** {pa['answer']}")
            lines.append("")
        lines.append("")

    # Image generation metadata
    lines += [
        "---",
        "",
        "## 7. Image Generation Metadata",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Confirmed DALL-E generations (tool events) | {img['confirmed_dalle_count']} |",
        f"| Matched user prompts recovered | {img['prompt_count']} |",
        "",
    ]
    if img["style_counts"]:
        lines += ["**Style distribution:**", ""]
        for style, cnt in sorted(img["style_counts"].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- {style}: {cnt}")
        lines.append("")
    if img["subject_counts"]:
        lines += ["**Subject distribution:**", ""]
        for subj, cnt in sorted(img["subject_counts"].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- {subj}: {cnt}")
        lines.append("")
    if img["top_phrases"]:
        lines += ["**Top image prompt phrases:**", ""]
        for phrase, cnt in img["top_phrases"][:8]:
            lines.append(f"- `{phrase}` ({cnt}×)")
        lines.append("")
    if img["sample_prompts"]:
        lines += ["**Sample image prompts:**", ""]
        for i, p in enumerate(img["sample_prompts"], 1):
            lines.append(f"{i}. _{p}_")
        lines.append("")

    # Prompt injection analysis
    lines += [
        "## 8. Prompt Injection & Security Analysis",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total user messages scanned | {inj['total_msgs']:,} |",
        f"| Regex patterns checked | {inj['total_patterns']} |",
        f"| Attack categories | {inj['total_categories']} |",
        f"| Flagged messages | {inj['total_flagged']} |",
        f"| Flag rate | {inj['flag_rate_pct']}% |",
        f"| Risk level | **{inj['risk_level']}** |",
        "",
        "### Risk Level Reasoning",
        "",
        f"> {inj['reasoning']}",
        "",
        "**Threshold scale:**",
        "",
        "| Flag Rate | Risk Level | Meaning |",
        "|-----------|------------|---------|",
        "| 0% | None | No injection patterns detected |",
        "| < 0.5% | Low | Rare occurrences, likely incidental |",
        "| < 2% | Medium | Notable pattern; review flagged messages |",
        "| ≥ 2% | High | Frequent injection attempts detected |",
        "",
    ]

    # Per-category breakdown with exact pattern hits
    lines += ["### Per-Category Results", ""]
    cat_counts = inj["category_counts"]
    pattern_detail = inj.get("pattern_detail", {})
    for cat_key, cat_label in INJECTION_CAT_LABELS.items():
        hits = cat_counts.get(cat_key, 0)
        mark = "⚠" if hits > 0 else "✓"
        lines.append(f"- {mark} **{cat_label}**: {hits} hit(s)")
        if cat_key in pattern_detail:
            for pat_entry in pattern_detail[cat_key]:
                lines.append(f"  - `{pat_entry['pattern']}` → {pat_entry['hits']} hit(s)")
    lines.append("")

    if inj["examples"]:
        lines += ["### Flagged Message Evidence", ""]
        for cat, items in inj["examples"].items():
            lines.append(f"**{INJECTION_CAT_LABELS.get(cat, cat)}** — {len(items)} example(s):")
            lines.append("")
            for item in items:
                lines.append(f"> \"{item['text'][:200]}{'…' if len(item['text']) > 200 else ''}\"")
                lines.append(f">")
                lines.append(f"> *Matched pattern:* `{item['matched_pattern']}` → *Match:* `{item['matched_string'][:80]}`")
                lines.append("")
    else:
        lines += [
            f"✓ **All {inj['total_msgs']:,} user messages passed "
            f"{inj['total_patterns']} regex checks across "
            f"{inj['total_categories']} attack categories with zero matches.**",
            "",
        ]

    # Custom instruction
    lines += [
        "---",
        "",
        "## 9. Generated Custom Instruction",
        "",
        "> Copy the block below directly into your chatbot's **Custom Instructions** field.",
        "",
        "```",
        build_custom_instruction(stats),
        "```",
        "",
    ]

    return "\n".join(lines)


def build_custom_instruction(stats: dict) -> str:
    tone     = stats["tone"]
    sub      = stats["ai_sub_counts"]
    dominant = max(sub, key=sub.get) if sub else "concept_explanation"

    if tone["concise"] >= tone["detailed"] and tone["concise"] >= tone["examples"]:
        tone_line = "Be concise and direct. Lead with the answer; add depth only when I ask."
    elif tone["detailed"] >= tone["concise"] and tone["detailed"] >= tone["examples"]:
        tone_line = (
            "Provide thorough, step-by-step explanations with reasoning, "
            "trade-offs, and relevant caveats."
        )
    else:
        tone_line = (
            "Include concrete code examples and runnable snippets to "
            "illustrate every key point."
        )

    sub_focus_map = {
        "code": (
            "I frequently ask you to write, debug, and refactor production-quality code. "
            "Show minimal diffs when possible; prefer clean, typed Python."
        ),
        "research": (
            "I regularly explore academic papers, SOTA models, and technical literature. "
            "Summarise papers as: motivation -> method -> results -> limitations + arXiv ID."
        ),
        "brainstorming": (
            "I often use you for architecture design and idea-exploration sessions. "
            "Offer 2-3 ranked alternatives with explicit trade-offs using comparison tables."
        ),
        "concept_explanation": (
            "I often need clear conceptual explanations of AI/ML mechanisms. "
            "Use analogies and diagrams (ASCII / Mermaid) when they aid understanding."
        ),
    }
    sub_line = sub_focus_map.get(dominant, "I work across multiple AI/ML domains.")

    top_phrases = [p for p, _ in stats["top_phrases_ai"][:8]
                   if p.isascii()]  # keep only clean ASCII phrases
    phrase_list = (
        ", ".join(f'"{p}"' for p in top_phrases)
        if top_phrases
        else '"LLMs", "RAG", "fine-tuning", "agents"'
    )

    img   = stats["image_stats"]
    img_note = (
        f"I have generated {img['confirmed_dalle_count']} images via DALL-E. "
        "When I ask for image generation prompts, focus on clarity, style keywords, "
        "and composition — avoid vague descriptions."
        if img["confirmed_dalle_count"] > 0 else ""
    )

    inj   = stats["injection_stats"]
    inj_note = (
        f"Security note: {inj['total_flagged']} messages flagged for injection-like patterns "
        f"(risk: {inj['risk_level']}). Maintain safety boundaries at all times."
        if inj["total_flagged"] > 0 else ""
    )

    parts = [
        """\
ROLE & CONTEXT
You are a senior AI/ML research and engineering assistant supporting a professional
working in the AI, Machine Learning, and LLM space. Treat all work as business-grade:
accuracy, reproducibility, and production-readiness always matter.""",

        f"""\
DOMAIN FOCUS
Primary  : LLMs, RAG pipelines, fine-tuning (LoRA/QLoRA), agentic systems, ML model
           evaluation, MLOps, embeddings, and vector databases.
Secondary: Applied Python, data pipelines, experiment tracking, and research synthesis.
My most frequent topics: {phrase_list}.""",

        """\
SESSION TYPES
1. CODE        -- Write clean Python with type hints and docstrings. State root cause
                  first when debugging. Prefer minimal diffs over full rewrites.
2. RESEARCH    -- Summarise papers as motivation -> method -> results -> limitations.
                  Include arXiv ID. Compare to baselines. Flag reproducibility issues.
3. BRAINSTORM  -- Present 2-3 ranked options with explicit trade-offs.
                  Use tables for comparisons. Reason about failure modes.""",

        f"""\
TONE & FORMAT
{tone_line}
Use Markdown with clear headings. Use fenced code blocks for all code and commands.
Never pad responses with filler text. If uncertain, say so and suggest how to verify.""",

        sub_line,

        """\
BUSINESS CONSTRAINTS
- Prefer open-source or cost-efficient solutions unless told otherwise.
- Proactively surface latency, cost, and privacy implications.
- Optimise recommendations for production deployability, not just prototypes.""",
    ]

    if img_note:
        parts.append(f"IMAGE GENERATION\n{img_note}")
    if inj_note:
        parts.append(f"SECURITY\n{inj_note}")

    parts.append("""\
ALWAYS
- Ask one clarifying question if the request is ambiguous rather than guessing.
- End complex answers with a short "Next steps" or "Follow-up questions" section.
- Proactively flag known pitfalls in the approach I am taking.""")

    return "\n\n".join(parts)


# ── PDF export ─────────────────────────────────────────────────────────────────

def build_pdf(stats: dict, out_path: Path) -> None:
    """Export report as a PDF. Requires fpdf2 (`pip install fpdf2`)."""
    try:
        from fpdf import FPDF  # type: ignore
    except ImportError:
        print("WARNING: fpdf2 not installed. Skipping PDF export. Run: pip install fpdf2")
        return

    dc       = stats["domain_counts"]
    total    = stats["total_user_msgs"] or 1
    tone     = stats["tone"]
    ai_pct   = round(100 * dc.get("ai_ml_llm", 0) / total)
    sub      = stats["ai_sub_counts"]
    sub_total = sum(sub.values()) or 1
    img      = stats["image_stats"]
    inj      = stats["injection_stats"]

    class Report(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(80, 80, 80)
            self.cell(0, 8, "Custom Instruction Generation Report", align="R")
            self.ln(4)
            self.set_draw_color(200, 200, 200)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def safe_text(text: str) -> str:
        return ascii_safe(str(text))

    pdf = Report()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 12, "Custom Instruction Generation Report",
             new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, "Generated from your conversation history export",
             new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(6)

    W = pdf.epw  # effective page width

    def section(title: str, level: int = 2):
        pdf.ln(4)
        pdf.set_x(pdf.l_margin)
        if level == 2:
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(20, 80, 160)
        else:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(60, 60, 60)
        pdf.cell(W, 8, safe_text(title), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        pdf.set_text_color(30, 30, 30)

    def row(label: str, value: str):
        pdf.set_x(pdf.l_margin)
        col1, col2 = 80, W - 80
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(col1, 6, safe_text(label), border="B")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(col2, 6, safe_text(value)[:60], border="B", new_x="LMARGIN", new_y="NEXT")

    def bullet(text: str):
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(W, 5, f"  - {safe_text(text)}")

    def body(text: str):
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(W, 5, safe_text(text))

    # 1. Summary
    section("1. Conversation Profile Summary")
    row("Total user messages", str(total))
    row("AI / ML / LLM share", f"{ai_pct}%")
    row("Avg message length (all topics)", f"{stats['avg_len_all']} chars")
    row("Avg message length (AI topics)", f"{stats['avg_len_ai']} chars")
    if stats["peak_hour"] >= 0:
        row("Peak usage hour (UTC)", f"{stats['peak_hour']}:00")
    for k, v in stats["ses_stats"].items():
        row(f"Session median {k}", str(v))
    pdf.ln(3)

    # 2. Domain breakdown
    section("2. Domain Breakdown")
    for domain, cnt in sorted(dc.items(), key=lambda x: x[1], reverse=True):
        pct = round(100 * cnt / total)
        bullet(f"{domain}: {cnt} msgs ({pct}%)")

    # 3. AI sub-categories
    section("3. AI/ML/LLM Sub-Category Breakdown")
    for sub_cat, cnt in sorted(sub.items(), key=lambda x: x[1], reverse=True):
        pct = round(100 * cnt / sub_total)
        bullet(f"{sub_cat}: {cnt} msgs ({pct}%)")

    # 4. Tone
    section("4. Inferred Tone Preferences")
    bullet(f"Concise / direct: {tone['concise']}%")
    bullet(f"Detailed explanations: {tone['detailed']}%")
    bullet(f"Examples / snippets: {tone['examples']}%")

    # 5. Top phrases
    section("5. Top Recurring Topics (AI/ML)")
    for phrase, cnt in stats["top_phrases_ai"][:12]:
        bullet(f"{phrase} ({cnt}x)")

    # 6. Sample titles
    section("6. Sample AI/ML/LLM Conversation Titles")
    for t in stats["sample_titles"][:15]:
        bullet(t)

    # 6a. Sample Q&A (from your data)
    sample_qa = stats.get("sample_qa", [])
    if sample_qa:
        pdf.ln(2)
        section("6a. Sample Questions & Answers (from your data)")
        for i, pa in enumerate(sample_qa[:4], 1):
            pdf.set_font("Helvetica", "BI", 9)
            pdf.cell(0, 5, safe_text(f"{i}. {pa.get('title', '')}"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            pdf.set_x(pdf.l_margin + 4)
            pdf.multi_cell(W - 4, 4, safe_text(f"Q: {pa['question'][:200]}"))
            pdf.set_x(pdf.l_margin + 4)
            pdf.multi_cell(W - 4, 4, safe_text(f"A: {pa['answer'][:250]}"))
            pdf.ln(1)

    # 7. Image metadata
    pdf.add_page()
    section("7. Image Generation Metadata")
    row("Confirmed DALL-E generations", str(img["confirmed_dalle_count"]))
    row("Matched user prompts recovered", str(img["prompt_count"]))
    pdf.ln(2)
    if img["style_counts"]:
        section("Style Distribution", level=3)
        for style, cnt in sorted(img["style_counts"].items(), key=lambda x: x[1], reverse=True):
            bullet(f"{style}: {cnt}")
    if img["subject_counts"]:
        section("Subject Distribution", level=3)
        for subj, cnt in sorted(img["subject_counts"].items(), key=lambda x: x[1], reverse=True):
            bullet(f"{subj}: {cnt}")
    if img["sample_prompts"]:
        section("Sample Image Prompts", level=3)
        for i, p in enumerate(img["sample_prompts"], 1):
            body(f"{i}. {p}")

    # 8. Prompt injection
    section("8. Prompt Injection & Security Analysis")
    row("Total messages scanned", f"{inj['total_msgs']:,}")
    row("Regex patterns checked", str(inj["total_patterns"]))
    row("Attack categories", str(inj["total_categories"]))
    row("Flagged messages", str(inj["total_flagged"]))
    row("Flag rate", f"{inj['flag_rate_pct']}%")
    row("Risk level", inj["risk_level"])
    pdf.ln(2)

    section("Risk Level Reasoning", level=3)
    body(safe_text(inj["reasoning"]))
    pdf.ln(1)

    section("Threshold Scale", level=3)
    body("0% = None | < 0.5% = Low | < 2% = Medium | >= 2% = High")
    pdf.ln(2)

    section("Per-Category Results", level=3)
    pattern_detail = inj.get("pattern_detail", {})
    for cat_key, cat_label in INJECTION_CAT_LABELS.items():
        hits = inj["category_counts"].get(cat_key, 0)
        mark = "!" if hits > 0 else "OK"
        bullet(f"[{mark}] {cat_label}: {hits} hit(s)")
        if cat_key in pattern_detail:
            for pat_entry in pattern_detail[cat_key]:
                pdf.set_font("Courier", "", 7)
                pdf.set_x(pdf.l_margin + 10)
                pdf.multi_cell(W - 10, 3.5, safe_text(f"{pat_entry['pattern']} -> {pat_entry['hits']} hit(s)"))
                pdf.set_font("Helvetica", "", 9)
    pdf.ln(1)

    if inj["examples"]:
        section("Flagged Message Evidence", level=3)
        for cat, items in inj["examples"].items():
            pdf.set_font("Helvetica", "BI", 9)
            pdf.cell(0, 5, f"{INJECTION_CAT_LABELS.get(cat, cat)} - {len(items)} example(s):",
                     new_x="LMARGIN", new_y="NEXT")
            for item in items:
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(80, 80, 80)
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(W, 4, safe_text(f"\"{item['text'][:200]}\""))
                pdf.set_font("Courier", "", 7)
                pdf.set_text_color(100, 80, 140)
                pdf.set_x(pdf.l_margin + 4)
                pdf.multi_cell(W - 4, 3.5, safe_text(f"Pattern: {item['matched_pattern']} -> \"{item['matched_string'][:80]}\""))
                pdf.set_text_color(30, 30, 30)
            pdf.ln(1)
    else:
        body(safe_text(f"All {inj['total_msgs']:,} user messages passed {inj['total_patterns']} "
               f"regex checks across {inj['total_categories']} attack categories with zero matches."))
        pdf.ln(2)

    # 9. Custom instruction
    pdf.add_page()
    section("9. Generated Custom Instruction")
    body("Copy the text below directly into your chatbot's Custom Instructions field.")
    pdf.ln(2)
    instruction = build_custom_instruction(stats)
    pdf.set_font("Courier", "", 8)
    pdf.set_fill_color(245, 245, 245)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(W, 4.5, safe_text(instruction), fill=True)

    pdf.output(str(out_path))
    print(f"PDF written    -> {out_path}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Generate a custom-instruction report from your conversation history."
    )
    ap.add_argument("--tagged",   default="outputs/messages_tagged.csv",
                    help="Path to messages_tagged.csv")
    ap.add_argument("--sessions", default="outputs/sessions_summary.csv",
                    help="Path to sessions_summary.csv")
    ap.add_argument("--out",      default="outputs/custom_instructions_report",
                    help="Output base path (no extension; .md always written, .pdf with --pdf)")
    ap.add_argument("--pdf",      action="store_true",
                    help="Also export a PDF report (requires fpdf2)")
    args = ap.parse_args()

    tagged_path   = Path(args.tagged)
    sessions_path = Path(args.sessions)
    out_base      = Path(args.out)
    out_base.parent.mkdir(parents=True, exist_ok=True)

    if not tagged_path.exists():
        raise FileNotFoundError(
            f"Tagged messages file not found: {tagged_path}\n"
            "Run tag_use_cases.py first:  python scripts/tag_use_cases.py"
        )

    df_msg = pd.read_csv(tagged_path, encoding="utf-8", low_memory=False)
    df_ses = (
        pd.read_csv(sessions_path, encoding="utf-8", low_memory=False)
        if sessions_path.exists() else None
    )

    stats = analyse(df_msg, df_ses)

    # Markdown
    md_path = out_base.with_suffix(".md")
    md_path.write_text(build_markdown(stats), encoding="utf-8")
    print(f"Markdown written -> {md_path}")

    # PDF
    if args.pdf:
        pdf_path = out_base.with_suffix(".pdf")
        build_pdf(stats, pdf_path)

    print()
    print("=== Quick stats ===")
    print(f"Total user messages : {stats['total_user_msgs']}")
    print(f"Domain breakdown    : {stats['domain_counts']}")
    print(f"AI sub-categories   : {stats['ai_sub_counts']}")
    print(f"Tone split          : {stats['tone']}")
    print()
    img = stats["image_stats"]
    print(f"Image generations   : {img['confirmed_dalle_count']} DALL-E events confirmed")
    print(f"Image styles        : {img['style_counts']}")
    inj = stats["injection_stats"]
    print(f"Injection scan      : {inj['total_flagged']} flagged / {inj['total_msgs']} msgs "
          f"({inj['flag_rate_pct']}%) — risk: {inj['risk_level']}")
    print()
    print("Open the report for your ready-to-paste custom instruction.")


if __name__ == "__main__":
    main()
