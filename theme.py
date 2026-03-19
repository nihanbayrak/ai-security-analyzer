"""
N26-inspired dark theme for AI Security Analyzer 2026.
Colors: #0F1117 bg, #1A1D27 cards, #6366F1 indigo primary.
Severity: #EF4444 critical, #F59E0B high, #EAB308 medium, #3B82F6 low, #10B981 safe.
"""

import gradio as gr

SEV_COLORS = {
    "Critical": "#EF4444",
    "High":     "#F59E0B",
    "Medium":   "#EAB308",
    "Low":      "#3B82F6",
    "Info":     "#10B981",
}


def get_theme() -> gr.themes.Base:
    return gr.themes.Base(
        primary_hue=gr.themes.colors.indigo,
        secondary_hue=gr.themes.colors.purple,
        neutral_hue=gr.themes.colors.slate,
        font=gr.themes.GoogleFont("Inter"),
        font_mono=gr.themes.GoogleFont("JetBrains Mono"),
    ).set(
        body_background_fill="#0F1117",
        body_background_fill_dark="#0F1117",
        block_background_fill="#1A1D27",
        block_background_fill_dark="#1A1D27",
        block_border_color="#2A2D3A",
        block_border_color_dark="#2A2D3A",
        block_label_text_color="#94A3B8",
        block_label_text_color_dark="#94A3B8",
        body_text_color="#E2E8F0",
        body_text_color_dark="#E2E8F0",
        button_primary_background_fill="#6366F1",
        button_primary_background_fill_dark="#6366F1",
        button_primary_background_fill_hover="#7C3AED",
        button_primary_background_fill_hover_dark="#7C3AED",
        button_primary_text_color="#FFFFFF",
        button_secondary_background_fill="#1A1D27",
        button_secondary_border_color="#2A2D3A",
        input_background_fill="#0F1117",
        input_background_fill_dark="#0F1117",
        input_border_color="#2A2D3A",
    )


DARK_CSS = """
/* Force dark mode */
body, .gradio-container { background: #0F1117 !important; color: #E2E8F0 !important; }

/* Glassmorphism stat cards */
.stat-card {
    background: rgba(26, 29, 39, 0.85);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(99, 102, 241, 0.15);
    border-radius: 16px;
    padding: 24px;
    text-align: center;
    transition: border-color 0.2s ease;
}
.stat-card:hover { border-color: rgba(99, 102, 241, 0.4); }

/* Big risk score number */
.risk-score-number {
    font-size: 72px;
    font-weight: 800;
    background: linear-gradient(135deg, #6366F1, #8B5CF6);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    line-height: 1;
}

/* Severity badge colors */
.badge-critical { color: #EF4444; font-weight: 700; }
.badge-high     { color: #F59E0B; font-weight: 700; }
.badge-medium   { color: #EAB308; font-weight: 700; }
.badge-low      { color: #3B82F6; font-weight: 700; }
.badge-info     { color: #10B981; font-weight: 700; }

/* Tab headers */
.tab-nav button {
    background: #1A1D27 !important;
    border: 1px solid #2A2D3A !important;
    color: #94A3B8 !important;
    border-radius: 8px !important;
    margin: 2px !important;
}
.tab-nav button.selected {
    background: #6366F1 !important;
    color: #FFFFFF !important;
    border-color: #6366F1 !important;
}

/* Dataframe table */
.dataframe thead th {
    background: #1E2130 !important;
    color: #94A3B8 !important;
    font-size: 12px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
}
.dataframe tbody tr:hover { background: rgba(99, 102, 241, 0.08) !important; }

/* Wipe button */
.wipe-btn { border-color: #EF4444 !important; color: #EF4444 !important; }
.wipe-btn:hover { background: #EF4444 !important; color: white !important; }

/* Score breakdown panel */
.score-breakdown {
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    background: #0F1117;
    border: 1px solid #2A2D3A;
    border-radius: 8px;
    padding: 16px;
    color: #94A3B8;
}

/* Supervisor badge */
.sup-validated   { color: #10B981; font-size: 11px; }
.sup-unvalidated { color: #F59E0B; font-size: 11px; }
"""

FORCE_DARK_JS = "() => document.body.classList.add('dark')"
