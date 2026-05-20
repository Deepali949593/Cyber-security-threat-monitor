import os
import streamlit as st
import streamlit.components.v1 as components
from sqlalchemy import text
from dotenv import load_dotenv
from google import genai
from google.genai import types

# 1. Page Configuration
st.set_page_config(
    page_title="Cyber Threat Agent — Real-Time SOC AI", 
    page_icon="🛡️", 
    layout="centered",
    initial_sidebar_state="collapsed"
)

# 2. Query URL state checker to clear messages cleanly
if "clear_session_trigger" in st.query_params:
    st.session_state.messages = []
    if "chat_session" in st.session_state:
        del st.session_state.chat_session
    st.query_params.clear()
    st.rerun()

# 3. Streamlit Native Styling Fixes
st.markdown("""
    <style>
    :root {
      --background: oklch(0.16 0.025 260);
      --foreground: oklch(0.96 0.01 220);
      --card: oklch(0.20 0.028 260);
      --muted: oklch(0.22 0.025 260);
      --muted-foreground: oklch(0.70 0.025 240);
      --border: oklch(0.30 0.03 260 / 60%);
      --input: oklch(0.26 0.03 260);
      --primary: oklch(0.78 0.18 165);
      --primary-foreground: oklch(0.15 0.03 260);
      --shadow-glow: 0 0 0 1px oklch(0.78 0.18 165 / 20%), 0 10px 40px -10px oklch(0.78 0.18 165 / 35%);
      --gradient-grid:
        linear-gradient(oklch(0.30 0.04 260 / 40%) 1px, transparent 1px),
        linear-gradient(90deg, oklch(0.30 0.04 260 / 40%) 1px, transparent 1px);
      --gradient-glow: radial-gradient(circle at 20% 0%, oklch(0.78 0.18 165 / 18%), transparent 55%);
    }

    .stApp, [data-testid="stAppViewContainer"] {
        background-color: var(--background) !important;
        background-image: var(--gradient-glow) !important;
        background-attachment: fixed !important;
        color: var(--foreground) !important;
    }
    
    [data-testid="stHeader"], footer { visibility: hidden !important; }
    .block-container { max-width: 768px !important; padding-top: 1.5rem !important; }

    .custom-grid-backdrop {
        position: fixed; inset: 0; pointer-events: none; opacity: .6; z-index: 0;
        background-image: var(--gradient-grid); background-size: 32px 32px;
        mask-image: radial-gradient(ellipse at top, black 30%, transparent 75%);
        -webkit-mask-image: radial-gradient(ellipse at top, black 30%, transparent 75%);
    }

    /* Onboarding Layout */
    .empty { display: flex; flex-direction: column; align-items: center; gap: 16px; padding: 40px 0; text-align: center; }
    .empty h2 { margin: 0; font-size: 18px; letter-spacing: -.01em; text-shadow: 0 0 24px oklch(0.78 0.18 165 / 50%); color: #ffffff; }
    .empty p { margin: 6px auto 0; max-width: 28rem; color: var(--muted-foreground); font-size: 14px; }

    /* Tool & Component Blocks */
    .tool { border: 1px solid color-mix(in oklab, var(--primary) 20%, var(--border)); background: color-mix(in oklab, var(--card) 60%, transparent); border-radius: 10px; overflow: hidden; margin-bottom: 12px; width: 100%; }
    .tool-header-css { display: flex; align-items: center; justify-content: space-between; padding: 12px; background: none; border: 0; color: inherit; width: 100%; }
    .tool-header-css .left { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 500; color: #ffffff; }
    .tool-header-css .badge { display: inline-flex; align-items: center; gap: 6px; padding: 2px 8px; font-size: 11px; border-radius: 999px; background: color-mix(in oklab, var(--muted) 70%, transparent); border: 1px solid var(--border); color: oklch(0.78 0.18 165); }
    .tool-content-css { padding: 0 12px 12px; border-top: 1px solid var(--border); background: rgba(0,0,0,0.2); }
    .tool-section-label { font-size: 11px; text-transform: uppercase; letter-spacing: .15em; color: var(--muted-foreground); margin: 8px 0 6px; }
    pre.code { background: color-mix(in oklab, var(--muted) 40%, transparent); border-radius: 6px; padding: 8px; font: 500 11px/1.5 \"JetBrains Mono\", monospace; color: var(--muted-foreground); overflow-x: auto; margin: 0; border: 1px solid var(--border); }

    .spike-list { display: flex; flex-direction: column; gap: 8px; margin-top: 5px; }
    .spike { position: relative; overflow: hidden; border: 1px solid var(--border); border-radius: 10px; background: color-mix(in oklab, var(--card) 80%, transparent); padding: 12px; }
    .spike.critical { box-shadow: var(--shadow-alert); border-color: oklch(0.62 0.24 25); }
    .spike-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .spike-target { display: flex; align-items: center; gap: 8px; }
    .spike-target span { font: 600 12px/1 \"JetBrains Mono\", monospace; letter-spacing: .1em; text-transform: uppercase; color: #ffffff; }
    .spike-msg { margin: 8px 0 0; font-size: 14px; color: oklch(0.96 0.01 220 / 90%); line-height: 1.4; }
    .spike-meta { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 4px 12px; font: 500 10px/1 \"JetBrains Mono\", monospace; color: var(--muted-foreground); letter-spacing: .12em; text-transform: uppercase; }

    .kw-pill { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border); background: color-mix(in oklab, var(--muted) 30%, transparent); max-width: 280px; margin-top: 5px; }
    .kw-pill.active { color: var(--primary); background: color-mix(in oklab, var(--primary) 5%, transparent); border-color: var(--primary); }
    .kw-pill .kw { font: 500 12px/1 \"JetBrains Mono\", monospace; text-transform: uppercase; letter-spacing: .1em; color: #ffffff; }
    .kw-pill .state { margin-left: auto; padding: 2px 6px; font-size: 10px; letter-spacing: .15em; text-transform: uppercase; background: rgba(0,0,0,0.3); border-radius: 3px; }
    .assistant-text-layout { font-size: 14px; line-height: 1.6; color: var(--foreground); margin-top: 10px; }

    /* Input Frame Adjustments */
    .stChatInputContainer {
        background-color: color-mix(in oklab, var(--input) 80%, transparent) !important;
        border: 1px solid var(--border) !important;
        border-radius: 14px !important;
        box-shadow: var(--shadow-glow) !important;
        padding-bottom: 34px !important;
        position: relative !important;
    }
    .stChatInputContainer:focus-within { border-color: var(--primary) !important; }
    .stChatInputContainer button { bottom: 8px !important; right: 12px !important; background-color: var(--primary) !important; color: var(--primary-foreground) !important; border-radius: 8px !important; width: 32px !important; height: 32px !important; }
    
    .stChatInputContainer::after {
        content: "● SECURE CHANNEL  ·  GEMINI 3 FLASH";
        position: absolute; bottom: 14px; left: 14px; font-family: "JetBrains Mono", monospace; font-size: 10px; font-weight: 500; letter-spacing: .18em; color: var(--muted-foreground); pointer-events: none;
    }
    </style>
    <div class="custom-grid-backdrop"></div>
""", unsafe_allow_html=True)

# 4. Load database and settings
load_dotenv()
from database.connection import engine

WRENCH_SVG = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a4 4 0 0 0 5 5L21 13l-8 8-5-5 8-8 1.7-1.7z"/></svg>'
CHECK_SVG = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>'
ALERT_SVG = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'

if "messages" not in st.session_state:
    st.session_state.messages = []

# =====================================================================
# 🏛️ FIXED BRAND INJECTION (ISOLATED EMBEDDED RENDER)
# =====================================================================
is_empty_history = "disabled" if len(st.session_state.messages) == 0 else ""

header_html_component = f"""
<!DOCTYPE html>
<html>
<head>
<style>
body {{
    margin: 0; padding: 0; background: transparent; overflow: hidden;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}}
.soc-header-row {{
    display: flex; align-items: center; justify-content: space-between;
    padding-bottom: 10px; border-bottom: 1px solid oklch(0.30 0.03 260 / 60%); width: 100%;
}}
.soc-brand-group {{ display: flex; align-items: center; gap: 12px; }}
.soc-logo-wrap {{ position: relative; display: inline-block; }}
.soc-logo {{
    width: 36px; height: 36px; border-radius: 8px;
    background: radial-gradient(circle at 30% 30%, oklch(0.85 0.18 165), oklch(0.55 0.18 165));
    display: grid; place-items: center;
    box-shadow: 0 0 0 1px oklch(0.78 0.18 165 / 20%), 0 10px 40px -10px oklch(0.78 0.18 165 / 35%);
}}
.soc-online-dot {{
    position: absolute; bottom: -2px; right: -2px; width: 10px; height: 10px;
    border-radius: 999px; background: oklch(0.78 0.18 165); box-shadow: 0 0 0 2px oklch(0.16 0.025 260);
}}
.soc-text-group {{ display: flex; flex-direction: column; justify-content: center; }}
.soc-text-group h1 {{ margin: 0; padding: 0; font-size: 13px; font-weight: 600; letter-spacing: 0.06em; color: #ffffff; line-height: 1.2; }}
.soc-text-group p {{ margin: 1px 0 0 0; padding: 0; font-size: 11px; color: oklch(0.70 0.025 240); letter-spacing: 0.22em; text-transform: uppercase; line-height: 1.2; }}
.soc-controls-group {{ display: flex; align-items: center; gap: 16px; }}
.soc-online-status {{ color: oklch(0.78 0.18 165); font-size: 11px; font-weight: 500; letter-spacing: .08em; text-transform: uppercase; display: flex; align-items: center; gap: 6px; }}
.soc-clear-btn {{
    display: inline-flex; align-items: center; gap: 6px; background: transparent; color: oklch(0.70 0.025 240);
    border: 1px solid oklch(0.30 0.03 260 / 60%); border-radius: 6px; padding: 4px 12px; font-size: 12px; text-decoration: none; cursor: pointer;
}}
.soc-clear-btn:hover {{ color: oklch(0.62 0.24 25); border-color: oklch(0.62 0.24 25 / 50%); }}
.soc-clear-btn.disabled {{ opacity: 0.4; pointer-events: none; }}
</style>
</head>
<body>
    <div class="soc-header-row">
        <div class="soc-brand-group">
            <div class="soc-logo-wrap">
                <div class="soc-logo">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="M8 12h2l1.5-3 1.5 6 1.5-3H17"/>
                    </svg>
                </div>
                <span class="soc-online-dot"></span>
            </div>
            <div class="soc-text-group">
                <h1>CYBER THREAT AGENT</h1>
                <p>Detect · Analyze · Defend</p>
            </div>
        </div>
        <div class="soc-controls-group">
            <div class="soc-online-status">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/>
                </svg>
                Online
            </div>
            <a href="?clear_session_trigger=true" class="soc-clear-btn {is_empty_history}" target="_self">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="3 6 5 6 21 6"/>
                    <path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"/>
                </svg>
                Clear
            </a>
        </div>
    </div>
</body>
</html>
"""

# Render the isolated layout block safely at the top of the interface
components.html(header_html_component, height=65)

# =====================================================================
# 🛠️ AGENT TOOL SPECIFICATIONS
# =====================================================================

def fetch_active_threat_spikes(limit: int = 5) -> str:
    try:
        with engine.begin() as connection:
            query = text("""
                SELECT target_identifier, article_count_window, triggered_by_cvss, severity_level, alert_message
                FROM alert_spikes 
                ORDER BY detected_at DESC LIMIT :limit;
            """)
            results = connection.execute(query, {"limit": limit}).fetchall()
        
        if not results:
            out_html = "<p style='color:var(--muted-foreground); padding:10px;'>Zero active threats found.</p>"
        else:
            spike_cards = ""
            for r in results:
                target, vol, cvss, sev, msg = r[0], r[1], float(r[2]), r[3], r[4]
                is_crit = "critical" if sev == "CRITICAL" else ""
                spike_cards += f"""
                <div class="spike {is_crit}">
                    <div class="spike-head">
                        <div class="spike-target">
                            <span class="icon-critical">{ALERT_SVG}</span>
                            <span>{target.upper()}</span>
                        </div>
                        <span class="sev {sev}">{sev}</span>
                    </div>
                    <p class="spike-msg">{msg}</p>
                    <div class="spike-meta">
                        <span>CVSS {cvss:.1f}</span>
                        <span>Vol {vol}</span>
                        <span class="when">Just Now</span>
                    </div>
                </div>
                """
            out_html = f"<div class='spike-list'>{spike_cards}</div>"
            
        return f"""
        <div class="tool">
            <div class="tool-header-css">
                <span class="left">{WRENCH_SVG}<span>fetch_active_threat_spikes</span></span>
                <span class="badge">{CHECK_SVG} Completed</span>
            </div>
            <div class="tool-content-css">
                <div class="tool-section-label">Parameters</div>
                <pre class="code">{{"limit": {limit}}}</pre>
                <div class="tool-section-label">Result</div>
                {out_html}
            </div>
        </div>
        """
    except Exception as e:
        return f"<pre class='code'>❌ Failure: {str(e)}</pre>"

def modify_keyword_monitoring_status(keyword: str, active: int) -> str:
    try:
        with engine.begin() as connection:
            update_query = text("""
                UPDATE monitored_keywords 
                SET active = :status 
                WHERE LOWER(keyword) = LOWER(:kw);
            """)
            connection.execute(update_query, {"status": active, "kw": keyword.strip()})
        
        status_label = "ACTIVE" if active == 1 else "PAUSED"
        pill_class = "active" if active == 1 else ""
        
        out_html = f"""
        <div class="kw-pill {pill_class}">
            {CHECK_SVG}
            <span class="kw">{keyword.upper()}</span>
            <span class="state">{status_label}</span>
        </div>
        """
        return f"""
        <div class="tool">
            <div class="tool-header-css">
                <span class="left">{WRENCH_SVG}<span>modify_keyword_monitoring_status</span></span>
                <span class="badge">{CHECK_SVG} Completed</span>
            </div>
            <div class="tool-content-css">
                <div class="tool-section-label">Parameters</div>
                <pre class="code">{{"keyword": "{keyword}", "active": {active}}}</pre>
                <div class="tool-section-label">Result</div>
                {out_html}
            </div>
        </div>
        """
    except Exception as e:
        return f"<pre class='code'>❌ Failure: {str(e)}</pre>"

all_agent_tools = [fetch_active_threat_spikes, modify_keyword_monitoring_status]

# =====================================================================
# 💬 CHAT TIMELINE DISPLAY CONTAINER
# =====================================================================
if st.session_state.messages:
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["text"], unsafe_allow_html=True)
else:
    st.markdown("""
        <div class="empty">
          <div class="logo-wrap" style="margin-bottom:10px;">
            <div class="logo" style="width:48px; height:48px; border-radius:10px; background:radial-gradient(circle at 30% 30%, oklch(0.85 0.18 165), oklch(0.55 0.18 165)); display:grid; place-items:center;">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
          </div>
          <div>
            <h2>🚨 Cyber Threat Agent ready</h2>
            <p>Real-time threat detection at your fingertips. Query the SOC feed, triage spikes, or adjust keyword monitoring with a single command.</p>
          </div>
        </div>
    """, unsafe_allow_html=True)

# =====================================================================
# 🔑 CREDENTIAL AUTH PIPELINE
# =====================================================================
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    st.error("🔑 Token Context Error.")
    st.stop()

if "gemini_client" not in st.session_state:
    st.session_state.gemini_client = genai.Client(api_key=api_key)

MODEL_ID = "gemini-2.5-flash"

if "chat_session" not in st.session_state:
    system_instruction = (
        "You are an elite SOC AI Agent. When asked for threats, spikes, or tracking status changes, choose the matching tool. "
        "Always format your textual summaries clean inside a div wrapper named assistant-text-layout."
    )
    st.session_state.chat_session = st.session_state.gemini_client.chats.create(
        model=MODEL_ID,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=all_agent_tools,
            temperature=0.1
        )
    )

# =====================================================================
# 🚀 CHAT RUNTIME PROCESSING CONTROL PANEL
# =====================================================================
if user_query := st.chat_input("Type a command or query the SOC database..."):
    st.session_state.messages.append({"role": "user", "text": user_query})
    
    with st.chat_message("assistant"):
        with st.spinner("Processing framework telemetry routines..."):
            try:
                response = st.session_state.chat_session.send_message(user_query)
                final_html_payload = ""
                
                if response.function_calls:
                    for call in response.function_calls:
                        if call.name == "fetch_active_threat_spikes":
                            limit_arg = call.args.get("limit", 5)
                            final_html_payload += fetch_active_threat_spikes(limit=int(limit_arg))
                        elif call.name == "modify_keyword_monitoring_status":
                            kw_arg = call.args.get("keyword", "ddos")
                            act_arg = call.args.get("active", 1)
                            final_html_payload += modify_keyword_monitoring_status(keyword=str(kw_arg), active=int(act_arg))
                
                if response.text:
                    text_output = response.text.replace("```html", "").replace("```", "").strip()
                    if "assistant-text-layout" not in text_output:
                        final_html_payload += f"<div class='assistant-text-layout'>{text_output}</div>"
                    else:
                        final_html_payload += text_output
                
                st.markdown(final_html_payload, unsafe_allow_html=True)
                st.session_state.messages.append({"role": "assistant", "text": final_html_payload})
                st.rerun()
                
            except Exception as e:
                if "503" in str(e) or "UNAVAILABLE" in str(e):
                    st.warning("⚠️ *Google's cloud infrastructure capacity is temporarily overloaded. Re-submit this command in a few seconds.*")
                else:
                    st.error(f"❌ Core Exception Failure: {str(e)}")