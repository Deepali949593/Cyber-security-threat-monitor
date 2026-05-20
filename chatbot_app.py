import os
import streamlit as st
from sqlalchemy import text
from dotenv import load_dotenv
from google import genai
from google.genai import types

# 1. Force environment configurations to load first
load_dotenv()
from database.connection import engine

# 2. Page Meta Setup
st.set_page_config(page_title="SOC AI Agent", page_icon="🚨", layout="centered")
st.title("🚨 Cyber Threat Agent")
st.caption("Real-Time Threat Detection, Detect. Analyze. Defend.")

# 3. Secure and verify API Key presence before initialization
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    st.error("API Key Missing: Could not find GEMINI_API_KEY in your .env file. Please check your workspace configuration.")
    st.stop()

# Initialize the GenAI SDK Client
if "gemini_client" not in st.session_state:
    st.session_state.gemini_client = genai.Client(api_key=api_key)

# The absolute exact canonical model identifier string required by your SDK
MODEL_ID = "gemini-2.5-flash"

# =====================================================================
# 🛠️ AGENT TOOL DECLARATIONS (RAG & Execution Layers)
# =====================================================================

def fetch_active_threat_spikes(limit: int = 5) -> str:
    """Queries the database to retrieve the most recent threat spikes."""
    try:
        with engine.begin() as connection:
            query = text("""
                SELECT target_identifier, article_count_window, triggered_by_cvss, severity_level, alert_message, detected_at
                FROM alert_spikes 
                ORDER BY detected_at DESC LIMIT :limit;
            """)
            results = connection.execute(query, {"limit": limit}).fetchall()
        if not results:
            return "✅ System Health Check: Clean. Zero high-risk alert spikes recorded."
        return "\n".join([f"🚨 TARGET: {r[0].upper()} | Severity: {r[3]}\n   - Insight: {r[4]}" for r in results])
    except Exception as e:
        return f"❌ Database read failure: {str(e)}"

def modify_keyword_monitoring_status(keyword: str, active: int) -> str:
    """Modifies the active tracking state (1 = active, 0 = paused) of a keyword."""
    try:
        with engine.begin() as connection:
            update_query = text("""
                UPDATE monitored_keywords 
                SET active = :status 
                WHERE LOWER(keyword) = LOWER(:kw);
            """)
            connection.execute(update_query, {"status": active, "kw": keyword.strip()})
        return f"🔒 System Action: Keyword '{keyword.upper()}' tracking set to {'ACTIVE' if active == 1 else 'PAUSED'}."
    except Exception as e:
        return f"❌ Action execution failed: {str(e)}"

all_agent_tools = [fetch_active_threat_spikes, modify_keyword_monitoring_status]

# =====================================================================
# 💬 UI SESSION INITIALIZATIONS
# =====================================================================

if "messages" not in st.session_state:
    st.session_state.messages = []

# Force fresh initialization to clear out any corrupted background string memory
if "chat_session" not in st.session_state or st.session_state.get("current_model") != MODEL_ID:
    system_instruction = (
        "You are an elite SOC AI Agent. Use `fetch_active_threat_spikes` to look up threats, "
        "and `modify_keyword_monitoring_status` to change monitoring flags. Keep replies concise."
    )
    st.session_state.chat_session = st.session_state.gemini_client.chats.create(
        model=MODEL_ID,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=all_agent_tools,
            temperature=0.2
        )
    )
    st.session_state.current_model = MODEL_ID

# =====================================================================
# 🎨 UI DIALOGUE RENDERING LAYER
# =====================================================================

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["text"])

# =====================================================================
# 🚀 INTERACTIVE USER PROMPT HANDLING
# =====================================================================
# =====================================================================
# 🚀 INTERACTIVE USER PROMPT HANDLING
# =====================================================================

if user_query := st.chat_input("Type a project command or ask a database question..."):
    with st.chat_message("user"):
        st.markdown(user_query)
    st.session_state.messages.append({"role": "user", "text": user_query})

    with st.chat_message("assistant"):
        with st.spinner("Agent evaluating intent and executing system tools..."):
            try:
                # Send message to the agent session
                response = st.session_state.chat_session.send_message(user_query)
                ai_response = response.text
                st.markdown(ai_response)
                st.session_state.messages.append({"role": "assistant", "text": ai_response})
                
            except Exception as e:
                # Catch temporary 503 high-demand spikes gracefully without breaking the layout
                if "503" in str(e) or "UNAVAILABLE" in str(e):
                    error_msg = "⚠️ *Google's free-tier servers are currently overloaded with traffic. Please press Enter to try sending your command again in a few seconds.*"
                    st.warning(error_msg)
                else:
                    # Catch any other runtime execution errors standard
                    st.error(f"❌ Execution Error: {str(e)}")