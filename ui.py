import streamlit as st
import uuid
import sys
import os

# Ensure app modules are importable
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.engine.orchestrator import analyze_message
from app.engine.judge import evaluate_prompt
from app.usecases.code_review.reviewer import review_code
from app.memory.store import get_recent_history

st.set_page_config(page_title="Prompt Injection Defense", page_icon="🛡️", layout="wide")

# Custom CSS for WhatsApp-like styling
st.markdown("""
<style>
    /* Main Background */
    .stApp {
        background-color: #ECE5DD;
        background-image: url("https://user-images.githubusercontent.com/15075759/28719144-86dc0f70-73b1-11e7-911d-60d70fcded21.png");
        background-repeat: repeat;
        background-size: 400px;
    }

    /* Chat Messages */
    .stChatMessage {
        background-color: transparent !important;
    }

    /* User Message Bubble (Right) */
    div[data-testid="stChatMessage"]:nth-child(2n+1) { 
        /* This selector is tricky in Streamlit, relying on direction mostly */
    }
    
    /* We can't easily select user/assistant via pure CSS in Streamlit's new chat elements
       without some hacky selectors or container wrapping. 
       However, Streamlit creates distinct structures for user/assistant.
       Let's try to target the avatars. */
       
    div[data-testid="chatAvatarIcon-user"] {
        background-color: #DCF8C6 !important;
    }
    
    /* General message bubble styling override if possible */
    div[data-testid="stMarkdownContainer"] p {
        font-family: Helvetica, Arial, sans-serif;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'conversation_id' not in st.session_state:
    st.session_state.conversation_id = str(uuid.uuid4())

if 'messages' not in st.session_state:
    st.session_state.messages = []

# Cumulative stats
if 'stats' not in st.session_state:
    st.session_state.stats = {
        'total': 0,
        'blocked': 0,
        'sanitized': 0,
        'flagged_by_judge': 0
    }

st.title("🛡️ Secure Chat Gateway")

# Tabs for Chat vs Use Case
tab1, tab2 = st.tabs(["💬 Chat Gateway", "🔬 UseCase: Code Review"])

# --- TAB 1: Chat Interface ---
with tab1:
    col1, col2 = st.columns([3, 1])
    
    with col2:
        st.subheader("📊 Session Summary")
        st.metric("Total Prompts", st.session_state.stats['total'])
        st.metric("Blocked Attacks", st.session_state.stats['blocked'])
        st.metric("Sanitized", st.session_state.stats['sanitized'])
        st.metric("Flagged by AI Judge", st.session_state.stats['flagged_by_judge'])
        
        st.divider()
        st.markdown("### 🧠 Accumulated Context")
        # Show what the LLM 'sees' as history
        history_preview = get_recent_history(st.session_state.conversation_id, limit=3)
        if history_preview:
            st.text_area("Context Memory (Last 3 turns)", history_preview, height=150, disabled=True)
        else:
            st.info("No history yet.")

    with col1:
        # Display Chat History with Custom HTML for WhatsApp feel
        for msg in st.session_state.messages:
            if msg["role"] == "user":
                st.markdown(f"""
                <div style="display: flex; justify-content: flex-end; margin-bottom: 10px;">
                    <div style="background-color: #DCF8C6; color: black; padding: 10px; border-radius: 10px 0px 10px 10px; max-width: 70%; box-shadow: 0px 1px 1px rgba(0,0,0,0.1);">
                        {msg['content']}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="display: flex; justify-content: flex-start; margin-bottom: 10px;">
                    <div style="background-color: #FFFFFF; color: black; padding: 10px; border-radius: 0px 10px 10px 10px; max-width: 70%; box-shadow: 0px 1px 1px rgba(0,0,0,0.1);">
                        {msg['content']}
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                # Show details expander (native streamlit)
                if "analysis" in msg:
                    with st.expander("🔍 details", expanded=False):
                        st.json(msg["analysis"])
                        if "judge" in msg:
                            st.write(f"**Judge:** {msg['judge'].get('classification')} ({msg['judge'].get('confidence',0):.2f})")

        # Chat Input
        if prompt := st.chat_input("Type a message"):
            # 1. User Message
            st.session_state.messages.append({"role": "user", "content": prompt})
            st.rerun()

    # Process new message (if last message is user)
    if st.session_state.messages and st.session_state.messages[-1]["role"] == "user":
        prompt = st.session_state.messages[-1]["content"]
        with col1:
            with st.spinner("..."):
                # Gateway Analysis
                response = analyze_message(st.session_state.conversation_id, prompt)
                
                # Update Stats
                st.session_state.stats['total'] += 1
                if response['action'] == 'block':
                    st.session_state.stats['blocked'] += 1
                elif response['action'] == 'sanitize':
                    st.session_state.stats['sanitized'] += 1

                # AI Judge
                judge_result = evaluate_prompt(prompt)
                judge_verdict = judge_result.get('classification', 'UNKNOWN')
                if judge_verdict == 'MALICIOUS':
                    st.session_state.stats['flagged_by_judge'] += 1

                # Determined Response based on Action
                if response['action'] == 'block':
                    final_response_text = "🚫 **Blocked:** Malicious content detected."
                elif response['action'] == 'sanitize':
                    final_response_text = f"⚠️ **Sanitized:** {response.get('sanitized_message', '')}"
                elif response['action'] == 'reprompt':
                    final_response_text = f"🔄 **Reprompt:** {response.get('reprompt_message', '')}"
                else:
                    final_response_text = "✅ **Allowed:** Prompt sent to LLM."

                # Save Assistant interaction
                st.session_state.messages.append({
                    "role": "assistant", 
                    "content": final_response_text,
                    "analysis": response,
                    "judge": judge_result
                })
                st.rerun()

# --- TAB 2: Code Review Demo ---
with tab2:
    st.header("UseCase Demo: Secure Code Reviewer")
    st.markdown("""
    This demo simulates a code review tool protected by the gateway.
    - **Safe Code**: Will be allowed and sent to the LLM for review.
    - **Malicious Code (Injections)**: Will be BLOCKED or SANITIZED by the gateway *before* reaching the reviewer.
    """)
    
    code_input = st.text_area("Enter Code Diff / Snippet:", height=200, key="code_input")
    
    if st.button("Submit for Review"):
        with st.spinner("Checking Gateway Policy..."):
            # 1. Check with Gateway
            analysis = analyze_message(st.session_state.conversation_id, code_input)
            action = analysis['action']
            risk = analysis['risk_score']
            
            if action == "block":
                st.error(f"🛑 **BLOCKED by Gateway** (Risk: {risk})")
                st.write("The request contained malicious content and was not sent to the Code Reviewer.")
                with st.expander("Details"):
                    st.json(analysis)
            
            elif action == "sanitize":
                st.warning(f"⚠️ **SANITIZED** (Risk: {risk})")
                st.write("Injection attempts were removed. Reviewing sanitized code...")
                clean_code = analysis['sanitized_message']
                st.code(clean_code)
                with st.spinner("Reviewing code..."):
                    review = review_code(clean_code)
                    st.markdown("### Review Result")
                    st.markdown(review)

            else: # Allow
                st.success(f"✅ **ALLOWED** (Risk: {risk})")
                with st.spinner("Reviewing code..."):
                    review = review_code(code_input)
                    st.markdown("### Review Result")
                    st.markdown(review)
