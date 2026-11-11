"""
app.py — the Streamlit user interface for MiniOffice AI.

Run it with:
    streamlit run app.py

How Streamlit works (the key idea):
    Streamlit runs this whole file from top to bottom every time you
    interact with the page (for example, when you pick a different user).
    So there are no "click handlers": the script simply re-runs and
    draws the page again using the new sidebar value.
"""

import streamlit as st

from data import DOCUMENTS, USERS
from permissions import can_access

# ---------------------------------------------------------------------------
# 1. Page setup
# ---------------------------------------------------------------------------
# set_page_config must be the first Streamlit command in the script.
st.set_page_config(page_title="MiniOffice AI", page_icon="🏢")

st.title("🏢 MiniOffice AI")
st.caption("A demo of role-based access to company documents.")

# ---------------------------------------------------------------------------
# 2. Sidebar: choose a demo user
# ---------------------------------------------------------------------------
# Everything written as st.sidebar.<something> appears in the left sidebar.
st.sidebar.header("Demo user")

# Build labels like "Alex (Employee)" from the USERS dictionary.
user_names = list(USERS.keys())
selected_name = st.sidebar.radio(
    "Sign in as:",
    user_names,
    format_func=lambda name: f"{name} ({USERS[name]['role']})",
)

# Look up the selected user's role. This one value drives all access checks.
selected_role = USERS[selected_name]["role"]

st.sidebar.info(f"Signed in as **{selected_name}**\n\nRole: **{selected_role}**")
st.sidebar.caption("This is a demo. There is no real sign-in yet.")

# ---------------------------------------------------------------------------
# 3. Split documents into "allowed" and "locked"
# ---------------------------------------------------------------------------
allowed_docs = []
locked_docs = []

for doc in DOCUMENTS:
    if can_access(selected_role, doc):
        allowed_docs.append(doc)
    else:
        locked_docs.append(doc)

# ---------------------------------------------------------------------------
# 4. Summary numbers
# ---------------------------------------------------------------------------
col1, col2, col3 = st.columns(3)
col1.metric("Total documents", len(DOCUMENTS))
col2.metric("Available to you", len(allowed_docs))
col3.metric("Locked", len(locked_docs))

st.divider()

# ---------------------------------------------------------------------------
# 5. Available documents (the user can open these)
# ---------------------------------------------------------------------------
st.subheader("✅ Your documents")

for doc in allowed_docs:
    # An expander is a collapsible box: click the title to see the content.
    with st.expander(f"{doc['icon']} {doc['title']}"):
        st.markdown(doc["content"])

# ---------------------------------------------------------------------------
# 6. Locked documents (shown, but the content is NOT displayed)
# ---------------------------------------------------------------------------
st.subheader("🔒 Locked documents")

if not locked_docs:
    st.success("You have access to every document.")

for doc in locked_docs:
    who_can = ", ".join(doc["allowed_roles"])
    # Note: we only show the title and the rule, never doc["content"].
    st.warning(f"🔒 **{doc['title']}** — restricted to: {who_can}")
