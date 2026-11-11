# MiniOffice AI

A beginner-friendly Streamlit demo of **role-based access control**: different
demo users see different company documents.

No real sign-in (Microsoft Entra ID) and no AI (Claude API) yet — those come later.

## Run it

```bash
cd minioffice-ai
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Then open the URL Streamlit prints (usually http://localhost:8501).

## Files

| File | Purpose |
|---|---|
| `app.py` | The user interface: title, sidebar, document lists |
| `data.py` | Sample users and documents, plus who may open each document |
| `permissions.py` | One function, `can_access`, that applies the access rule |
| `requirements.txt` | Python packages to install |

## Who sees what

| User | Role | Handbook | Budget | Salaries |
|---|---|---|---|---|
| Alex | Employee | ✅ | 🔒 | 🔒 |
| Sam | Manager | ✅ | ✅ | 🔒 |
| Jordan | HR | ✅ | 🔒 | ✅ |
