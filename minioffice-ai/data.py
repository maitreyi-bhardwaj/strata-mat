"""
data.py — the sample data for MiniOffice AI.

This file holds two things:
  1. USERS     — the demo people you can pick in the sidebar.
  2. DOCUMENTS — the company documents, and which roles may open each one.

There is no logic here, only data. Keeping data separate from code makes
it easy to change later (for example, loading users from Microsoft Entra ID
instead of this hard-coded dictionary).
"""

# Each demo user has a name and exactly one role.
# The key ("Alex") is what the sidebar shows; the value holds the details.
USERS = {
    "Alex": {"role": "Employee"},
    "Sam": {"role": "Manager"},
    "Jordan": {"role": "HR"},
}

# Each document lists the roles that are allowed to open it.
# "allowed_roles" is the access rule. The app never checks names,
# only roles, so adding a new Manager would need no code change.
DOCUMENTS = [
    {
        "title": "Company Handbook",
        "icon": "📘",
        "allowed_roles": ["Employee", "Manager", "HR"],  # everyone
        "content": (
            "Welcome to MiniOffice!\n\n"
            "- Office hours: 9:00 to 17:00\n"
            "- Remote work: up to 2 days per week\n"
            "- Holidays: 25 days per year"
        ),
    },
    {
        "title": "Project Budget",
        "icon": "💰",
        "allowed_roles": ["Manager"],  # managers only
        "content": (
            "Q3 project budget (sample data)\n\n"
            "- Website redesign: $40,000\n"
            "- Mobile app: $65,000\n"
            "- Training: $8,000"
        ),
    },
    {
        "title": "Employee Salaries",
        "icon": "🧾",
        "allowed_roles": ["HR"],  # HR only
        "content": (
            "Salary table (sample data)\n\n"
            "- Alex: $55,000\n"
            "- Sam: $80,000\n"
            "- Jordan: $70,000"
        ),
    },
]
