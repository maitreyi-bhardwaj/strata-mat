"""
permissions.py — the access-control rule for MiniOffice AI.

One small function decides whether a user may open a document.
Putting this rule in its own file means:
  - the rule lives in ONE place (easy to read and test), and
  - later you can replace how the role is obtained (for example, from a
    Microsoft Entra ID token) without touching the user interface.
"""


def can_access(user_role, document):
    """Return True if a user with `user_role` may open `document`.

    Example:
        can_access("Manager", {"allowed_roles": ["Manager"]})  ->  True
        can_access("Employee", {"allowed_roles": ["Manager"]}) ->  False
    """
    return user_role in document["allowed_roles"]
