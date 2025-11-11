import re


def validate_email(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email)


def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    # if not re.search(r"[A-Z]", password):
    #     return "Password must contain at least one uppercase letter"
    # if not re.search(r"[a-z]", password):
    #     return "Password must contain at least one lowercase letter"
    # if not re.search(r"[0-9]", password):
    #     return "Password must contain at least one number"
    # if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
    #     return "Password must contain at least one special character"
    return None
