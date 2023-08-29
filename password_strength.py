import re

def check_password_strength(password):
    # Define regular expressions to check password strength
    patterns = {
        'length': r'.{8,}',            # Minimum length of 8 characters
        'uppercase': r'[A-Z]',         # At least one uppercase letter
        'lowercase': r'[a-z]',         # At least one lowercase letter
        'digit': r'\d',                # At least one digit
        'special_char': r'[!@#$%^&*]', # At least one special character
    }

    # Check each pattern using list comprehensions
    strength = [
        bool(re.search(pattern, password)) for pattern in patterns.values()
    ]

    # Determine overall password strength
    if all(strength):
        return "Strong password"
    else:
        return "Weak password"

def suggest_strong_password():
    # Suggest a strong password
    return "Suggest a password with at least 8 characters including uppercase letters, lowercase letters, digits, and special characters."

def main():
    password = input("Enter your password: ")
    strength = check_password_strength(password)

    if strength == "Strong password":
        print("Password is strong.")
    else:
        print("Password is weak.")
        print(suggest_strong_password())

if __name__ == "__main__":
    main()