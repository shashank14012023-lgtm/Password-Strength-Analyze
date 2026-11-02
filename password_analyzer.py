import re
import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_length INTEGER,
            strength TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_to_db(length, strength):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO history (password_length, strength, timestamp) VALUES (?, ?, ?)", (length, strength, timestamp))
    conn.commit()
    conn.close()

def evaluate_password_strength(password):
    score = 0
    feedback = []

    if len(password) > 11:
        score += 2
    elif len(password) > 7:
        score += 1
        feedback.append("Password length should ideally be at least 12 characters for better security.")
    else:
        feedback.append("Password is too short. It must be at least 8 characters long.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters (A-Z).")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters (a-z).")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers (0-9).")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters (e.g., !, @, #, $).")

    if score > 8:
        strength = "Very Strong"
    elif score > 7:
        strength = "Strong"
    elif score > 5:
        strength = "Moderate"
    else:
        strength = "Weak"

    return strength, feedback

def main():
    init_db()
    print("=== Password Strength Analyzer (with DB) ===")
    user_password = input("Enter a password to test: ")
    
    strength, feedback = evaluate_password_strength(user_password)
    save_to_db(len(user_password), strength)
    
    print(f"\nPassword Strength: {strength}")
    print("[+] Result successfully saved to database (passwords.db)")
    
    if feedback:
        print("\nSuggestions to improve:")
        for item in feedback:
            print(f"- {item}")
    else:
        print("\nGreat job! Your password looks very secure.")

if __name__ == "__main__":
    main()
