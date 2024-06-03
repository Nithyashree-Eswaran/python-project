import random
import string
import hashlib
import os
import pyperclip

def generate_password(length=12, use_lowercase=True, use_uppercase=True, use_digits=True, use_special=True):
    # Define the character sets to include in the password
    char_sets = []
    if use_lowercase:
        char_sets.append(string.ascii_lowercase)
    if use_uppercase:
        char_sets.append(string.ascii_uppercase)
    if use_digits:
        char_sets.append(string.digits)
    if use_special:
        char_sets.append(string.punctuation)

    # Ensure at least one character set is selected
    if not char_sets:
        raise ValueError("At least one character type must be selected")

    # Combine all selected character sets
    all_chars = ''.join(char_sets)

    # Generate the password ensuring at least one character from each selected set
    password = [
        random.choice(char_set) for char_set in char_sets
    ]

    # Fill the remaining length of the password
    password += [
        random.choice(all_chars) for _ in range(length - len(password))
    ]

    # Shuffle to ensure randomness
    random.shuffle(password)

    return ''.join(password)

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key, salt

def verify_password(stored_password, stored_salt, password_attempt):
    key, _ = hash_password(password_attempt, stored_salt)
    return key == stored_password

def get_user_input():
    length = int(input("Enter the length of the password: "))
    use_lowercase = input("Include lowercase letters? (yes/no): ").lower() == 'yes'
    use_uppercase = input("Include uppercase letters? (yes/no): ").lower() == 'yes'
    use_digits = input("Include digits? (yes/no): ").lower() == 'yes'
    use_special = input("Include special characters? (yes/no): ").lower() == 'yes'
    return length, use_lowercase, use_uppercase, use_digits, use_special

# Get user input
length, use_lowercase, use_uppercase, use_digits, use_special = get_user_input()

# Generate password
password = generate_password(length=length, use_lowercase=use_lowercase, use_uppercase=use_uppercase, use_digits=use_digits, use_special=use_special)
print("Generated password:", password)

# Copy password to clipboard
pyperclip.copy(password)
print("Password copied to clipboard")

# Hash password
hashed_password, salt = hash_password(password)
print("Hashed password:", hashed_password)
print("Salt:", salt)

# Verification
print("Password verified:", verify_password(hashed_password, salt, password))
