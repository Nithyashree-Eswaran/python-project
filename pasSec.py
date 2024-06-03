import random
import string
import hashlib
import os

def generate_password(length=12):
    """Generate a random password"""
    if length < 12:
        raise ValueError("Password length should be at least 12 characters")
    
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def hash_password(password):
    """Hash a password with a new random salt"""
    salt = os.urandom(16)  # Generate a new salt
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt, hashed_password

def verify_password(stored_password, stored_salt, provided_password):
    """Verify a stored password against one provided by user"""
    hashed_password = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), stored_salt, 100000)
    return hashed_password == stored_password

# Example usage
if __name__ == "__main__":
    # Generate a new password
    new_password = generate_password(16)
    print(f"Generated Password: {new_password}")

    # Hash the new password
    salt, hashed_password = hash_password(new_password)
    print(f"Salt: {salt.hex()}")
    print(f"Hashed Password: {hashed_password.hex()}")

    # Verify the password
    is_correct = verify_password(hashed_password, salt, new_password)
    print(f"Password verification result: {is_correct}")
