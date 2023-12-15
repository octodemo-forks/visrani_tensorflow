import hashlib

def hash_password(password):
    # Insecure: Using MD5 for hashing password
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    return hashed_password

if __name__ == "__main__":
    user_password = input("Enter a password: ")
    hashed_password = hash_password(user_password)
    print("Hashed Password:", hashed_password)
