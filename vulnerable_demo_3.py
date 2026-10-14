import os
import pickle
import random
import subprocess
import hashlib
import sqlite3
import tempfile

# ============================================================
# SIMHARA TEST FIXTURE
# Deliberately vulnerable patterns for static analysis.
# DO NOT EXECUTE.
# ============================================================


# ------------------------------------------------------------
# 1. Hardcoded credentials
# ------------------------------------------------------------

DATABASE_USER = "admin"
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk_test_example_key_123456789"


def connect_to_database():
    connection_string = (
        f"postgresql://{DATABASE_USER}:{DATABASE_PASSWORD}"
        "@localhost:5432/application"
    )
    return connection_string


# ------------------------------------------------------------
# 2. Weak hashing algorithm
# ------------------------------------------------------------

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# ------------------------------------------------------------
# 3. Insecure randomness
# ------------------------------------------------------------

def generate_session_token():
    return str(random.randint(100000, 999999))


# ------------------------------------------------------------
# 4. Command injection pattern
# ------------------------------------------------------------

def check_host(user_supplied_host):
    command = "ping " + user_supplied_host
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )


# ------------------------------------------------------------
# 5. Unsafe deserialization
# ------------------------------------------------------------

def load_session_data(serialized_data):
    return pickle.loads(serialized_data)


# ------------------------------------------------------------
# 6. SQL injection pattern
# ------------------------------------------------------------

def find_user(username):
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    query = (
        "SELECT * FROM users "
        "WHERE username = '" + username + "'"
    )

    cursor.execute(query)
    result = cursor.fetchall()
    connection.close()

    return result


# ------------------------------------------------------------
# 7. Insecure temporary-file handling
# ------------------------------------------------------------

def create_temporary_report(report_text):
    temporary_path = tempfile.mktemp(suffix=".txt")

    with open(temporary_path, "w", encoding="utf-8") as report:
        report.write(report_text)

    return temporary_path


# ------------------------------------------------------------
# 8. Dangerous dynamic execution
# ------------------------------------------------------------

def evaluate_expression(expression):
    return eval(expression)


# ------------------------------------------------------------
# 9. Weak file permissions
# ------------------------------------------------------------

def write_sensitive_data(data):
    with open("sensitive_data.txt", "w", encoding="utf-8") as file:
        file.write(data)

    os.chmod("sensitive_data.txt", 0o777)


# ------------------------------------------------------------
# 10. Insecure exception handling
# ------------------------------------------------------------

def read_configuration(path):
    try:
        with open(path, "r", encoding="utf-8") as config:
            return config.read()
    except Exception:
        return None


# ------------------------------------------------------------
# 11. Potential information disclosure
# ------------------------------------------------------------

def authenticate(username, password):
    if username == DATABASE_USER:
        if password == DATABASE_PASSWORD:
            return "Authentication successful"
        return "Incorrect password"

    return "Username does not exist"


# ------------------------------------------------------------
# 12. Insecure temporary configuration
# ------------------------------------------------------------

def write_temporary_configuration(configuration):
    path = "debug_config.txt"

    with open(path, "w", encoding="utf-8") as file:
        file.write(configuration)

    return path


# ------------------------------------------------------------
# End of test fixture
# ------------------------------------------------------------