username = "admin"
password = "supersecret123"

def authenticate(user, pwd):
    if user == username and pwd == password:
        return True
    return False

print(authenticate("admin", "wrongpassword"))