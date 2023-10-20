import bcrypt


class Password_hashing:
    def __init__(self) -> None:
        # storing user name and password
        print("### STORING USERNAME AND PASSWORD ###")
        self.user_name = input("Enter new username: ")
        self.user_password = input("Enter  new password: ")
        self.database = {}

    def hash_pw(self) -> str:
        user_password_bytes = bytes(self.user_password, "utf-8")
        hash = bcrypt.hashpw(password=user_password_bytes, salt=bcrypt.gensalt())
        self.database[self.user_name] = hash

    def compare_password(self) -> bool:
        print("")
        print("### VALIDATING PASSWORD ###")

        user_name = input("Enter your existing username : ")
        password = input("Enter your existing password : ")
        user_password_bytes = bytes(password, "utf-8")

        if user_name not in self.database:
            return False

        stored_hash = self.database[user_name]

        matched = bcrypt.checkpw(
            password=user_password_bytes, hashed_password=stored_hash
        )
        return matched


if __name__ == "__main__":
    pw_hashing = Password_hashing()
    h = pw_hashing.hash_pw()
    p = pw_hashing.compare_password()
    print("")
    if p:
        print("valid username and password - Logged in ")
    else:
        print("Invalid username or password - Unable to log in ")
