import hashlib
import subprocess
import pickle

password = "secret123"


def login(user_password):
    if user_password == password:
        return True
    return False


def execute_command(command):
    subprocess.run(command, shell=True)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def load_data(data):
    return pickle.loads(data)


user_command = input("Enter command: ")
execute_command(user_command)
