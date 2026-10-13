import subprocess

user_input = input("Enter a command: ")

subprocess.run(user_input, shell=True)
