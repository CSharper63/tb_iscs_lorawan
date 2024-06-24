import os
import subprocess
from dotenv import load_dotenv

load_dotenv()

REPO_URL = os.getenv('REPO_URL')

# no so clean but working
files_to_commit = ["wss_messages.json", "requests.json"]

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: {result.stderr}")
    else: # is ok
        print(f'SUCCESS: {result.stdout}')

def push_to_github():

    # list files and copy here
    for file in files_to_commit:
        run_command(f"cp ~/lorawan_capture/{file} .")
    
    for file in files_to_commit:
        run_command(f"git add {file}")

    # commit
    run_command("git commit -m 'deamon - Add wss_messages.json and requests.json'")

    # push
    run_command(f"git pull {REPO_URL} main --rebase")
    run_command(f"git push {REPO_URL} main")

if __name__ == "__main__":
    # init if not done yet -> should never happen
    if not os.path.exists(".git"):
        run_command("git init")
        run_command(f"git remote add origin {REPO_URL}")
        run_command("git checkout -b main")

    push_to_github()
