import os
import pickle
import subprocess
import yaml

API_KEY = "sk-abc123secretkey456"
DB_PASSWORD = "password123"

def run_command(user_input):
    os.system(user_input)
    subprocess.run(user_input, shell=True)
    subprocess.Popen(user_input, shell=True)

def unsafe_eval(data):
    return eval(data)

def unsafe_exec(code):
    exec(code)

def unsafe_compile(source):
    compiled = compile(source, "<string>", "exec")
    exec(compiled)

def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_yaml(path):
    with open(path) as f:
        return yaml.load(f)

def dangerous_popen(cmd):
    return os.popen(cmd).read()

def delete_everything(path):
    import shutil
    shutil.rmtree(path)

def kill_process(pid):
    os.kill(pid, 9)
