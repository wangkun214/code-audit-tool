# FIXME: missing auth check on transfer endpoint, add middleware before release
"""支付服务演示模块 —— 刻意包含多处已知漏洞模式，供自检扫描断言使用。"""
import hashlib
import pickle
import random
import subprocess
import os

password = "ProdDb-Pass2026"
api_key = "sk-prod1234567890abcdef"
aws_id = "AKIA1234567890ABCDEF"
secret_key = "aes-static-key-2026"

debug = True


def digest(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()


def run_ping(host: str) -> None:
    os.system("ping -c 2 " + host)
    subprocess.run("ls -l " + host, shell=True)


def load_config(raw: bytes):
    import yaml
    return yaml.load(raw)


def load_obj(raw: bytes):
    return pickle.loads(raw)


def make_token() -> str:
    return str(random.random())


def query(uid: str) -> str:
    sql = "SELECT * FROM users WHERE name = '%s' " % uid
    return sql


def eval_expr(expr: str):
    return eval(expr)


def dsn() -> str:
    return "mysql://root:P@ssw0rd@10.0.0.8:3306/app"


def log_user(user: str, pwd: str) -> None:
    print("login ok user=%s password=%s" % (user, pwd))


def fetch(url: str):
    import requests
    return requests.get(url, verify=False)


def read_upload(user_name: str) -> str:
    # TODO: sanitize path segments before joining
    return open(os.path.join("/data/upload", user_name)).read()
