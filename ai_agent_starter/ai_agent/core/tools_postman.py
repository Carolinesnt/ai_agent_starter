import subprocess, json, os, tempfile

def run_newman(collection_path: str, env_path: str=None, out_json: str=None):
    cmd = ["newman", "run", collection_path, "--reporters", "cli,json"]
    if env_path:
        cmd += ["-e", env_path]
    if out_json:
        cmd += ["--reporter-json-export", out_json]
    subprocess.run(cmd, check=True)
    return out_json or ""
