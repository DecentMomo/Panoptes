import subprocess


def run(cmd: str) -> None:
    subprocess.Popen(cmd, shell=True)
