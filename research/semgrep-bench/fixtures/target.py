import subprocess


def run(cmd):
    subprocess.call(cmd, shell=True)
    subprocess.check_output(cmd, shell=True)
