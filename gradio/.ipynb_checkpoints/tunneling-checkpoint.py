"""
This file provides remote port forwarding functionality using paramiko package,
Inspired by: https://github.com/paramiko/paramiko/blob/master/demos/rforward.py
"""

import select
import socket
import sys
import threading
import warnings
from io import StringIO

from cryptography.utils import CryptographyDeprecationWarning

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    import paramiko


def handler(chan, host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        verbose(f"Forwarding request to {host}:{port} failed: {e}")
        return

    verbose(
        "Connected! Tunnel open "
        f"{chan.origin_addr} -> {chan.getpeername()} -> {(host, port)}"
    )

    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    chan.close()
    sock.close()
    verbose(f"Tunnel closed from {chan.origin_addr}")


def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
    transport.request_port_forward("", server_port)
    while True:
        chan = transport.accept(1000)
        if chan is None:
            continue
        thr = threading.Thread(target=handler, args=(chan, remote_host, remote_port))
        thr.setDaemon(True)
        thr.start()


def verbose(s, debug_mode=False):
    if debug_mode:
        print(s)


def create_tunnel(payload, local_server, local_server_port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    verbose(f'Conecting to ssh host {payload["host"]}:{payload["port"]} ...')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client.connect(
                hostname=payload["host"],
                port=int(payload["port"]),
                username=payload["user"],
                pkey=paramiko.RSAKey.from_private_key(StringIO(payload["key"])),
            )
    except Exception as e:
        print(f'*** Failed to connect to {payload["host"]}:{payload["port"]}: {e}')
        sys.exit(1)

    verbose(
        f'Now forwarding remote port {payload["remote_port"]}'
        f"to {local_server}:{local_server_port} ..."
    )

    thread = threading.Thread(
        target=reverse_forward_tunnel,
        args=(
            int(payload["remote_port"]),
            local_server,
            local_server_port,
            client.get_transport(),
        ),
        daemon=True,
    )
    thread.start()

    return payload["share_url"]

import atexit
import os
import platform
import re
import stat
import subprocess
from pathlib import Path
from typing import List

import requests

VERSION = "0.2"
CURRENT_TUNNELS: List["Tunnel"] = []

machine = platform.machine()
if machine == "x86_64":
    machine = "amd64"

BINARY_REMOTE_NAME = f"frpc_{platform.system().lower()}_{machine.lower()}"
EXTENSION = ".exe" if os.name == "nt" else ""
BINARY_URL = f"https://cdn-media.huggingface.co/frpc-gradio-{VERSION}/{BINARY_REMOTE_NAME}{EXTENSION}"

BINARY_FILENAME = f"{BINARY_REMOTE_NAME}_v{VERSION}"
BINARY_FOLDER = Path(__file__).parent
BINARY_PATH = f"{BINARY_FOLDER / BINARY_FILENAME}"


class Tunnel:
    def __init__(self, remote_host, remote_port, local_host, local_port, share_token):
        self.proc = None
        self.url = None
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.local_host = local_host
        self.local_port = local_port
        self.share_token = share_token

    @staticmethod
    def download_binary():
        if not Path(BINARY_PATH).exists():
            resp = requests.get(BINARY_URL)

            if resp.status_code == 403:
                raise OSError(
                    f"Cannot set up a share link as this platform is incompatible. Please "
                    f"create a GitHub issue with information about your platform: {platform.uname()}"
                )

            resp.raise_for_status()

            # Save file data to local copy
            with open(BINARY_PATH, "wb") as file:
                file.write(resp.content)
            st = os.stat(BINARY_PATH)
            os.chmod(BINARY_PATH, st.st_mode | stat.S_IEXEC)

    def start_tunnel(self) -> str:
        self.download_binary()
        self.url = self._start_tunnel(BINARY_PATH)
        return self.url

    def kill(self):
        if self.proc is not None:
            print(f"Killing tunnel {self.local_host}:{self.local_port} <> {self.url}")
            self.proc.terminate()
            self.proc = None

    def _start_tunnel(self, binary: str) -> str:
        CURRENT_TUNNELS.append(self)
        command = [
            binary,
            "http",
            "-n",
            self.share_token,
            "-l",
            str(self.local_port),
            "-i",
            self.local_host,
            "--uc",
            "--sd",
            "random",
            "--ue",
            "--server_addr",
            f"{self.remote_host}:{self.remote_port}",
            "--disable_log_color",
        ]
        self.proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        atexit.register(self.kill)
        url = ""
        while url == "":
            if self.proc.stdout is None:
                continue
            line = self.proc.stdout.readline()
            line = line.decode("utf-8")
            if "start proxy success" in line:
                result = re.search("start proxy success: (.+)\n", line)
                if result is None:
                    raise ValueError("Could not create share URL")
                else:
                    url = result.group(1)
        return url
