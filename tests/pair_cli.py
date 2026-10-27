"""Pair two configured nodes using real TCP, PAKE, TLS and CLI code entry."""
import os
import getpass
import re
import subprocess
import sys
from pathlib import Path

binary, client_config, server_config, peer = sys.argv[1:]
server_env = dict(os.environ, HOME=str(Path(server_config).parent))
client_env = dict(os.environ, HOME=str(Path(client_config).parent))
def in_namespace(command, name, home):
    if not name:
        return command
    return ["sudo", "-n", "ip", "netns", "exec", name, "runuser", "-u", getpass.getuser(), "--", "env", f"HOME={home}"] + command

server = subprocess.Popen(
    in_namespace([binary, "pair-server", "--config", server_config], os.getenv("DPDP_SERVER_NS"), str(Path(server_config).parent)),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=server_env,
)
try:
    first = server.stderr.readline()
    match = re.fullmatch(r"Pairing code: ([0-9]{6})\n", first)
    if not match:
        raise AssertionError(f"pairing listener failed: {first}{server.stderr.read()}")
    # Code stays out of command arguments and environment variables.
    client = subprocess.run(
        in_namespace([binary, "pair", peer, "--config", client_config], os.getenv("DPDP_CLIENT_NS"), str(Path(client_config).parent)),
        input=match[1] + "\n", text=True, capture_output=True,
        timeout=20, env=client_env,
    )
    if client.returncode:
        raise AssertionError(f"client pairing failed: {client.stderr}")
    _, error = server.communicate(timeout=15)
    assert server.returncode == 0, error
    print("OK: TCP pairing CLI exchanges and pins both identities")
finally:
    if server.poll() is None:
        server.terminate()
        server.wait(timeout=5)
