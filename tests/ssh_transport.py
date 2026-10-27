"""Optional Linux CI test: real SSH, SFTP, file copy and a shared master.

Requires a normal local account, openssh-server and passwordless sudo only to run
an isolated loopback sshd. Never edits system sshd config or real authorized_keys.
"""
import getpass
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "build/ssh_transport-test"
if os.getuid() == 0:
    raise SystemExit("ssh-test requires a normal non-root test account")
user = getpass.getuser()
with tempfile.TemporaryDirectory(prefix="dpdp-real-ssh-") as tmp:
    directory = Path(tmp)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(directory / "host")], check=True)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    command = [str(HELPER), tmp, user, str(port)]
    subprocess.run(command + ["prepare"], check=True, timeout=15)
    config = directory / "sshd_config"
    config.write_text(f"""Port {port}
ListenAddress 127.0.0.1
HostKey {directory / 'host'}
PidFile {directory / 'sshd.pid'}
AuthorizedKeysFile {directory / 'authorized_keys'}
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers {user}
UsePAM yes
AllowTcpForwarding yes
GatewayPorts no
LogLevel ERROR
Subsystem sftp /usr/lib/openssh/sftp-server
""")
    subprocess.run(["sudo", "-n", "mkdir", "-p", "/run/sshd"], check=True)
    log = open(directory / "sshd.log", "w+")
    server = subprocess.Popen(["sudo", "-n", "/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stdout=log, stderr=log)
    master = None
    try:
        for _ in range(100):
            if server.poll() is not None:
                log.seek(0)
                raise AssertionError(log.read())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        master = subprocess.Popen(command + ["master"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(100):
            if list(directory.glob("cm-*")) and any(p.is_socket() for p in directory.glob("cm-*")):
                break
            if master.poll() is not None:
                raise AssertionError(master.communicate()[1].decode())
            time.sleep(0.05)
        assert any(p.is_socket() for p in directory.glob("cm-*")), "master socket missing"
        shell = subprocess.run(command + ["ssh", "printf", "dpdp-transport-ok"], text=True, capture_output=True, timeout=15)
        assert shell.returncode == 0 and "dpdp-transport-ok" in shell.stdout, shell.stderr
        source = directory / "source file.txt"
        source.write_bytes(b"DPDP actual SFTP transport\x00\xff\n")
        uploaded = directory / "uploaded file.txt"
        downloaded = directory / "downloaded file.txt"
        subprocess.run(command + ["send", str(source), str(uploaded)], check=True, timeout=15)
        subprocess.run(command + ["receive", str(uploaded), str(downloaded)], check=True, timeout=15)
        assert source.read_bytes() == uploaded.read_bytes() == downloaded.read_bytes()
        listing = subprocess.run(command + ["sftp"], input=f"ls {tmp}\nbye\n", text=True, capture_output=True, timeout=15)
        assert listing.returncode == 0 and "uploaded file.txt" in listing.stdout, listing.stderr
        assert master.poll() is None, "shared master unexpectedly exited"
        print("OK: real pinned SSH, shared master, SFTP listing and binary file round trip")
    finally:
        if master is not None and master.poll() is None:
            master.terminate()
            master.communicate(timeout=8)
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        log.close()
