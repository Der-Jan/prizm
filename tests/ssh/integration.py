#!/usr/bin/env python3
"""Opt-in signed sandbox + real OpenSSH integration, using only synthetic keys.

Run from the repository: python3 tests/ssh/integration.py
Requires configured LocalConfig.xcconfig, Xcode, OpenSSH and OpenSSL 3.
Never imports a key into the user's real vault or touches an existing agent.
"""
import base64
import os
import pathlib
import pwd
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import uuid

repo = pathlib.Path(__file__).resolve().parents[2]
user = pwd.getpwuid(os.getuid())
container = pathlib.Path(user.pw_dir) / 'Library/Containers/de.b0x42.Prizm/Data'
run = uuid.uuid4().hex[:8]
agent_path = container / ('.ssh-test-' + run + '.sock')
ready = container / ('.ssh-test-' + run + '-ready')
complete = container / ('.ssh-test-' + run + '-complete')
openssl = os.environ.get('PRIZM_TEST_OPENSSL') or next((p for p in ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl'] if pathlib.Path(p).exists()), shutil.which('openssl'))
if not openssl:
    raise SystemExit('OpenSSL is required for independent signature verification')
if os.path.lexists(agent_path) or ready.exists() or complete.exists():
    raise SystemExit('Test path collision; no existing socket or test file will be changed')


def ssh_string(data):
    return struct.pack('>I', len(data)) + data


def field(data):
    count = struct.unpack('>I', data[:4])[0]
    assert count <= len(data) - 4
    return data[4:4 + count], data[4 + count:]


with tempfile.TemporaryDirectory(prefix='prizm-ssh-test-') as temporary:
    root = pathlib.Path(temporary)
    subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root / 'host')], check=True)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    config = root / 'sshd_config'
    config.write_text(f'''Port {port}
ListenAddress 127.0.0.1
HostKey {root}/host
PidFile {root}/sshd.pid
AuthorizedKeysFile {root}/authorized_keys
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowUsers {user.pw_name}
''')
    server_log = open(root / 'sshd.log', 'w')
    sshd = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(config)], stdout=server_log, stderr=subprocess.STDOUT)
    build_log = pathlib.Path('/tmp/prizm-ssh-signed-integration.log')
    output = open(build_log, 'w')
    environment = dict(os.environ, TEST_RUNNER_PRIZM_SSH_SIGNED_SOCKET_TEST='1', TEST_RUNNER_PRIZM_SSH_TEST_RUN_ID=run)
    build = subprocess.Popen(['xcodebuild', 'test', '-project', 'Prizm/Prizm.xcodeproj', '-scheme', 'Prizm',
                              '-destination', 'platform=macOS', '-derivedDataPath', '/tmp/prizm-ssh-signed',
                              '-allowProvisioningUpdates', '-only-testing:PrizmTests/SSHAgentLifecycleTests/testSignedContainerSocketWithExternalOpenSSHClient'],
                             cwd=repo, env=environment, stdout=output, stderr=subprocess.STDOUT)
    try:
        for _ in range(1800):
            if ready.exists():
                break
            if build.poll() is not None:
                raise RuntimeError(f'Signed test host exited; see {build_log}')
            if sshd.poll() is not None:
                raise RuntimeError((root / 'sshd.log').read_text())
            time.sleep(.1)
        else:
            raise RuntimeError('Signed test host did not become ready')
        env = dict(os.environ, SSH_AUTH_SOCK=str(agent_path))
        listing = subprocess.check_output(['/usr/bin/ssh-add', '-L'], env=env, timeout=10).decode().strip()
        assert listing.startswith('ssh-ed25519 ')
        blob = base64.b64decode(listing.split()[1])
        name, rest = field(blob)
        public, rest = field(rest)
        assert not rest and len(public) == 32
        payload = ssh_string(b'1' * 32) + b'\x32' + ssh_string(user.pw_name.encode()) + ssh_string(b'ssh-connection') + ssh_string(b'publickey') + b'\x01' + ssh_string(name) + ssh_string(blob)
        request = ssh_string(b'\x0d' + ssh_string(blob) + ssh_string(payload) + struct.pack('>I', 0))
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(10)
            client.connect(str(agent_path))
            # Fragmented header and payload must not be discarded.
            client.sendall(request[:1])
            client.sendall(request[1:7])
            client.sendall(request[7:])
            def read(count):
                data = b''
                while len(data) < count:
                    part = client.recv(count - len(data))
                    assert part
                    data += part
                return data
            reply = read(struct.unpack('>I', read(4))[0])
        assert reply[0] == 14
        signature, trailing = field(reply[1:])
        assert not trailing
        algorithm, signature = field(signature)
        signature, trailing = field(signature)
        assert algorithm == b'ssh-ed25519' and not trailing
        (root / 'pub.der').write_bytes(bytes.fromhex('302a300506032b6570032100') + public)
        (root / 'payload').write_bytes(payload)
        (root / 'signature').write_bytes(signature)
        subprocess.run([openssl, 'pkeyutl', '-verify', '-pubin', '-rawin', '-keyform', 'DER', '-inkey', str(root / 'pub.der'), '-in', str(root / 'payload'), '-sigfile', str(root / 'signature')], check=True)
        (root / 'authorized_keys').write_text(listing + '\n')
        (root / 'identity.pub').write_text(listing + '\n')
        host = subprocess.check_output(['/usr/bin/ssh-keygen', '-y', '-f', str(root / 'host')]).decode().strip()
        (root / 'known_hosts').write_text(f'[127.0.0.1]:{port} {host}\n')
        # New TCP/agent connection each time: the second must reuse the explicit
        # until-lock grant after verifying a fresh OpenSSH session binding.
        for _ in range(2):
            subprocess.run(['/usr/bin/ssh', '-F', '/dev/null', '-p', str(port), '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(root / 'known_hosts'), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-i', str(root / 'identity.pub'), user.pw_name + '@127.0.0.1', 'true'], env=env, check=True, timeout=10)
        complete.write_text('verified')
        assert build.wait(timeout=60) == 0, f'Xcode test failed; see {build_log}'
        print('PASS: signed sandbox agent, ssh-add, independent signature verification and two OpenSSH logins with verified binding and remembered approval')
    finally:
        for process in (build, sshd):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        output.close()
        server_log.close()
