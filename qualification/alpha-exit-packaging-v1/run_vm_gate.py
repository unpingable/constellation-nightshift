#!/usr/bin/env python3
"""Run the Nightshift/Pulse release gate in one fresh Debian 12 VM.

Host side: verify the base image against SHA512SUMS, create a qcow2 overlay
and a cloud-init seed, boot under KVM with user networking restrict=on (one SSH
hostfwd on 127.0.0.1) and -sandbox on, upload only the release artifacts, the
synthetic fixtures and guest/gate.py, run the gate as root in the guest, fetch
its JSON result, power off, and write VM-GATE-RESULT.json.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
IMAGE = pathlib.Path(
    "/data/git/.campaign-artifacts/constellation-operator-beta-composed-m2-run-002/input/"
    "debian-12-genericcloud-amd64-20260903-2590.qcow2"
)
GUEST_USER = "gate"
FIXTURES = (
    "foreman-provider-draft.json",
    "nightshift-synthetic.sqlite",
    "nightshift-synthetic.sqlite.expected.json",
    "nightshift-synthetic.sqlite.base-request.json",
    "pulse-config.json",
    "pulse-producer-key.hex",
)


class Refusal(RuntimeError):
    pass


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(path: pathlib.Path, algorithm: str = "sha256") -> str:
    value = hashlib.new(algorithm)
    with path.open("rb") as source:
        while block := source.read(1 << 20):
            value.update(block)
    return value.hexdigest()


def run(argv: list[str], *, check: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(argv, capture_output=True, check=False, timeout=timeout)
    if check and result.returncode != 0:
        raise Refusal(f"{shlex.join(argv)} -> {result.returncode}: {result.stderr.decode(errors='replace')[-2000:]}")
    return result


def port_free(port: int) -> bool:
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=pathlib.Path, required=True, help="directory holding nightshift/ and pulse/")
    parser.add_argument("--fixtures", type=pathlib.Path, required=True)
    parser.add_argument("--state", type=pathlib.Path, required=True, help="empty VM state directory (root fs)")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--image", type=pathlib.Path, default=IMAGE)
    parser.add_argument("--ssh-port", type=int, default=23411)
    args = parser.parse_args()

    for tool in ("qemu-img", "qemu-system-x86_64", "xorriso", "ssh", "scp", "ssh-keygen"):
        if shutil.which(tool) is None:
            raise Refusal(f"missing tool {tool}")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise Refusal("/dev/kvm unavailable")
    if not port_free(args.ssh_port):
        raise Refusal(f"port {args.ssh_port} busy")
    if args.state.exists() and any(args.state.iterdir()):
        raise Refusal("state directory not empty")
    if args.output.exists():
        raise Refusal("output exists")
    sums = {}
    for line in (args.image.parent / "SHA512SUMS").read_text().splitlines():
        value, _, name = line.strip().partition("  ")
        sums[name] = value
    image_sha512 = digest(args.image, "sha512")
    if sums.get(args.image.name) != image_sha512:
        raise Refusal("base image SHA-512 mismatch")
    receipts = {}
    for component in ("nightshift", "pulse"):
        directory = args.artifacts / component
        checked = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=directory,
                                 capture_output=True, text=True)
        if checked.returncode != 0:
            raise Refusal(f"{component} SHA256SUMS: {checked.stdout}{checked.stderr}")
        receipts[component] = json.loads((directory / "build-receipt.v1.json").read_text())
    commit = receipts["nightshift"]["source"]["head"]
    if receipts["pulse"]["source"]["head"] != commit or len(commit) != 40:
        raise Refusal("receipts disagree on the source commit")

    args.state.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.mkdir(parents=True)
    key = args.state / "id_ed25519"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "nightshift-vm-gate", "-f", str(key)])
    public = key.with_suffix(".pub").read_text().strip()
    (args.state / "meta-data").write_text("instance-id: nightshift-vm-gate\nlocal-hostname: nightshift-gate\n")
    (args.state / "user-data").write_text(f"""#cloud-config
disable_root: true
hostname: nightshift-gate
package_update: false
package_upgrade: false
ssh_pwauth: false
users:
  - name: {GUEST_USER}
    groups: [sudo]
    lock_passwd: true
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - "{public}"
""")
    run(["xorriso", "-as", "mkisofs", "-quiet", "-output", str(args.state / "seed.iso"), "-volid", "cidata",
         "-joliet", "-rock", str(args.state / "user-data"), str(args.state / "meta-data")])
    run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(args.image), "-F", "qcow2",
         str(args.state / "overlay.qcow2")])
    qemu = [
        "qemu-system-x86_64", "-name", "nightshift-vm-gate,process=nightshift-vm-gate",
        "-no-user-config", "-nodefaults", "-accel", "kvm", "-machine", "q35", "-cpu", "host",
        "-smp", "2", "-m", "2048", "-display", "none", "-monitor", "none",
        "-serial", f"file:{args.state / 'serial.log'}", "-pidfile", str(args.state / "qemu.pid"),
        "-drive", f"if=virtio,file={args.state / 'overlay.qcow2'},format=qcow2,cache=none,aio=threads",
        "-drive", f"if=virtio,file={args.state / 'seed.iso'},format=raw,readonly=on",
        "-netdev", f"user,id=mgmt,restrict=on,hostfwd=tcp:127.0.0.1:{args.ssh_port}-:22",
        "-device", "virtio-net-pci,netdev=mgmt,mac=52:54:00:9c:11:01",
        "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
    ]
    ssh = ["ssh", "-i", str(key), "-p", str(args.ssh_port), "-o", "IdentitiesOnly=yes",
           "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={args.state / 'known_hosts'}",
           "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR", f"{GUEST_USER}@127.0.0.1"]
    scp = ["scp", "-q", "-r", "-i", str(key), "-P", str(args.ssh_port), "-o", "IdentitiesOnly=yes",
           "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={args.state / 'known_hosts'}",
           "-o", "LogLevel=ERROR"]
    started = now()
    process = subprocess.Popen(qemu, stdout=(args.state / "qemu.stdout.log").open("wb"),
                               stderr=(args.state / "qemu.stderr.log").open("wb"), start_new_session=True)
    transcript: list[dict] = []

    def guest(command: str, *, timeout: float = 900) -> subprocess.CompletedProcess[bytes]:
        result = run(ssh + [command], check=False, timeout=timeout)
        transcript.append({"command": command, "exit": result.returncode,
                           "stdout": result.stdout.decode(errors="replace")[-20000:],
                           "stderr": result.stderr.decode(errors="replace")[-20000:]})
        return result

    try:
        deadline = time.monotonic() + 900
        while True:
            if process.poll() is not None:
                raise Refusal("qemu exited: " + (args.state / "qemu.stderr.log").read_text()[-1000:])
            try:
                if run(ssh + ["true"], check=False, timeout=30).returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() > deadline:
                raise Refusal("guest SSH unreachable")
            time.sleep(3)
        guest("cloud-init status --wait >/dev/null; cloud-init status")
        release = guest('. /etc/os-release; printf "%s:%s" "$ID" "$VERSION_ID"')
        if release.stdout != b"debian:12":
            raise Refusal(f"guest is not Debian 12: {release.stdout!r}")
        guest("mkdir -p /home/gate/inputs/fixtures")
        for component in ("nightshift", "pulse"):
            run(scp + [str(args.artifacts / component), f"{GUEST_USER}@127.0.0.1:/home/gate/inputs/"])
        run(scp + [str(args.fixtures / name) for name in FIXTURES] + [f"{GUEST_USER}@127.0.0.1:/home/gate/inputs/fixtures/"])
        run(scp + [str(HERE / "guest" / "gate.py"), f"{GUEST_USER}@127.0.0.1:/home/gate/gate.py"])
        gate = guest(f"sudo /usr/bin/python3 -I /home/gate/gate.py --inputs /home/gate/inputs --source-commit {commit}",
                     timeout=1800)
        (args.output / "gate-stdout.json").write_bytes(gate.stdout)
        (args.output / "gate-stderr.log").write_bytes(gate.stderr)
        try:
            gate_result = json.loads(gate.stdout)
        except json.JSONDecodeError as error:
            raise Refusal(f"gate produced no JSON: {error}: {gate.stderr.decode(errors='replace')[-2000:]}")
        guest("sudo systemctl poweroff", timeout=30)
    finally:
        try:
            process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        for name in ("serial.log", "qemu.stderr.log"):
            if (args.state / name).exists():
                shutil.copy2(args.state / name, args.output / name)
        (args.output / "qemu-command.txt").write_text(shlex.join(qemu) + "\n")
        (args.output / "transcript.json").write_text(json.dumps(transcript, indent=2) + "\n")

    result = {
        "schema": "constellation.alpha_exit.nightshift_vm_gate_run.v1",
        "started_at": started,
        "finished_at": now(),
        "source_commit": commit,
        "image": {"path": str(args.image), "sha512": image_sha512},
        "artifacts": {
            component: {name: artifact["sha256"] for name, artifact in receipts[component]["artifacts"].items()}
            for component in receipts
        },
        "fixtures": {name: digest(args.fixtures / name) for name in FIXTURES},
        "harness": {
            "run_vm_gate.py": digest(pathlib.Path(__file__).resolve()),
            "guest/gate.py": digest(HERE / "guest" / "gate.py"),
        },
        "network": "user,restrict=on; ssh hostfwd 127.0.0.1 only",
        "passed": gate_result["passed"],
        "failed": gate_result["failed"],
        "cases": [{k: case[k] for k in ("case", "title", "verdict")} for case in gate_result["cases"]],
        "verdict": "PASS" if gate_result["failed"] == 0 and gate.returncode == 0 else "FAIL",
    }
    (args.output / "VM-GATE-RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"verdict": result["verdict"], "passed": result["passed"], "failed": result["failed"]}))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        raise SystemExit(2)
