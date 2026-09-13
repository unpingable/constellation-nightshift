#!/usr/bin/python3
"""Create a closed zero-argument launcher for Pulse support resolution.

The generated launcher is an executable descriptor, not a general command
runner.  It captures both configured files into sealed memfds before it execs
the fixed resolver role.  The resolver source revision that consumes this
descriptor recognizes only the exact /proc/self/fd configuration form below.
"""

import argparse
import hashlib
import json
import os
import pathlib
import stat


SCHEMA = "pulse.nq_host_load_pressure.closed_resolver_launcher_enrollment.v1"
MANIFEST_SCHEMA = "pulse.nq_host_load_pressure.closed_resolver_launcher_manifest.v1"
MAX_ENROLLMENT = 64 * 1024
MAX_CONFIG = 64 * 1024
MAX_RESOLVER = 512 * 1024 * 1024
MAX_INTERPRETER = 128 * 1024 * 1024


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_regular(path, executable, maximum):
    if not path.is_absolute():
        raise ValueError("configured paths must be absolute")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode):
            raise ValueError(f"not a regular file: {path}")
        if executable and meta.st_mode & 0o111 == 0:
            raise ValueError(f"not an executable regular file: {path}")
        chunks = []
        total = 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - total))
            if not block:
                return b"".join(chunks)
            total += len(block)
            if total > maximum:
                raise ValueError(f"regular file exceeds {maximum} bytes: {path}")
            chunks.append(block)
    finally:
        os.close(fd)


def load_enrollment(path):
    raw = read_regular(path, False, MAX_ENROLLMENT)
    if not raw:
        raise ValueError("enrollment must be between 1 byte and 64 KiB")
    value = json.loads(raw)
    if canonical(value) != raw:
        raise ValueError("enrollment must be exact canonical JSON")
    required = {
        "schema", "resolver_program", "resolver_sha256", "config_path",
        "config_sha256", "python_interpreter", "python_sha256",
    }
    if not isinstance(value, dict) or set(value) != required or value["schema"] != SCHEMA:
        raise ValueError("unsupported or non-closed enrollment")
    for name in ("resolver_program", "config_path", "python_interpreter"):
        if not isinstance(value[name], str) or not value[name]:
            raise ValueError(f"{name} must be a nonempty string")
        value[name] = str(pathlib.Path(value[name]))
        if not pathlib.Path(value[name]).is_absolute():
            raise ValueError(f"{name} must be absolute")
    if any(character.isspace() for character in value["python_interpreter"]):
        raise ValueError("Python interpreter path is not valid in a shebang")
    resolver = read_regular(pathlib.Path(value["resolver_program"]), True, MAX_RESOLVER)
    config = read_regular(pathlib.Path(value["config_path"]), False, MAX_CONFIG)
    interpreter = read_regular(pathlib.Path(value["python_interpreter"]), True, MAX_INTERPRETER)
    for name, actual in (("resolver_sha256", resolver), ("config_sha256", config),
                         ("python_sha256", interpreter)):
        if not isinstance(value[name], str) or digest(actual) != value[name]:
            raise ValueError(f"{name} mismatch")
    return value


def launcher_bytes(value):
    embedded = repr({key: value[key] for key in sorted(value)})
    source = f'''#!{value["python_interpreter"]} -I
import fcntl, hashlib, os, stat, sys
C={embedded}
MAX_CONFIG={MAX_CONFIG}
MAX_RESOLVER={MAX_RESOLVER}
if len(sys.argv) != 1:
    raise SystemExit("pulse support resolver launcher accepts no arguments")
def capture(path, expected, maximum, executable, name):
    flags=os.O_RDONLY|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(path,flags)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or (executable and meta.st_mode & 0o111 == 0):
            raise SystemExit("configured "+name+" is not an allowed regular file")
        image=os.memfd_create("pulse-"+name,os.MFD_ALLOW_SEALING)
        h=hashlib.sha256(); total=0
        while True:
            block=os.read(fd,65536)
            if not block: break
            total+=len(block)
            if total>maximum: raise SystemExit("configured "+name+" exceeds its byte bound")
            h.update(block); view=memoryview(block)
            while view:
                written=os.write(image,view)
                if written<=0: raise SystemExit("sealed "+name+" image write was incomplete")
                view=view[written:]
        if "sha256:"+h.hexdigest()!=expected:
            raise SystemExit("configured "+name+" digest mismatch")
    finally:
        os.close(fd)
    os.fchmod(image,0o500 if executable else 0o400)
    fcntl.fcntl(image,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
    os.lseek(image,0,os.SEEK_SET); os.set_inheritable(image,True)
    return image
resolver=capture(C["resolver_program"],C["resolver_sha256"],MAX_RESOLVER,True,"resolver")
config=capture(C["config_path"],C["config_sha256"],MAX_CONFIG,False,"config")
program="/proc/self/fd/"+str(resolver)
config_descriptor="/proc/self/fd/"+str(config)
os.execve(program,["pulse-support-resolver"],{{"PULSE_LOAD_SUPPORT_CONFIG":config_descriptor,"PULSE_LOAD_SUPPORT_CONFIG_SHA256":C["config_sha256"]}})
'''
    return source.encode()


def exclusive(path, data, mode):
    if not path.is_absolute():
        raise ValueError("output paths must be absolute")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("exclusive output write was incomplete")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--enrollment", required=True, type=pathlib.Path)
    parser.add_argument("--launcher", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.launcher.name != "pulse-support-resolver":
        raise ValueError("launcher basename must be pulse-support-resolver")
    value = load_enrollment(args.enrollment)
    launcher = launcher_bytes(value)
    exclusive(args.launcher, launcher, 0o500)
    manifest = canonical({
        "schema": MANIFEST_SCHEMA,
        "launcher": str(args.launcher),
        "launcher_sha256": digest(launcher),
        "resolver_program": value["resolver_program"],
        "resolver_sha256": value["resolver_sha256"],
        "config_path": value["config_path"],
        "config_sha256": value["config_sha256"],
        "python_interpreter": value["python_interpreter"],
        "python_sha256": value["python_sha256"],
    })
    exclusive(args.manifest, manifest, 0o400)


if __name__ == "__main__":
    main()
