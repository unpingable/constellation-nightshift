#!/usr/bin/env python3
"""Reproducibly build the Nightshift and Pulse-support release tarballs.

Two independent clean builds run in a pinned Debian 12 Rust image with no
network, from one exact clean source commit and one hashed vendor snapshot.
Every compiled executable and every artifact must be byte-equal across the two
builds before anything is written to the output directory.

Outputs (one directory per component, as the cohort manifest requires one
artifact per component):

  <output>/nightshift/  nightshift-<v>-<short>-linux-amd64.tar.gz, SHA256SUMS,
                        build-receipt.v1.json, build-{a,b}.log
  <output>/pulse/       pulse-nq-load-support-<v>-<short>-linux-amd64.tar.gz,
                        SHA256SUMS, build-receipt.v1.json, build-{a,b}.log
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import Any

SCHEMA = "constellation.alpha_exit.nightshift_release_build.v1"
REPOSITORY = "https://github.com/unpingable/constellation-nightshift"
SOURCE_HEAD = "30c89fe17723a7b9d77b19fd650aadb0a784748d"
SOURCE_TREE = "343a47854048a720af7f433c20bdf973cbe79ead"
PROVENANCE = {
    "alpha6_runtime_pin": "9e592cbe581c24b3973677ef3938bccac4feea49",
    "public_equivalent_of_alpha6_pin": "8ab64ed",
    "campaign_base": "6844196",
    "alpha6_executed_foreman_revision_not_public": "01edf6fbcc71b6e63a8d732434a9162bd4e0989c",
    "alpha6_pulse_support_pin": "d91b214",
    "note": (
        "SOURCE_HEAD is main 6844196 plus four campaign commits (Foreman authority-expiry "
        "refusal, Nightshift build identity, Pulse build identity, Pulse enrollment of the NQ 0.2.0 "
        "nq.host identity). 6844196 contains 8ab64ed; "
        "runtime source differs from 8ab64ed only by ef7877f (exact-input reads accept an "
        "inherited /proc/self/fd descriptor) and e7c35db (additive lineage export). The Pulse "
        "support source equals d91b214 apart from its build identity and the added NQ 0.2.0 "
        "profile semantic id."
    ),
}
IMAGE_ID = "sha256:fb7a58d0482a24e269ba85636ce46cb06aaaef3aea0e868154ed0ae7c18fa379"
IMAGE_REPO_DIGEST = "rust@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f"
SOURCE_DATE_EPOCH = "1700000000"
BUILD_USER = "1000:1000"
VERSION = "0.1.0"
SHORT = SOURCE_HEAD[:7]
ARCH = "amd64"
MAX_GLIBC = (2, 36)
LIMITATIONS = [
    "vendor snapshot is a campaign-owned input produced by cargo vendor --locked",
    "the runtime crates' SOURCE-PROVENANCE.json files describe the pre-campaign export and do not cover the four campaign commits",
    "Foreman must be natively requalified; alpha.6 executed a binary built from non-public 01edf6f",
]
COMPONENTS: dict[str, dict[str, Any]] = {
    "nightshift": {
        "stem": f"nightshift-{VERSION}-{SHORT}-linux-{ARCH}",
        "binaries": {
            "nightshift": "runtime/release/nightshift",
            "nightshift-foreman": "runtime/release/nightshift-foreman",
            "nightshift-observation-resolver": "runtime/release/nightshift-observation-resolver",
        },
        "files": {
            "share/doc/nightshift/LICENSE": "runtime/LICENSE",
            "share/doc/nightshift/NOTICE": "runtime/NOTICE",
            "share/doc/nightshift/PRECOMPILED_WORKFLOW_LINEAGE.md": "runtime/docs/PRECOMPILED_WORKFLOW_LINEAGE.md",
        },
    },
    "pulse": {
        "stem": f"pulse-nq-load-support-{VERSION}-{SHORT}-linux-{ARCH}",
        "binaries": {
            "pulse-nq-load-support": "pulse/release/pulse-nq-load-support",
        },
        "files": {
            "share/pulse-nq-load-support/seal-pulse-support-resolver-launcher.py":
                "integrations/pulse-nq-load-support/tools/seal-pulse-support-resolver-launcher.py",
            "share/doc/pulse-nq-load-support/LICENSE": "integrations/pulse-nq-load-support/LICENSE",
            "share/doc/pulse-nq-load-support/THIRD_PARTY_NOTICES.md":
                "integrations/pulse-nq-load-support/THIRD_PARTY_NOTICES.md",
            "share/doc/pulse-nq-load-support/pulse-closed-resolver-launcher.md":
                "integrations/pulse-nq-load-support/docs/pulse-closed-resolver-launcher.md",
        },
    },
}
BUILD_ENV = {
    "CARGO_HOME": "/cargo-home",
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
    "HOME": "/tmp/nightshift-builder-home",
    "LC_ALL": "C.UTF-8",
    "NIGHTSHIFT_SOURCE_COMMIT": SOURCE_HEAD,
    "PULSE_NQ_LOAD_SUPPORT_SOURCE_COMMIT": SOURCE_HEAD,
    "RUSTFLAGS": "--remap-path-prefix=/src=. --remap-path-prefix=/vendor=/cargo-vendor --remap-path-prefix=/cargo-home=/cargo-home",
    "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
    "TZ": "UTC",
    "USER": "nightshift-builder",
}
BUILD_SCRIPT = (
    "set -eu; "
    "cd /src/runtime && cargo build --release --locked --offline --jobs 4 --target-dir /build/runtime "
    "--bin nightshift --bin nightshift-foreman --bin nightshift-observation-resolver; "
    "cd /src/integrations/pulse-nq-load-support && cargo build --release --locked --offline --jobs 4 "
    "--target-dir /build/pulse --bin pulse-nq-load-support; "
    "rustc --version; cargo --version"
)
TRACKED_INPUTS = (
    "runtime/Cargo.lock",
    "runtime/Cargo.toml",
    "integrations/pulse-nq-load-support/Cargo.lock",
    "integrations/pulse-nq-load-support/Cargo.toml",
)


class Refusal(RuntimeError):
    pass


def run(command: list[str], *, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise Refusal(
            f"command refused ({result.returncode}): {command!r}\n"
            + result.stderr.decode(errors="replace")[-4000:]
        )
    return result


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def tree_digest(root: pathlib.Path) -> tuple[str, int]:
    if not root.is_dir() or root.is_symlink():
        raise Refusal("vendor input is not one physical directory")
    digest = hashlib.sha256(b"nightshift-release-vendor-tree-v1\0")
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise Refusal(f"vendor input contains a non-regular entry: {path}")
        relative = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update((metadata.st_mode & 0o777).to_bytes(4, "big"))
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        count += 1
    if count == 0:
        raise Refusal("vendor input is empty")
    return digest.hexdigest(), count


def source_facts(source: pathlib.Path) -> dict[str, Any]:
    if not source.is_dir() or source.is_symlink():
        raise Refusal("source is not one physical directory")
    head = run(["git", "rev-parse", "HEAD"], cwd=source).stdout.decode().strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=source).stdout.decode().strip()
    if head != SOURCE_HEAD or tree != SOURCE_TREE:
        raise Refusal(f"source head/tree {head}/{tree} differs from the accepted release source")
    if run(["git", "status", "--porcelain", "--ignored"], cwd=source).stdout:
        raise Refusal("source worktree is not clean (including ignored files)")
    return {
        "repository": REPOSITORY,
        "head": head,
        "tree": tree,
        "clean": True,
        "provenance": PROVENANCE,
        "tracked_inputs_sha256": {name: sha256(source / name) for name in TRACKED_INPUTS},
    }


def image_facts() -> dict[str, Any]:
    records = json.loads(run(["/usr/bin/docker", "image", "inspect", IMAGE_ID]).stdout)
    if len(records) != 1 or records[0].get("Id") != IMAGE_ID:
        raise Refusal("local builder image identity differs")
    if IMAGE_REPO_DIGEST not in records[0].get("RepoDigests", []):
        raise Refusal("local builder repository digest is absent")
    return {"image_id": IMAGE_ID, "repository_digest": IMAGE_REPO_DIGEST, "network": "none", "pull": "never"}


def docker_argv(source: str, vendor: str, cargo_home: str, build: str) -> list[str]:
    command = [
        "/usr/bin/docker", "run", "--rm", "--pull", "never", "--network", "none",
        "--hostname", "nightshift-release-builder", "--user", BUILD_USER,
    ]
    for key, value in sorted(BUILD_ENV.items()):
        command.extend(["-e", f"{key}={value}"])
    command.extend([
        "-v", f"{source}:/src:ro", "-v", f"{vendor}:/vendor:ro",
        "-v", f"{cargo_home}:/cargo-home:rw", "-v", f"{build}:/build:rw",
        "-w", "/src", IMAGE_ID, "sh", "-c", BUILD_SCRIPT,
    ])
    return command


def cargo_config() -> str:
    return """[net]
offline = true

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "/vendor"
"""


def glibc_ceiling(path: pathlib.Path) -> str | None:
    versions = run(["readelf", "--version-info", str(path)]).stdout.decode()
    parsed = [(int(a), int(b)) for a, b in re.findall(r"Name: GLIBC_(\d+)\.(\d+)", versions)]
    newest = max(parsed) if parsed else None
    if newest is not None and newest > MAX_GLIBC:
        raise Refusal(f"{path.name} requires glibc {newest}, beyond Debian 12")
    return None if newest is None else f"GLIBC_{newest[0]}.{newest[1]}"


def tar_member(name: str, data: bytes, mode: int) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(SOURCE_DATE_EPOCH)
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.type = tarfile.REGTYPE
    return info, data


def directory_member(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.mtime = int(SOURCE_DATE_EPOCH)
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    return info


def assemble(component: str, source: pathlib.Path, build: pathlib.Path, output: pathlib.Path) -> dict[str, Any]:
    spec = COMPONENTS[component]
    stem = spec["stem"]
    members: dict[str, tuple[bytes, int]] = {}
    binaries: dict[str, Any] = {}
    for name, relative in spec["binaries"].items():
        path = build / relative
        data = path.read_bytes()
        members[f"bin/{name}"] = (data, 0o755)
        binaries[name] = {
            "path": f"bin/{name}",
            "bytes": len(data),
            "sha256": sha256_bytes(data),
            "maximum_glibc": glibc_ceiling(path),
        }
    for name, relative in spec["files"].items():
        members[name] = ((source / relative).read_bytes(), 0o644)
    build_info = {
        "schema": "constellation.alpha_exit.component_build_info.v1",
        "component": component,
        "version": VERSION,
        "source_repository": REPOSITORY,
        "source_commit": SOURCE_HEAD,
        "source_tree": SOURCE_TREE,
        "binaries": {name: {"path": fact["path"], "sha256": fact["sha256"]} for name, fact in binaries.items()},
    }
    members["BUILD-INFO.json"] = (
        (json.dumps(build_info, sort_keys=True, indent=2) + "\n").encode(), 0o644
    )
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        directories: set[str] = {stem}
        for name in members:
            parts = name.split("/")[:-1]
            for index in range(1, len(parts) + 1):
                directories.add(f"{stem}/{'/'.join(parts[:index])}")
        entries: list[tuple[str, Any]] = [(d, None) for d in directories]
        entries += [(f"{stem}/{name}", members[name]) for name in members]
        for name, payload in sorted(entries, key=lambda entry: entry[0]):
            if payload is None:
                archive.addfile(directory_member(name))
            else:
                info, data = tar_member(name, payload[0], payload[1])
                archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0, compresslevel=9) as stream:
        stream.write(raw.getvalue())
    tarball = f"{stem}.tar.gz"
    output.mkdir(parents=True)
    (output / tarball).write_bytes(compressed.getvalue())
    (output / "SHA256SUMS").write_text(f"{sha256(output / tarball)}  {tarball}\n", encoding="utf-8")
    return {
        "tarball": tarball,
        "binaries": binaries,
        "artifacts": {
            name: {"bytes": (output / name).stat().st_size, "sha256": sha256(output / name)}
            for name in (tarball, "SHA256SUMS")
        },
        "build_info": build_info,
    }


def qualification_facts() -> dict[str, Any]:
    builder = pathlib.Path(__file__).resolve(strict=True)
    return {"builder": {"path": "qualification/alpha-exit-packaging-v1/build_release.py", "sha256": sha256(builder)}}


def build(source: pathlib.Path, vendor: pathlib.Path, output: pathlib.Path, scratch_parent: pathlib.Path) -> None:
    if output.exists():
        raise Refusal("output path already exists")
    if f"{os.getuid()}:{os.getgid()}" != BUILD_USER:
        raise Refusal(f"builder requires host uid:gid {BUILD_USER}")
    source = source.resolve(strict=True)
    vendor = vendor.resolve(strict=True)
    source_record = source_facts(source)
    vendor_sha, vendor_files = tree_digest(vendor)
    builder_record = image_facts()
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="nightshift-release-build.", dir=scratch_parent))
    try:
        results: dict[str, list[dict[str, Any]]] = {name: [] for name in COMPONENTS}
        logs: dict[str, bytes] = {}
        for label in ("a", "b"):
            case = scratch / label
            (case / "cargo-home").mkdir(parents=True)
            (case / "build").mkdir()
            (case / "cargo-home" / "config.toml").write_text(cargo_config(), encoding="utf-8")
            built = run(docker_argv(str(source), str(vendor), str(case / "cargo-home"), str(case / "build")))
            logs[label] = built.stdout + built.stderr
            for component in COMPONENTS:
                results[component].append(assemble(component, source, case / "build", case / "out" / component))
        for component, pair in results.items():
            if pair[0]["binaries"] != pair[1]["binaries"]:
                raise Refusal(f"{component}: independent build binary identities differ")
            if pair[0]["artifacts"] != pair[1]["artifacts"]:
                raise Refusal(f"{component}: independent release artifacts differ")
        output.mkdir(mode=0o755)
        normalized = docker_argv("<SOURCE>", "<VENDOR>", "<CARGO_HOME>", "<BUILD>")
        for component, pair in results.items():
            destination = output / component
            shutil.copytree(scratch / "a" / "out" / component, destination)
            for label in ("a", "b"):
                (destination / f"build-{label}.log").write_bytes(logs[label])
            receipt = {
                "schema": SCHEMA,
                "component": component,
                "version": VERSION,
                "source": source_record,
                "vendor": {"tree_sha256": vendor_sha, "regular_files": vendor_files, "container_path": "/vendor"},
                "builder": builder_record,
                "build": {
                    "environment": BUILD_ENV,
                    "script": BUILD_SCRIPT,
                    "normalized_docker_argv": normalized,
                    "cargo_config_sha256": sha256_bytes(cargo_config().encode()),
                    "profile": "release",
                },
                "binaries": pair[0]["binaries"],
                "artifacts": pair[0]["artifacts"],
                "build_info": pair[0]["build_info"],
                "reproduction": {
                    "clean_builds": 2,
                    "binary_bytes_equal": True,
                    "artifact_bytes_equal": True,
                    "build_b_artifacts": pair[1]["artifacts"],
                },
                "logs": {
                    f"build-{label}.log": {"sha256": sha256_bytes(logs[label]), "bytes": len(logs[label])}
                    for label in ("a", "b")
                },
                "qualification": qualification_facts(),
                "limitations": LIMITATIONS,
            }
            (destination / "build-receipt.v1.json").write_text(
                json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            print(json.dumps({
                "result": "REPRODUCIBLE_RELEASE_ARTIFACT",
                "component": component,
                "tarball": pair[0]["tarball"],
                "sha256": pair[0]["artifacts"][pair[0]["tarball"]]["sha256"],
            }, sort_keys=True))
    except Exception:
        if output.exists():
            shutil.rmtree(output)
        raise
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    root.add_argument("--source", type=pathlib.Path, required=True, help="clean checkout at SOURCE_HEAD")
    root.add_argument("--vendor", type=pathlib.Path, required=True, help="cargo vendor --locked snapshot")
    root.add_argument("--output", type=pathlib.Path, required=True)
    root.add_argument("--scratch", type=pathlib.Path, default=pathlib.Path(tempfile.gettempdir()))
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        build(args.source, args.vendor, args.output, args.scratch)
        return 0
    except (OSError, ValueError, Refusal) as error:
        print(f"REFUSED: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
