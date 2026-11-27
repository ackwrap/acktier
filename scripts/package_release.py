#!/usr/bin/env python3
"""Build the AckTier center and client archives for one target."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_ARCHES = {"amd64": "amd64", "arm64": "arm64", "386": "x86"}
PROGRAMS = {
    "center": ("acktier-server", "acktier"),
    "client": ("acktierd", "acktier"),
}


def prepare_wintun(arch, work):
    download = work / "wintun.zip"
    subprocess.run(
        [
            "curl", "--fail", "--silent", "--show-error", "--location",
            "--proto", "=https", "--proto-redir", "=https", "--max-time", "40",
            "--retry", "3", "--retry-all-errors", "--retry-max-time", "90",
            "--max-filesize", "4194304",
            "--output", str(download), WINTUN_URL,
        ],
        check=True,
    )
    if hashlib.sha256(download.read_bytes()).hexdigest() != WINTUN_SHA256:
        raise ValueError("Wintun archive SHA-256 does not match the official release")
    files = {
        "wintun.dll": f"wintun/bin/{WINTUN_ARCHES[arch]}/wintun.dll",
        "WINTUN-LICENSE.txt": "wintun/LICENSE.txt",
    }
    with zipfile.ZipFile(download) as archive:
        for name, member in files.items():
            (work / name).write_bytes(archive.read(member))
    return {name: work / name for name in files}


def write_archive(path, name, files, executables, windows):
    if windows:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for filename, source in files.items():
                archive.write(source, f"{name}/{filename}")
        return
    with tarfile.open(path, "w:gz") as archive:
        for filename, source in files.items():
            entry = archive.gettarinfo(source, f"{name}/{filename}")
            entry.mode = 0o755 if filename in executables else 0o644
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = "root"
            with source.open("rb") as content:
                archive.addfile(entry, content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("os", choices=("linux", "windows"))
    parser.add_argument("arch", choices=WINTUN_ARCHES)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}", args.version):
        parser.error("version must be a safe archive name component")

    windows = args.os == "windows"
    suffix = ".exe" if windows else ""
    extension = "zip" if windows else "tar.gz"
    env = dict(os.environ, GOOS=args.os, GOARCH=args.arch, CGO_ENABLED="0")
    args.output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="acktier-package-", dir=args.output) as tmp:
        work = Path(tmp).resolve()
        binaries = work / "bin"
        binaries.mkdir()
        subprocess.run(
            [
                "go", "build", "-trimpath", "-buildvcs=false", "-o", str(binaries),
                "./cmd/acktier-server", "./cmd/acktierd", "./cmd/acktier",
            ],
            cwd=ROOT,
            env=env,
            check=True,
        )
        wintun = prepare_wintun(args.arch, work) if windows else {}
        published = []
        for role, programs in PROGRAMS.items():
            executables = {program + suffix: binaries / (program + suffix) for program in programs}
            files = dict(executables)
            files["INSTALL.md"] = ROOT / "docs" / "INSTALL.md"
            if role == "client":
                files.update(wintun)
            name = f"acktier-{role}-{args.version}-{args.os}-{args.arch}"
            archive = work / f"{name}.{extension}"
            write_archive(archive, name, files, executables, windows)
            published.append(archive)
        for archive in published:
            result = archive.replace(args.output / archive.name)
            print(result)


if __name__ == "__main__":
    main()
