"""Transfer a reviewed private candidate TAR without source export or rebuilding.

Packing grants no approval. The workflow receiver requires the existing explicit
publication receipt and the exact complete producer/source-audit evidence.
"""

import argparse
import gzip
import hashlib
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
import pages_gate
import release_preflight

PART_BYTES = 64 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(file):
    return json.loads(Path(file).read_bytes())


def evidence(report, audit_raw):
    audit = json.loads(audit_raw)
    if (
        report.get("state") != "private_technical_candidate_measured"
        or report.get("source_output_unchanged") is not True
        or report.get("public_ready") is not False
        or report.get("publication_performed") is not False
        or not re.fullmatch("[a-f0-9]{64}", report.get("tar_sha256", ""))
    ):
        raise ValueError("Incomplete or approved-looking technical producer report")
    count = report.get("source_manifest_html")
    if (
        type(count) is not int
        or count < 1
        or audit.get("site") != report.get("site")
        or audit.get("manifest_pages") != count
        or audit.get("read") != count
        or audit.get("issues") != {}
        or audit.get("limit") is not None
        or not re.fullmatch("[a-f0-9]{64}", audit.get("manifest_sha256", ""))
        or sha(audit_raw) not in report.get("pins", {}).values()
        or audit["manifest_sha256"] not in report.get("pins", {}).values()
    ):
        raise ValueError(
            "Source audit is incomplete or not bound to the producer report"
        )
    for key in ["tar_bytes", "files", "published_bytes"]:
        if type(report.get(key)) is not int or report[key] < 1:
            raise ValueError("Missing exact candidate counts")


class _SplitOutput:
    def __init__(self, folder):
        self.folder, self.part, self.rows = folder, None, []
        self.size, self.digest = 0, None

    def _close(self):
        if self.part is not None:
            self.part.close()
            self.rows.append(
                {
                    "name": self.part.name.split("/")[-1],
                    "bytes": self.size,
                    "sha256": self.digest.hexdigest(),
                }
            )
            self.part = None

    def write(self, raw):
        length = len(raw)
        while raw:
            if self.part is None:
                self.part = (
                    self.folder / ("archive.tar.gz.%05d.part" % len(self.rows))
                ).open("xb")
                self.size, self.digest = 0, hashlib.sha256()
            piece = raw[: PART_BYTES - self.size]
            self.part.write(piece)
            self.digest.update(piece)
            self.size += len(piece)
            raw = raw[len(piece) :]
            if self.size == PART_BYTES:
                self._close()
        return length

    def flush(self):
        if self.part is not None:
            self.part.flush()


def pack(archive, report_file, audit_file, folder, hostname, receipt_file=None):
    archive, report_file, audit_file, folder = map(
        Path, [archive, report_file, audit_file, folder]
    )
    report_raw, audit_raw = report_file.read_bytes(), audit_file.read_bytes()
    report = json.loads(report_raw)
    evidence(report, audit_raw)
    # Real TAR readback happens before creating a transport bundle.
    release_preflight.inspect_archive(archive, report_file, hostname)
    folder.mkdir(parents=True, exist_ok=False)
    sink = _SplitOutput(folder)
    digest, size = hashlib.sha256(), 0
    try:
        with gzip.GzipFile(
            filename="", mode="wb", mtime=0, compresslevel=6, fileobj=sink
        ) as compressor:
            with archive.open("rb") as stream:
                while raw := stream.read(1024 * 1024):
                    digest.update(raw)
                    size += len(raw)
                    compressor.write(raw)
    finally:
        sink._close()
    if size != report["tar_bytes"] or digest.hexdigest() != report["tar_sha256"]:
        raise ValueError("Candidate TAR changed during transport packing")
    if report_file.read_bytes() != report_raw or audit_file.read_bytes() != audit_raw:
        raise ValueError("Candidate evidence changed during transport packing")
    (folder / "candidate-report.json").write_bytes(report_raw)
    (folder / "source-audit.json").write_bytes(audit_raw)
    receipt_sha = None
    if receipt_file is not None:
        raw = Path(receipt_file).read_bytes()
        (folder / ".publication-ready.json").write_bytes(raw)
        receipt_sha = sha(raw)
    manifest = {
        "version": 1,
        "hostname": hostname,
        "site": report["site"],
        "candidate_report_sha256": sha(report_raw),
        "source_audit_sha256": sha(audit_raw),
        "publication_receipt_sha256": receipt_sha,
        "parts": sink.rows,
        "part_max_bytes": PART_BYTES,
        "tar_sha256": report["tar_sha256"],
        "tar_bytes": size,
        "approval_created": False,
        "publication_performed": False,
    }
    with (folder / "transfer-manifest.json").open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return manifest


class _PartsInput:
    def __init__(self, folder, rows):
        self.folder, self.rows, self.index = folder, rows, 0
        self.stream = None

    def read(self, size=-1):
        if size < 0:
            raise ValueError("Unbounded compressed reads are forbidden")
        pieces = []
        while size:
            if self.stream is None:
                if self.index == len(self.rows):
                    break
                row = self.rows[self.index]
                file = self.folder / row["name"]
                if file.is_symlink() or file.stat().st_size != row["bytes"]:
                    raise ValueError("Changed or linked transfer part")
                self.stream = file.open("rb")
                self.digest = hashlib.sha256()
                self.size = 0
            raw = self.stream.read(size)
            if not raw:
                self.stream.close()
                self.stream = None
                row = self.rows[self.index]
                if (
                    self.size != row["bytes"]
                    or self.digest.hexdigest() != row["sha256"]
                ):
                    raise ValueError("Transfer part SHA changed")
                self.index += 1
                continue
            self.digest.update(raw)
            self.size += len(raw)
            size -= len(raw)
            pieces.append(raw)
        return b"".join(pieces)

    def close(self):
        if self.stream is not None:
            self.stream.close()


def receive(folder, hostname, archive, capacity_policy="supported", domain_config=None):
    folder, archive = Path(folder).resolve(), Path(archive).resolve()
    if archive.is_relative_to(folder):
        raise ValueError("Restored TAR must remain outside the transfer bundle")
    manifest_raw = (folder / "transfer-manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    report_raw = (folder / "candidate-report.json").read_bytes()
    audit_raw = (folder / "source-audit.json").read_bytes()
    if (
        manifest.get("version") != 1
        or manifest.get("hostname") != hostname
        or manifest.get("candidate_report_sha256") != sha(report_raw)
        or manifest.get("source_audit_sha256") != sha(audit_raw)
    ):
        raise ValueError("Transfer manifest differs from candidate evidence")
    report = json.loads(report_raw)
    evidence(report, audit_raw)
    if any(
        manifest.get(key) != report[key] for key in ["site", "tar_sha256", "tar_bytes"]
    ):
        raise ValueError("Transfer TAR identity differs from producer")
    receipt_raw = (folder / ".publication-ready.json").read_bytes()
    receipt = json.loads(receipt_raw)
    if (
        manifest.get("publication_receipt_sha256") != sha(receipt_raw)
        or receipt.get("hostname") != hostname
        or any(
            receipt.get(k) is not True
            for k in [
                "public_approval",
                "source_conditions_verified",
                "artifact_reviewed",
            ]
        )
        or receipt.get("tar_sha256") != report["tar_sha256"]
        or receipt.get("capacity_policy") != capacity_policy
    ):
        raise ValueError("Missing exact explicit publication review")
    capacity = pages_gate.capacity(report["published_bytes"], report["tar_bytes"])
    if not pages_gate.capacity_allowed(capacity, capacity_policy):
        raise ValueError("Capacity policy blocks this prepared TAR")
    rows = manifest.get("parts")
    if not isinstance(rows, list) or not rows:
        raise ValueError("Missing transfer parts")
    for index, row in enumerate(rows):
        if (
            row.get("name") != "archive.tar.gz.%05d.part" % index
            or type(row.get("bytes")) is not int
            or not 0 < row["bytes"] <= PART_BYTES
            or not re.fullmatch("[a-f0-9]{64}", row.get("sha256", ""))
        ):
            raise ValueError("Unbounded or unordered transfer parts")
    source = _PartsInput(folder, rows)
    try:
        with archive.open("xb") as target, gzip.GzipFile(
            fileobj=source, mode="rb"
        ) as compressor:
            size = 0
            while raw := compressor.read(1024 * 1024):
                size += len(raw)
                if size > report["tar_bytes"]:
                    raise ValueError("Expanded TAR exceeds the exact reviewed bytes")
                target.write(raw)
            # Exhaust every compressed byte and verify the final part too.
            if source.read(1):
                raise ValueError("Unconsumed transfer bytes")
    finally:
        source.close()
    checked = release_preflight.inspect_archive(
        archive, folder / "candidate-report.json", hostname, domain_config
    )
    if (folder / "transfer-manifest.json").read_bytes() != manifest_raw:
        raise ValueError("Transfer manifest changed during receiving")
    return {
        **checked,
        **capacity,
        "capacity_policy": capacity_policy,
        "capacity_allowed": True,
        "explicit_publication_receipt_checked": True,
        "receipt_sha256": sha(receipt_raw),
        "source_rebuilt": False,
        "scope": "Exact completed producer TAR plus bound complete audit and existing explicit review; no source export, V5 rerun or raw-out repackaging",
    }



def transfer_budget(folder, hostname):
    folder = Path(folder)
    manifest_raw = (folder / "transfer-manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    closed = read(folder / "readback.json")
    if (manifest.get("hostname") != hostname
            or closed.get("state") != "private_transport_bundle_verified"
            or closed.get("actual_parts_readback") is not True
            or closed.get("publication_performed") is not False
            or closed.get("transfer_manifest_sha256") != sha(manifest_raw)
            or closed.get("hostname") != hostname or closed.get("site") != manifest.get("site")
            or closed.get("tar_sha256") != manifest.get("tar_sha256")
            or closed.get("tar_bytes") != manifest.get("tar_bytes")):
        raise ValueError("Disk budget requires a closed exact private bundle")
    report_raw = (folder / "candidate-report.json").read_bytes()
    audit_raw = (folder / "source-audit.json").read_bytes()
    if sha(report_raw) != manifest["candidate_report_sha256"] or sha(audit_raw) != manifest["source_audit_sha256"]:
        raise ValueError("Closed candidate evidence changed")
    evidence(json.loads(report_raw), audit_raw)
    parts = {row["name"]: row for row in manifest["parts"]}
    allowed = set(parts) | {"transfer-manifest.json", "candidate-report.json", "source-audit.json",
                           ".publication-ready.json", "readback.json", "tar-css-readback.json.gz",
                           "tar-binary-readback.json.gz"}
    files = {}
    for file in folder.iterdir():
        if file.name not in allowed or not file.is_file() or file.is_symlink():
            raise ValueError("Unregistered source material in the transfer folder")
        raw = file.read_bytes()
        if len(raw) >= 100 * 1024 * 1024:
            raise ValueError("Transfer file reaches GitHub's 100 MiB boundary")
        row = {"bytes": len(raw), "sha256": sha(raw)}
        if file.name in parts and any(row[k] != parts[file.name][k] for k in row):
            raise ValueError("Closed transfer part changed")
        files[file.name] = row
    if not set(parts) <= set(files):
        raise ValueError("Missing transfer parts")
    size = sum(row["bytes"] for row in files.values())
    return {"version": 1, "site": manifest["site"], "hostname": hostname,
            "transfer_manifest_sha256": sha(manifest_raw), "bundle_files": files,
            "checkout_bytes": size, "git_object_budget_bytes": size + 16 * 1024 * 1024,
            "release_file_budget_bytes": 2 * size + 16 * 1024 * 1024,
            "tar_bytes": manifest["tar_bytes"], "tar_sha256": manifest["tar_sha256"],
            "approval_created": False, "publication_performed": False,
            "scope": "Measured compressed working tree plus a separate Git object budget; explicit runtime floor, not a measured clone/upload peak"}


def check_transfer_budget(folder, hostname, budget_file, release_root=None):
    budget = read(budget_file)
    actual = transfer_budget(folder, hostname)
    if budget != actual:
        raise ValueError("Release checkout differs from the source-pinned transfer budget")
    if release_root is not None:
        root = Path(release_root).resolve()
        if Path(folder).resolve() != root / "prepared":
            raise ValueError("Prepared bundle must be the release checkout's prepared directory")
        if {p.name for p in root.iterdir()} - {".git", "prepared"}:
            raise ValueError("Prepared release branch contains unexpected source material")
    return budget


def check_prepared_disk(budget_file, hostname, workspace, temp):
    import runner_disk
    budget = read(budget_file)
    if (budget.get("version") != 1 or budget.get("hostname") != hostname
            or type(budget.get("checkout_bytes")) is not int
            or budget["checkout_bytes"] < 1
            or type(budget.get("tar_bytes")) is not int
            or not 0 < budget["tar_bytes"] < 10_000_000_000
            or budget.get("approval_created") is not False
            or budget.get("publication_performed") is not False
            or budget.get("release_file_budget_bytes") != 2 * budget["checkout_bytes"] + 16 * 1024 * 1024
            or not re.fullmatch("[a-f0-9]{64}", budget.get("transfer_manifest_sha256", ""))):
        raise ValueError("Missing or malformed measured transfer disk budget")
    return runner_disk.check_space(workspace, temp, budget["release_file_budget_bytes"], budget["tar_bytes"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    packing = commands.add_parser(
        "pack", help="Prepare a new private transport bundle; never approve it"
    )
    for flag in ["archive", "candidate-report", "source-audit", "bundle"]:
        packing.add_argument("--" + flag, type=Path, required=True)
    packing.add_argument("--hostname", required=True)
    packing.add_argument("--publication-receipt", type=Path)
    receiving = commands.add_parser(
        "receive",
        help="Restore and validate the already prepared TAR for the manual workflow",
    )
    for flag in ["bundle", "archive", "report"]:
        receiving.add_argument("--" + flag, type=Path, required=True)
    receiving.add_argument("--hostname", required=True)
    receiving.add_argument("--domain-config", type=Path)
    receiving.add_argument(
        "--capacity-policy", choices=["supported", "precedent"], default="supported"
    )
    receiving.add_argument("--transfer-budget", type=Path)
    receiving.add_argument("--release-root", type=Path)
    measuring = commands.add_parser("budget", help="Measure a closed private bundle; never approve it")
    measuring.add_argument("--bundle", type=Path, required=True)
    measuring.add_argument("--hostname", required=True)
    measuring.add_argument("--report", type=Path, required=True)
    disk = commands.add_parser("check-disk", help="Check the measured prepared checkout and exact TAR disk floor")
    disk.add_argument("--budget", type=Path, required=True)
    disk.add_argument("--hostname", required=True)
    disk.add_argument("--workspace", type=Path, required=True)
    disk.add_argument("--temp", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "pack":
        result = pack(
            args.archive,
            args.candidate_report,
            args.source_audit,
            args.bundle,
            args.hostname,
            args.publication_receipt,
        )
    elif args.command == "check-disk":
        result = check_prepared_disk(args.budget, args.hostname, args.workspace, args.temp)
    elif args.command == "budget":
        if args.report.exists() or args.report.resolve().is_relative_to(args.bundle.resolve()):
            parser.error("Budget must be a new file outside the transfer bundle")
        result = transfer_budget(args.bundle, args.hostname)
        with args.report.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    else:
        if bool(args.transfer_budget) != bool(args.release_root):
            parser.error("Transfer budget and release root must be provided together")
        if args.transfer_budget:
            check_transfer_budget(args.bundle, args.hostname, args.transfer_budget, args.release_root)
        if args.report.exists() or args.report.resolve().is_relative_to(
            args.bundle.resolve()
        ):
            parser.error("Report must be a new file outside the transfer bundle")
        result = receive(
            args.bundle,
            args.hostname,
            args.archive,
            args.capacity_policy,
            args.domain_config,
        )
        with args.report.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
