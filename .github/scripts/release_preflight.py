"""Read release discovery files before the existing Pages TAR/approval gate.

This check does not alter a candidate, grant source clearance or publish it.
Custom Actions domains are configured in Pages settings; CNAME is optional.
"""

import argparse
import hashlib
import json
import re
import sys
import tarfile
import io
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor_xml"))
from defusedxml import ElementTree as ET

MAX_XML_BYTES = 10_000_000  # Conservative decimal Naver sitemap boundary.
SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"


def read_stable(file, pins):
    before = file.stat()
    raw = file.read_bytes()
    after = file.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ValueError("Release discovery input changed: " + str(file))
    pins[str(file)] = hashlib.sha256(raw).hexdigest()
    return raw


def route_file(out, url, hostname, exists=None):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != hostname
        or not parsed.path.startswith("/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Release URL must use the selected HTTPS origin: " + url)
    path = unquote(parsed.path)
    if path.startswith("//") or "\\" in path or any(c in path for c in "\x00\r\n"):
        raise ValueError("Unsafe release route")
    if any(part in {".", ".."} for part in path.split("/")):
        raise ValueError("Unsafe release route")
    relative = path.lstrip("/") + ("index.html" if path.endswith("/") else "")
    file = out / relative
    if not file.resolve().is_relative_to(out) or not (exists(file) if exists is not None else file.is_file()):
        raise ValueError("Release URL has no local file: " + url)
    return file, path


def check_robots(raw, hostname):
    agents, rules, groups, sitemaps = [], [], [], []
    for original in raw.decode("utf-8-sig").splitlines():
        line = original.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            raise ValueError("Malformed robots directive")
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if rules:
                groups.append((agents, rules))
                agents, rules = [], []
            agents.append(value.lower())
        elif key == "sitemap":
            sitemaps.append(value)
        elif key in {"allow", "disallow", "crawl-delay"}:
            if not agents:
                raise ValueError("Robots rule has no user-agent")
            rules.append((key, value))
    if agents:
        groups.append((agents, rules))
    wildcard = [rules for agents, rules in groups if "*" in agents]
    if not wildcard:
        raise ValueError("Missing general robots group")
    # A literal root-wide block left from preview must never reach release.
    # Bot-specific groups and narrower private-path rules remain untouched.
    if any(
        key == "disallow" and value in {"/", "/*", "/*$", "/$"}
        for rules in wildcard
        for key, value in rules
    ):
        raise ValueError("General robots group blocks the public root")
    if sitemaps != ["https://" + hostname + "/sitemap.xml"]:
        raise ValueError("Robots sitemap must match the selected site index")
    return {
        "groups": len(groups),
        "specific_groups": sum("*" not in a for a, _ in groups),
    }


def inspect(out, hostname, domain_config=None, *, _assets=None, _members=None):
    out = Path(out).resolve()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname):
        raise ValueError("Invalid selected hostname")
    pins = {}
    if domain_config is not None:
        config = json.loads(read_stable(Path(domain_config), pins))
        if (
            config.get("hostname") != hostname
            or config.get("value_source") != "user_explicit_choice"
        ):
            raise ValueError("Hostname differs from the user's domain selection")
    exists = lambda file: file.relative_to(out).as_posix() in _members if _members is not None else file.is_file()
    def read(file):
        if _assets is None:
            return read_stable(file, pins)
        name = file.relative_to(out).as_posix()
        raw = _assets[name]
        pins[name] = hashlib.sha256(raw).hexdigest()
        return raw
    cname = out / "CNAME"
    if exists(cname) and read(cname).decode("ascii").strip() != hostname:
        raise ValueError("Optional CNAME differs from the selected hostname")
    robots = check_robots(read(out / "robots.txt"), hostname)
    queue, seen, urls, counts = [out / "sitemap.xml"], set(), set(), Counter()
    while queue:
        file = queue.pop()
        if file in seen:
            raise ValueError("Repeated sitemap file or sitemap index cycle")
        seen.add(file)
        raw = read(file)
        if len(raw) > MAX_XML_BYTES:
            raise ValueError("Sitemap exceeds its uncompressed size limit")
        tree = ET.fromstring(raw, forbid_dtd=True)
        if tree.tag not in {
            "{" + SITEMAP_NS + "}urlset",
            "{" + SITEMAP_NS + "}sitemapindex",
        }:
            raise ValueError("Unknown sitemap XML root or namespace")
        indexed = tree.tag.endswith("}sitemapindex")
        child_tag = "{" + SITEMAP_NS + "}" + ("sitemap" if indexed else "url")
        children = list(tree)
        if (
            not children
            or len(children) > 50000
            or any(n.tag != child_tag for n in children)
        ):
            raise ValueError("Invalid sitemap member count or element")
        for node in children:
            locations = node.findall("{" + SITEMAP_NS + "}loc")
            if len(locations) != 1 or not locations[0].text:
                raise ValueError("Sitemap member requires one URL")
            target, path = route_file(out, locations[0].text, hostname, exists)
            if indexed:
                if target.suffix != ".xml":
                    raise ValueError("Sitemap index references a non-XML file")
                queue.append(target)
            else:
                if target.suffix != ".html" or path == "/404.html":
                    raise ValueError("Sitemap must reference public content HTML")
                if path in urls:
                    raise ValueError("Repeated sitemap content URL")
                urls.add(path)
                counts["sitemap_urls"] += 1
        counts["sitemap_files"] += 1
    raw = read(out / "feed.xml")
    feed = ET.fromstring(raw, forbid_dtd=True)
    channels = feed.findall("channel") if feed.tag == "rss" else []
    if (
        len(channels) != 1
        or channels[0].findtext("link") != "https://" + hostname + "/"
    ):
        raise ValueError("RSS channel must use the selected site")
    feed_paths = set()
    for item in channels[0].findall("item"):
        links = item.findall("link")
        if len(links) != 1 or not links[0].text:
            raise ValueError("RSS item requires one URL")
        target, path = route_file(out, links[0].text, hostname, exists)
        if target.suffix != ".html" or path == "/404.html" or path in feed_paths:
            raise ValueError("Invalid or repeated RSS content URL")
        if path not in urls:
            raise ValueError("RSS item is outside the public sitemap")
        feed_paths.add(path)
        counts["rss_items"] += 1
    for name, expected in pins.items():
        raw = _assets[name] if _assets is not None and name in _assets else Path(name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Release discovery input changed after validation")
    return {
        "state": "release_discovery_checked",
        "hostname": hostname,
        **counts,
        "robots": robots,
        "optional_cname_present": exists(cname),
        "input_sha256": pins,
        "source_clearance_granted": False,
        "public_ready": False,
        "publication_performed": False,
        "scope": "Discovery files only; existing HTML, alias, TAR, capacity and explicit approval gates remain mandatory",
    }



class _HashedInput:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.bytes = 0

    def read(self, size=-1):
        raw = self.stream.read(size)
        self.digest.update(raw)
        self.bytes += len(raw)
        return raw


def inspect_archive(archive, candidate_report, hostname, domain_config=None):
    """Validate discovery and exact TAR bytes; never extract or approve a TAR."""
    archive, candidate_report = Path(archive), Path(candidate_report)
    report_raw = candidate_report.read_bytes()
    expected = json.loads(report_raw)
    if (expected.get("state") != "private_technical_candidate_measured"
            or expected.get("public_ready") is not False
            or expected.get("publication_performed") is not False
            or not re.fullmatch("[a-f0-9]{64}", expected.get("tar_sha256", ""))):
        raise ValueError("Expected a complete private candidate report")
    before = archive.stat()
    members, names, assets = set(), set(), {}
    files = published = asset_bytes = 0
    with archive.open("rb") as stream:
        source = _HashedInput(stream)
        with tarfile.open(fileobj=source, mode="r|") as tf:
            for member in tf:
                name = member.name
                parts = name.rstrip("/").split("/")
                if (not name or name.startswith("/") or "\\" in name
                        or any(p in {"", ".", ".."} for p in parts)
                        or any(c in name for c in "\x00\r\n")):
                    raise ValueError("Unsafe TAR member")
                if name in names:
                    raise ValueError("Repeated TAR member")
                names.add(name)
                if len(names) > 5_000_000:
                    raise ValueError("TAR exceeds the explicit member-count budget")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError("TAR links and special files are forbidden")
                members.add(name)
                files += 1
                published += member.size
                if name in {"CNAME", "robots.txt", "feed.xml"} or name.endswith(".xml"):
                    asset_bytes += member.size
                    if member.size > MAX_XML_BYTES or asset_bytes > 256 * 1024 * 1024:
                        raise ValueError("Discovery data exceeds its explicit bounded memory budget")
                    assets[name] = tf.extractfile(member).read()
        while source.read(1024 * 1024):
            pass
    after = archive.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_ino):
        raise ValueError("TAR changed during validation")
    actual = {"tar_bytes": source.bytes, "tar_sha256": source.digest.hexdigest(),
              "files": files, "published_bytes": published}
    if any(expected.get(key) != value for key, value in actual.items()):
        raise ValueError("TAR differs from the measured candidate report")
    if candidate_report.read_bytes() != report_raw:
        raise ValueError("Candidate report changed during validation")
    result = inspect(Path("/"), hostname, domain_config, _assets=assets, _members=members)
    return {**result, **actual, "physical_tar_extracted": False,
            "candidate_report_sha256": hashlib.sha256(report_raw).hexdigest(),
            "discovery_bytes_retained": asset_bytes,
            "scope": "Exact measured TAR bytes and discovery files; source clearance and explicit publication approval remain separate"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--out", type=Path)
    inputs.add_argument("--archive-input", type=Path, help="Read an existing private TAR without extraction")
    parser.add_argument("--candidate-report", type=Path, help="Exact complete prepare_public_stream report for --archive-input")
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--domain-config", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.report is not None and args.report.resolve().is_relative_to(
        args.out.resolve()
    ):
        parser.error("Report must remain outside the candidate output")
    if args.archive_input is not None:
        if args.candidate_report is None:
            parser.error("--archive-input requires --candidate-report")
        result = inspect_archive(args.archive_input, args.candidate_report, args.hostname, args.domain_config)
    else:
        if args.candidate_report is not None:
            parser.error("--candidate-report requires --archive-input")
        result = inspect(args.out, args.hostname, args.domain_config)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.report is not None:
        with args.report.open("x", encoding="utf-8") as stream:
            stream.write(rendered)
    print(rendered)


if __name__ == "__main__":
    main()
