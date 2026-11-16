"""Measure and validate the exact, lossless TAR sent to GitHub Pages.

The supported 1 GB publication limit and the action's unofficial <10 GB TAR
ceiling are separate. Gzip bytes are a measured reference, never a TAR substitute.
"""
import argparse
from contextlib import ExitStack
import gzip
import importlib.util
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import stat
import tarfile
from urllib.parse import urlsplit

SUPPORTED_BYTES = 1_000_000_000
UNOFFICIAL_TAR_BYTES = 10_000_000_000  # Conservative decimal interpretation.


class _HeadComplete(Exception):
    pass


class Head(HTMLParser):
    """Read actual head tokens and stop at its real closing tag."""
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.noindex = False
        self.canonical = []
        self.started = self.inside = self.closed = self.ambiguous = False
        self.inert = 0
        try:
            self.feed(text)
            self.close()
        except _HeadComplete:
            pass
        self.ambiguous |= not self.started or not self.closed

    def handle_starttag(self, tag, attrs):
        if self.inert:
            if tag == 'template':
                self.inert += 1
            return
        if tag == 'head':
            if self.started:
                self.ambiguous = True
            self.started = self.inside = True
        if not self.inside:
            return
        if tag == 'body':
            self.ambiguous = True
        names = [key for key, _ in attrs]
        if len(names) != len(set(names)):
            self.ambiguous = True
        values = dict(attrs)
        if tag == 'template':
            self.inert = 1
            return
        if tag == 'meta' and (values.get('name') or '').lower() in {'robots', 'googlebot', 'bingbot', 'yeti'}:
            directives = set((values.get('content') or '').lower().replace(',', ' ').split())
            self.noindex |= bool(directives & {'noindex', 'none'})
        if tag == 'link' and 'canonical' in (values.get('rel') or '').lower().split():
            self.canonical.append(values.get('href') or '')

    def handle_endtag(self, tag):
        if self.inert:
            if tag == 'template':
                self.inert -= 1
            return
        if tag == 'head' and self.inside:
            self.closed = True
            self.inside = False
            raise _HeadComplete()


class Counter:
    def __init__(self, destination=None):
        self.bytes = 0
        self.sha256 = hashlib.sha256()
        self.destination = destination

    def write(self, data):
        self.bytes += len(data)
        self.sha256.update(data)
        if self.destination is not None:
            self.destination.write(data)
        return len(data)

    def flush(self):
        if self.destination is not None:
            self.destination.flush()


class TarCounter(Counter):
    def __init__(self, destination, compressor):
        super().__init__(destination)
        self.compressor = compressor

    def write(self, data):
        self.compressor.write(data)
        return super().write(data)


def valid_canonical(value, hostname):
    try:
        target = urlsplit(value)
        return target.scheme == 'https' and target.netloc.lower() == hostname.lower()
    except ValueError:
        return False


def capacity(published_bytes, tar_bytes):
    return {
        'published_bytes': published_bytes,
        'tar_bytes': tar_bytes,
        'github_pages_limit_bytes': SUPPORTED_BYTES,
        'within_supported_limit': published_bytes <= SUPPORTED_BYTES,
        'unofficial_tar_limit_exclusive_bytes': UNOFFICIAL_TAR_BYTES,
        'under_unofficial_tar_limit': tar_bytes < UNOFFICIAL_TAR_BYTES,
        'over_supported_size_is_guaranteed': False,
    }


def capacity_allowed(report, policy):
    if policy not in {'supported', 'precedent'}:
        raise ValueError('Unknown capacity policy')
    return report['under_unofficial_tar_limit'] and (
        report['within_supported_limit'] or policy == 'precedent'
    )


def entries(root):
    """Sorted, bounded per-directory traversal; reject links and special files."""
    def walk(directory):
        children = sorted(os.scandir(directory), key=lambda item: item.name)
        if not children and directory != root:
            yield directory, directory.lstat()
        for child in children:
            path = Path(child.path)
            if child.is_symlink():
                raise ValueError('Package contains a symlink: ' + str(path))
            if child.is_dir(follow_symlinks=False):
                yield from walk(path)
            elif child.is_file(follow_symlinks=False):
                yield path, child.stat(follow_symlinks=False)
            else:
                raise ValueError('Non-regular package entry: ' + str(path))
    yield from walk(root)


def inspect(folder, hostname, public=False, capacity_policy='supported', archive=None, policy_root=None):
    root = Path(folder).resolve()
    if not root.is_dir():
        raise ValueError('Missing output directory')
    if archive is not None and Path(archive).resolve().is_relative_to(root):
        raise ValueError('Archive must be outside the output directory')
    reviewed_foreign = 0
    alias_guard = None
    if public:
        helper_file = Path(__file__).with_name('duplicate_publication.py')
        spec = importlib.util.spec_from_file_location('pages_reviewed_alias_publication', helper_file)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        source_root = Path(policy_root) if policy_root is not None else helper.policy_root_for(root, __file__)
        alias_guard = helper.ReviewedAliases(source_root, hostname)
    count = size = html_count = empty_dirs = 0
    extensions = {}
    issues = []
    with ExitStack() as stack:
        destination = stack.enter_context(Path(archive).open('xb')) if archive is not None else None
        compressed = Counter()
        compressor = stack.enter_context(gzip.GzipFile(filename='', mode='wb', compresslevel=6, mtime=0, fileobj=compressed))
        stream = TarCounter(destination, compressor)
        tar = stack.enter_context(tarfile.open(fileobj=stream, mode='w|', format=tarfile.GNU_FORMAT))
        for path, metadata in entries(root):
            relative = path.relative_to(root).as_posix()
            info = tarfile.TarInfo(relative)
            info.uid = info.gid = info.mtime = 0
            if stat.S_ISDIR(metadata.st_mode):
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
                empty_dirs += 1
                continue
            count += 1
            size += metadata.st_size
            suffix = path.suffix or '(none)'
            extensions[suffix] = extensions.get(suffix, 0) + 1
            if public and path.suffix == '.html':
                html_count += 1
                if path.name != '404.html':
                    document = path.read_text()
                    head = Head(document)
                    accepted = len(head.canonical) == 1 and valid_canonical(head.canonical[0], hostname)
                    if not head.noindex and not head.ambiguous and len(head.canonical) == 1 and not accepted:
                        page_path = '/' + relative
                        if page_path.endswith('/index.html'):
                            page_path = page_path[:-len('index.html')]
                        accepted = alias_guard.validate_public(document, page_path)
                        reviewed_foreign += int(accepted)
                    if head.noindex or head.ambiguous or not accepted:
                        if len(issues) < 10:
                            issues.append(relative)
            info.size = metadata.st_size
            info.mode = 0o644
            # addfile copies file contents, never creates TAR hard-link entries.
            with path.open('rb') as source:
                tar.addfile(info, source)
            after = path.stat()
            if (metadata.st_size, metadata.st_mtime_ns, metadata.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError('Package changed during archiving: ' + relative)
    result = {
        **capacity(size, stream.bytes),
        'files': count,
        'preserved_empty_directories': empty_dirs,
        'file_extensions': extensions,
        'tar_sha256': stream.sha256.hexdigest(),
        'tar_gzip_bytes': compressed.bytes,
        'tar_gzip_sha256': compressed.sha256.hexdigest(),
        'gzip_purpose': 'reference only; upload-artifact v4 uses its own ZIP transport',
        'tar_format': 'GNU; files and empty directories; normalized metadata; no links',
        'capacity_policy': capacity_policy,
        'capacity_allowed': False,
        'html_public_checked': html_count,
        'reviewed_foreign_canonicals': reviewed_foreign,
        'foreign_target_scope': 'Source-bound declared targets only; actual external target readback and publication approval remain separate',
        'invalid_public_examples': issues,
    }
    result['capacity_allowed'] = capacity_allowed(result, capacity_policy)
    if public:
        if not result['capacity_allowed']:
            raise ValueError('Capacity policy blocks this archive: ' + json.dumps(result))
        if issues:
            raise ValueError('Invalid public HTML: ' + json.dumps(issues))
        for name in ['index.html', 'robots.txt', 'sitemap.xml', 'feed.xml']:
            if not (root / name).is_file():
                raise ValueError('Missing ' + name)
        receipt = json.loads((root.parent / '.publication-ready.json').read_text())
        if receipt.get('hostname') != hostname or any(receipt.get(key) is not True for key in ['public_approval', 'source_conditions_verified', 'artifact_reviewed']):
            raise ValueError('Missing explicit publication review')
        if receipt.get('tar_sha256') != result['tar_sha256']:
            raise ValueError('Reviewed archive hash does not match package')
        if receipt.get('capacity_policy') != capacity_policy:
            raise ValueError('Reviewed capacity policy does not match selected policy')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--public', action='store_true')
    parser.add_argument('--capacity-policy', choices=['supported', 'precedent'], default='supported')
    parser.add_argument('--policy-root', help='Source checkout containing reviewed data/seo-duplicate-policy.json.gz')
    parser.add_argument('--archive', help='Create this new TAR outside --out; refuse overwrite')
    parser.add_argument('--report', help='Write measured JSON report')
    args = parser.parse_args()
    result = inspect(args.out, args.hostname, args.public, args.capacity_policy, args.archive, args.policy_root)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.report:
        Path(args.report).write_text(rendered + '\n')
    print(rendered)
