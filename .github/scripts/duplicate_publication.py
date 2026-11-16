"""Project reviewed alias metadata without mapping unrelated foreign URLs.

This module shares the site's source-bound duplicate policy implementation. It
never approves publication, changes indexing directives, writes source output,
or fetches a representative. External target readback remains a separate gate.
"""
import importlib.util
import json
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit

TEXT_SUFFIXES = {'.html', '.js', '.json', '.xml', '.txt', '.css', '.svg'}
_CORES = {}


def _core(root):
    root = Path(root).resolve()
    candidates = [root / 'seo_duplicate_policy.py', root / 'scripts/seo_duplicate_policy.py', Path(__file__).resolve().parents[2] / 'sites/seo-support/seo_duplicate_policy.py']
    file = next((file for file in candidates if file.is_file()), None)
    if file is None:
        raise ValueError('Missing shared duplicate policy implementation')
    stat = file.stat()
    key = (str(file), stat.st_mtime_ns, stat.st_size)
    if key not in _CORES:
        spec = importlib.util.spec_from_file_location('_pages_duplicate_policy', file)
        module = importlib.util.module_from_spec(spec)
        directory = str(file.parent)
        sys.path.insert(0, directory)
        try:
            spec.loader.exec_module(module)
        finally:
            sys.path.remove(directory)
        _CORES[key] = module
    return _CORES[key]


def _identity(value):
    if not isinstance(value, str):
        return None
    p = urlsplit(value)
    return p.scheme.lower(), p.netloc.lower(), unquote(p.path), p.query, p.fragment


def _page_identity(value):
    identity = _identity(value)
    return identity[:-1] if identity is not None else None


def policy_root_for(out, script):
    """Find release-local evidence or the actual workflow source checkout."""
    for root in [Path(out).resolve().parent, Path(script).resolve().parents[2]]:
        if (root / 'data/seo-duplicate-policy.json.gz').is_file():
            return root
    return None


class ReviewedAliases:
    def __init__(self, root, hostname):
        self.root = Path(root).resolve() if root is not None else None
        self.hostname = hostname
        self.core = _core(root) if root is not None else None

    def _entry(self, path):
        if self.core is None:
            return None
        plan = self.core.load_policy(self.root)
        row = plan['entries'].get(unquote(path))
        if row is None:
            return None
        own = plan['origins'][plan['site_id']]
        if urlsplit(own['public']).netloc != self.hostname:
            raise ValueError('Publication hostname differs from reviewed site policy')
        target = self.core.alias_target(self.root, path, own['public'])
        return plan, row, own, target

    def _source_matches(self, text, row, own):
        expected = row['source_content_sha256']
        if self.core.content_sha256(text) == expected:
            return True
        # Own-origin projection may change visible literal self URLs. Invert
        # only that reviewed mapping when comparing with the frozen source.
        restored = text.replace(own['public'] + '/', own['preview'] + '/')
        return self.core.content_sha256(restored) == expected

    def validate_public(self, text, path):
        entry = self._entry(path)
        if entry is None:
            return False
        plan, row, own, target = entry
        head = self.core.Head(text)
        if _identity(head.canonicals[0]) != _identity(target):
            return False
        if not self._source_matches(text, row, own):
            raise ValueError('Reviewed alias source content changed')
        og = [a.get('content') for tag, a, _, _ in head.tags if tag == 'meta' and a.get('property', a.get('name', '')).lower() == 'og:url']
        if len(og) != 1 or _identity(og[0]) != _identity(target):
            raise ValueError('Reviewed alias OG identity differs')
        known = {
            _page_identity(own['preview'] + path),
            _page_identity(own['public'] + path),
            _page_identity(plan['origins'][row['target_site']]['preview'] + row['target_path']),
            _page_identity(target),
        }
        primary = 0
        for left, right in head.scripts:
            try:
                data = json.loads(text[left:right])
            except ValueError as error:
                raise ValueError('Malformed reviewed alias page JSON') from error
            nodes = data if isinstance(data, list) else [data]
            for node in list(nodes):
                if isinstance(node, dict) and isinstance(node.get('@graph'), list):
                    nodes.extend(node['@graph'])
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                kinds = node.get('@type', [])
                kinds = [kinds] if isinstance(kinds, str) else kinds
                # Use the same actual primary-document type set as the shared
                # semantic reader, including Article-only existing guides.
                page_types = sys.modules[self.core._Current.__module__].PAGE_TYPES
                normalized = {
                    value.rsplit('/', 1)[-1] if value.startswith(('https://schema.org/', 'http://schema.org/')) else value
                    for value in kinds if isinstance(value, str)
                } if isinstance(kinds, list) else set()
                if not normalized & page_types:
                    continue
                identities = [_page_identity(node[key]) for key in ['url', '@id'] if isinstance(node.get(key), str)]
                if not any(value in known for value in identities):
                    continue
                if any(value != _page_identity(target) for value in identities):
                    raise ValueError('Reviewed alias primary page JSON differs')
                primary += 1
        if not primary:
            raise ValueError('Reviewed alias primary page JSON absent')
        return True


def project_html(raw, root, page_path, source_origin, selected_origin):
    """Return selected-domain bytes; preserve noindex and all physical inputs."""
    text = raw.decode('utf-8')
    selected = urlsplit(selected_origin)
    aliases = ReviewedAliases(root, selected.netloc)
    entry = aliases._entry(page_path)
    if entry is not None:
        _, _, own, _ = entry
        if source_origin != own['preview'] or selected_origin != own['public']:
            raise ValueError('Selected projection origins differ from reviewed policy')
        # This is the same head-only writer as native generation; its source
        # fingerprint, prior origin and source evidence checks stay active.
        text = aliases.core.apply_for_site(text, root, page_path, selected_origin)
    result = text.replace(source_origin + '/', selected_origin + '/')
    if entry is not None and not aliases.validate_public(result, page_path):
        raise ValueError('Selected alias projection differs from reviewed target')
    return result.encode('utf-8')


def project_bytes(raw, suffix, root, page_path, source_origin, selected_origin):
    """Preserve opaque formats; only HTML receives reviewed alias conversion."""
    suffix = suffix.lower()
    if suffix not in TEXT_SUFFIXES:
        return raw
    try:
        raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw
    if suffix == '.html':
        if page_path is None:
            raise ValueError('HTML projection requires its actual consumer path')
        return project_html(raw, root, page_path, source_origin, selected_origin)
    return raw.replace((source_origin + '/').encode(), (selected_origin + '/').encode())
