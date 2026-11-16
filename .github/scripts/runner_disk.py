"""Preview fixed ephemeral SDK cleanup and check actual runner free disk."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

SDK_PATHS = ('/usr/share/dotnet', '/usr/local/lib/android', '/opt/ghc', '/opt/hostedtoolcache/CodeQL', '/usr/local/share/boost')
RESERVE_BYTES = 2 * 1024 ** 3


def cleanup(apply=False):
    plan = {'sdk_paths': list(SDK_PATHS), 'apply_requested': apply, 'performed': False}
    if not apply:
        return plan
    if platform.system() != 'Linux' or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.environ.get('PAGES_RUNNER_CLEANUP_APPROVED') != 'true':
        raise ValueError('Cleanup requires explicit approval on an ephemeral GitHub-hosted Linux runner')
    for value in SDK_PATHS:
        path = Path(value)
        if path.resolve() != path or path.is_symlink():
            raise ValueError('SDK path or ancestor is a symlink: ' + value)
    subprocess.run(['sudo', 'rm', '-rf', '--', *SDK_PATHS], check=True)
    plan['performed'] = True
    return plan


def check_space(workspace, temp, release_bytes=0, archive_bytes=10_000_000_000):
    if release_bytes < 0 or archive_bytes < 0:
        raise ValueError('Negative disk budget')
    workspace, temp = Path(workspace), Path(temp)
    shared = workspace.stat().st_dev == temp.stat().st_dev
    available_workspace = shutil.disk_usage(workspace).free
    available_temp = shutil.disk_usage(temp).free
    workspace_floor = release_bytes + RESERVE_BYTES + (archive_bytes if shared else 0)
    temp_floor = workspace_floor if shared else archive_bytes + RESERVE_BYTES
    result = {'workspace_free_bytes': available_workspace, 'temp_free_bytes': available_temp, 'same_filesystem': shared, 'release_file_budget_bytes': release_bytes, 'archive_budget_bytes': archive_bytes, 'reserve_bytes': RESERVE_BYTES, 'workspace_required_free_bytes': workspace_floor, 'temp_required_free_bytes': temp_floor, 'sufficient': available_workspace >= workspace_floor and available_temp >= temp_floor, 'scope': 'Runtime free-space floor; reserve is explicit, not a measured checkout or upload peak'}
    if not result['sufficient']:
        raise ValueError('Insufficient runner disk: ' + json.dumps(result))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply-reviewed-sdk-cleanup', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--workspace')
    parser.add_argument('--temp')
    parser.add_argument('--release-bytes', type=int, default=0)
    parser.add_argument('--archive-bytes', type=int, default=10_000_000_000)
    args = parser.parse_args()
    result = cleanup(args.apply_reviewed_sdk_cleanup)
    if args.check:
        if not args.workspace or not args.temp:
            parser.error('--check requires --workspace and --temp')
        result['disk'] = check_space(args.workspace, args.temp, args.release_bytes, args.archive_bytes)
    print(json.dumps(result, indent=2))
