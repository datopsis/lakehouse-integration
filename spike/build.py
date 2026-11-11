"""Throwaway acquisition/build harness; never edits an input repository."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / 'reports'
REPORTS.mkdir(exist_ok=True)
PINS = json.loads((ROOT / 'spike/pins.json').read_text())


def run(args, **kwargs):
    print('+', ' '.join(map(str, args)), flush=True)
    return subprocess.run(args, check=True, **kwargs)


def output(args):
    return subprocess.check_output(args, text=True).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(repo, revision):
    source = ROOT / '.sources' / repo
    source.mkdir(parents=True)
    run(['git', 'init', '-q', str(source)])
    run(['git', '-C', str(source), 'remote', 'add', 'origin', f'https://github.com/datopsis/{repo}.git'])
    fetched = subprocess.run(['git', '-C', str(source), 'fetch', '--depth=1', 'origin', revision])
    if fetched.returncode:
        assert repo == 'trino-ubi', 'Exact SHA fetch failed'
        run(['git', '-C', str(source), 'fetch', '--depth=1', 'origin', 'refs/pull/2/head'])
    run(['git', '-C', str(source), 'checkout', '--detach', 'FETCH_HEAD'])
    assert output(['git', '-C', str(source), 'rev-parse', 'HEAD']) == revision
    assert not output(['git', '-C', str(source), 'status', '--porcelain'])
    image = f'localhost/{repo}:spike'
    runtime = 'podman' if repo in ('lakekeeper-ubi', 'seaweedfs-ubi') else 'docker'
    env = dict(os.environ, CONTAINER_RUNTIME=runtime, IMAGE=image, RELEASE_REVISION=revision)
    if repo == 'postgresql-lakekeeper-ubi':
        command = ['bash', 'scripts/build-offline.sh']
        lock = source / 'artifacts/locks/amd64.json'
    elif repo == 'lakekeeper-ubi':
        command = ['bash', 'scripts/build.sh', '--arch', 'amd64', '--runtime', runtime, '--tag', image]
        lock = source / 'artifacts/lakekeeper.lock.json'
    elif repo == 'seaweedfs-ubi':
        # Extract (never run) the exact verifier image chosen by the owner's script.
        # Host execution avoids an unhardened helper container and leaves admission intact.
        ref = 'ghcr.io/sigstore/cosign/cosign@sha256:68839b7f13dac5a6744a5d8818e984dd39183374e37855c19e14d623d9bc9037'
        run(['docker', 'pull', ref])
        cid = output(['docker', 'create', ref])
        verifier = ROOT / '.sources/cosign'
        try:
            run(['docker', 'cp', f'{cid}:/ko-app/cosign', str(verifier)])
        finally:
            run(['docker', 'rm', cid])
        verifier.chmod(0o755)
        env['COSIGN'] = str(verifier)
        command = ['bash', 'scripts/build.sh', 'amd64']
        lock = source / 'artifacts/seaweedfs.lock.json'
    else:
        command = ['bash', 'scripts/build.sh', 'amd64']
        lock = source / 'artifacts/trino.lock.json'
    run(command, cwd=source, env=env)
    if runtime == 'podman':
        archive = ROOT / '.sources/transfer.tar'
        run(['podman', 'save', '--format', 'docker-archive', '-o', str(archive), image])
        run(['docker', 'load', '-i', str(archive)])
        archive.unlink()
    inspected = json.loads(output(['docker', 'image', 'inspect', image]))[0]
    assert inspected['Architecture'] == 'amd64'
    labels = inspected['Config'].get('Labels') or {}
    result = {'revision': revision, 'image_id': inspected['Id'], 'architecture': inspected['Architecture'],
              'lock_sha256': sha(lock), 'labels': labels, 'label_gaps': []}
    for key, expected in [('org.opencontainers.image.revision', revision),
                          ('io.datopsis.artifact-lock.sha256', sha(lock))]:
        if key not in labels:
            result['label_gaps'].append(key)
            print(f'LABEL GAP: {repo} does not emit {key}', flush=True)
        else:
            assert labels[key] == expected, (repo, key, labels[key], expected)
    # Explicit expected gaps, not a generic acceptance of missing provenance.
    expected_gaps = {'lakekeeper-ubi': ['org.opencontainers.image.revision', 'io.datopsis.artifact-lock.sha256'],
                     'seaweedfs-ubi': ['io.datopsis.artifact-lock.sha256']}.get(repo, [])
    assert result['label_gaps'] == expected_gaps
    if repo in ('lakekeeper-ubi', 'seaweedfs-ubi'):
        binary = 'lakekeeper' if repo == 'lakekeeper-ubi' else 'weed'
        cid = output(['docker', 'create', image])
        extracted = ROOT / '.sources' / f'{binary}-from-image'
        try:
            run(['docker', 'cp', f'{cid}:/usr/local/bin/{binary}', str(extracted)])
        finally:
            run(['docker', 'rm', cid])
        result['image_binary_sha256'] = sha(extracted)
        assert result['image_binary_sha256'] == json.loads(lock.read_text())['architectures']['amd64']['binary']['sha256']
        extracted.unlink()
        if repo == 'seaweedfs-ubi':
            assert labels['io.datopsis.seaweedfs.commit'] == json.loads(lock.read_text())['upstream']['releaseCommit']
    assert not output(['git', '-C', str(source), 'diff', 'HEAD'])
    return result


results = {}
for repo, revision in PINS.items():
    start = time.monotonic()
    try:
        results[repo] = dict(build(repo, revision), status='built-and-verified')
    except Exception as exc:
        results[repo] = {'status': 'failed', 'error': str(exc)}
        import traceback
        traceback.print_exc()
    results[repo]['seconds'] = round(time.monotonic() - start, 2)
    (REPORTS / 'builds.json').write_text(json.dumps(results, indent=2) + '\n')
assert all(r['status'] == 'built-and-verified' for r in results.values()), results
