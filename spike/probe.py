"""Feasibility evidence, not a production integration-test framework."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / '.runtime'
REPORTS = ROOT / 'reports'
DC = ['docker', 'compose', '-f', str(ROOT / 'spike/compose.yaml')]
RESULTS = {}
START = time.monotonic()


def record(name, value):
    RESULTS[name] = value
    RESULTS['elapsed_seconds'] = round(time.monotonic() - START, 2)
    (REPORTS / 'results.json').write_text(json.dumps(RESULTS, indent=2, default=str) + '\n')
    print(name + ': ' + json.dumps(value, default=str), flush=True)


def compose(*args, **kwargs):
    return subprocess.run(DC + list(args), check=True, **kwargs)


def cid(service):
    return subprocess.check_output(DC + ['ps', '-q', service], text=True).strip()


def http(method, url, data=None, headers=None):
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        headers = {'Content-Type': 'application/json', **(headers or {})}
    elif isinstance(data, str):
        data = data.encode()
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        try:
            body = json.loads(body)
        except ValueError:
            pass
        return exc.code, body


def wait(label, fn, seconds=120):
    deadline = time.monotonic() + seconds
    error = None
    while time.monotonic() < deadline:
        try:
            if fn():
                return
        except Exception as exc:
            error = str(exc)
        time.sleep(2)
    raise RuntimeError(f'{label} not ready after {seconds}s: {error}')


def hosts():
    # Linux runner can reach the internal bridge. Nothing is port-published.
    entries = []
    for service in ('s3', 'catalog', 'trino'):
        if not cid(service):
            continue
        item = json.loads(subprocess.check_output(['docker', 'inspect', cid(service)]))[0]
        address = next(iter(item['NetworkSettings']['Networks'].values()))['IPAddress']
        entries.append(f'{address} {service}\n')
    old = Path('/etc/hosts').read_text().split('# feasibility-start')[0]
    subprocess.run(['sudo', 'tee', '/etc/hosts'], input=old + '# feasibility-start\n' + ''.join(entries), text=True, stdout=subprocess.DEVNULL, check=True)


def sql(query):
    status, page = http('POST', 'http://trino:8080/v1/statement', query, {'X-Trino-User': 'spike'})
    assert status == 200, (status, page)
    rows = []
    deadline = time.monotonic() + 180
    while True:
        if 'error' in page:
            raise RuntimeError(json.dumps(page['error']))
        rows.extend(page.get('data', []))
        if 'nextUri' not in page:
            break
        assert time.monotonic() < deadline, 'SQL timeout'
        time.sleep(0.1)
        status, page = http('GET', page['nextUri'])
        assert status == 200, (status, page)
    print('SQL', query, '=>', rows, flush=True)
    return rows


def check_hardening():
    report = {}
    for service in ('postgres', 'master', 'volume', 'filer', 's3', 'catalog', 'trino'):
        item = json.loads(subprocess.check_output(['docker', 'inspect', cid(service)]))[0]
        config = item['HostConfig']
        assert item['Config']['User'].split(':')[0] not in ('0', 'root', '')
        assert config['ReadonlyRootfs'] and 'ALL' in config['CapDrop']
        assert 'no-new-privileges:true' in config['SecurityOpt']
        assert not config['PortBindings']
        status = subprocess.check_output(DC + ['exec', '-T', service, 'cat', '/proc/1/status'], text=True)
        fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
        assert set(fields['Uid'].split()) != {'0'}
        assert fields['CapEff'].strip() == '0000000000000000'
        assert fields['NoNewPrivs'].strip() == '1'
        report[service] = {key: fields[key].strip() for key in ('Uid', 'CapEff', 'NoNewPrivs')}
    net = json.loads(subprocess.check_output(['docker', 'network', 'inspect', 'feasibility_private']))[0]
    assert net['Internal']
    record('hardening', report)


def rest_catalog(delegation='client-managed', with_credentials=True):
    from pyiceberg.catalog.rest import RestCatalog
    properties = {
        'uri': 'http://catalog:8181/catalog', 'warehouse': 'qualification',
        's3.endpoint': 'http://s3:8333', 's3.region': 'local', 's3.path-style-access': 'true',
    }
    if with_credentials:
        properties.update({'s3.access-key-id': CREDS['access'], 's3.secret-access-key': CREDS['secret']})
    if delegation:
        properties['header.X-Iceberg-Access-Delegation'] = delegation
    return RestCatalog('qualification', **properties)


def probe(name, fn):
    start = time.monotonic()
    try:
        value = fn()
        record(name, {'status': 'pass', 'seconds': round(time.monotonic() - start, 2), 'value': value})
    except Exception as exc:
        record(name, {'status': 'fail', 'seconds': round(time.monotonic() - start, 2), 'error': str(exc)})
        traceback.print_exc()


CREDS = {key: secrets.token_hex(24) for key in ('admin', 'postgres', 'encryption', 'access', 'secret')}

def prepare():
    RUNTIME.mkdir(mode=0o755)
    secret_dir = RUNTIME / 'secrets'
    secret_dir.mkdir(mode=0o755)
    for key in CREDS.values():
        print(f'::add-mask::{key}', flush=True)
    (RUNTIME / 'credentials.json').write_text(json.dumps(CREDS))
    (RUNTIME / 'credentials.json').chmod(0o600)
    (secret_dir / 'postgres-password').write_text(CREDS['admin'])
    (secret_dir / 'lakekeeper-password').write_text(CREDS['postgres'])
    (secret_dir / 's3.json').write_text(json.dumps({'identities': [{
        'name': 'lakehouse', 'credentials': [{'accessKey': CREDS['access'], 'secretKey': CREDS['secret']}],
        'actions': ['Admin', 'Read', 'Write', 'List', 'Tagging'],
    }]}))
    for path in secret_dir.iterdir():
        subprocess.run(['sudo', 'chown', 'root:root', str(path)], check=True)
        subprocess.run(['sudo', 'chmod', '0440', str(path)], check=True)
    (RUNTIME / 'lakekeeper.env').write_text(
        f'LAKEKEEPER__PG_DATABASE_URL_WRITE=postgres://lakekeeper:{CREDS["postgres"]}@postgres:5432/lakekeeper\n'
        f'LAKEKEEPER__PG_ENCRYPTION_KEY={CREDS["encryption"]}\n')
    (RUNTIME / 'trino.env').write_text(f'S3_ACCESS_KEY_ID={CREDS["access"]}\nS3_SECRET_ACCESS_KEY={CREDS["secret"]}\n')
    for name in ('lakekeeper.env', 'trino.env'):
        (RUNTIME / name).chmod(0o600)
    shutil.copytree(ROOT / 'spike/trino', RUNTIME / 'trino')
    # An independent second Trino catalog requests vending; same endpoint and static creds.
    content = (RUNTIME / 'trino/catalog/iceberg.properties').read_text()
    (RUNTIME / 'trino/catalog/vending.properties').write_text(content.replace('vended-credentials-enabled=false', 'vended-credentials-enabled=true'))


def start():
    compose('up', '-d', 'postgres', 'master', 'volume', 'filer', 's3')
    wait('PostgreSQL TCP', lambda: subprocess.run(DC + ['exec', '-T', 'postgres', 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'lakekeeper'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
    with (ROOT / 'spike/postgres-init.sql').open() as source:
        compose('exec', '-T', 'postgres', 'psql', '-X', '-h', '/tmp', '-U', 'postgres', '-d', 'lakekeeper', stdin=source)
    compose('run', '--rm', '--no-deps', 'migrate')
    compose('up', '-d', 'catalog')
    hosts()
    wait('Lakekeeper', lambda: subprocess.run(DC + ['exec', '-T', 'catalog', 'lakekeeper', 'healthcheck', '-s'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
    # The hardened gateway disables auto-create. Register the bucket before Lakekeeper validates it.
    def bucket():
        result = subprocess.run(DC + ['exec', '-T', 'master', 'weed', 'shell', '-master=master:9333', '-filer=filer:8888'], input='s3.bucket.create -name warehouse\ns3.bucket.list\n', text=True, capture_output=True)
        return 'warehouse' in result.stdout
    wait('registered bucket', bucket)
    status, _ = http('POST', 'http://catalog:8181/management/v1/bootstrap', {'accept-terms-of-use': True})
    assert status == 204, status
    profile = {'type': 's3', 'bucket': 'warehouse', 'region': 'local', 'sts-enabled': False, 'flavor': 's3-compat', 'endpoint': 'http://s3:8333', 'path-style-access': True}
    warehouse = {'warehouse-name': 'qualification', 'storage-profile': profile,
                 'storage-credential': {'type': 's3', 'credential-type': 'access-key', 'access-key-id': CREDS['access'], 'secret-access-key': CREDS['secret']}}
    bad = json.loads(json.dumps(warehouse))
    bad['warehouse-name'] = 'rejected'
    bad['storage-credential']['secret-access-key'] = secrets.token_hex(24)
    status, body = http('POST', 'http://catalog:8181/management/v1/warehouse', bad)
    assert 400 <= status < 500, (status, body)
    record('wrong_s3_secret', {'status': status, 'body': body})
    status, body = http('POST', 'http://catalog:8181/management/v1/warehouse', warehouse)
    assert status in (200, 201), (status, body)
    record('warehouse', {'profile': profile, 'response': body})
    compose('up', '-d', 'trino')
    hosts()
    wait('Trino', lambda: http('GET', 'http://trino:8080/v1/info')[1].get('starting') is False, 180)
    check_hardening()
    return body['warehouse-id']


def trino_write():
    sql('CREATE SCHEMA iceberg.spike')
    sql("CREATE TABLE iceberg.spike.from_trino (id BIGINT, label VARCHAR) WITH (format='PARQUET', format_version=2)")
    sql("INSERT INTO iceberg.spike.from_trino VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma')")
    assert sql('SELECT * FROM iceberg.spike.from_trino ORDER BY id') == [[1, 'alpha'], [2, 'beta'], [3, 'gamma']]
    return 'CREATE TABLE / INSERT / SELECT asserted'


def mutate():
    sql("UPDATE iceberg.spike.from_trino SET label='updated' WHERE id=2")
    sql('DELETE FROM iceberg.spike.from_trino WHERE id=3')
    assert sql('SELECT * FROM iceberg.spike.from_trino ORDER BY id') == [[1, 'alpha'], [2, 'updated']]
    snapshots = sql('SELECT snapshot_id, operation FROM iceberg.spike."from_trino$snapshots" ORDER BY committed_at')
    history = sql('SELECT snapshot_id, is_current_ancestor FROM iceberg.spike."from_trino$history" ORDER BY made_current_at')
    assert len(snapshots) >= 3 and len(history) >= 3
    return {'snapshots': snapshots, 'history': history}


def py_read(expected=None, delegation='client-managed', with_credentials=True):
    table = rest_catalog(delegation, with_credentials).load_table('spike.from_trino')
    rows = table.scan().to_arrow().sort_by('id').to_pylist()
    expected = expected or [{'id': 1, 'label': 'alpha'}, {'id': 2, 'label': 'updated'}]
    assert rows == expected, rows
    paths = [task.file.file_path for task in table.scan().plan_files()]
    assert paths and all(p.startswith('s3://warehouse/') for p in paths)
    return {'rows': rows, 'files': paths, 'file_io': type(table.io).__module__ + '.' + type(table.io).__name__,
            'signer': table.io.properties.get('s3.signer'), 'delegation': delegation, 'client_s3_credentials': with_credentials}


def py_write():
    import pyarrow as pa
    data = pa.table({'id': [10, 20], 'label': ['py-alpha', 'py-beta']})
    table = rest_catalog().create_table('spike.from_python', schema=data.schema, properties={'format-version': '2'})
    table.append(data)
    assert sql('SELECT * FROM iceberg.spike.from_python ORDER BY id') == [[10, 'py-alpha'], [20, 'py-beta']]
    return {'metadata': table.metadata_location, 'rows': 2}


def modes(warehouse_id):
    url = f'http://catalog:8181/catalog/v1/{warehouse_id}/namespaces/spike/tables/from_trino'
    results = {}
    for mode in ('none', 'vended-credentials', 'remote-signing', 'client-managed'):
        headers = {} if mode == 'none' else {'X-Iceberg-Access-Delegation': mode}
        status, body = http('GET', url, headers=headers)
        # Do not retain credentials if an implementation unexpectedly vends them.
        config = body.get('config', {}) if isinstance(body, dict) else {}
        results[mode] = {'status': status, 'config_keys': sorted(config),
                         'remote_signing_enabled': config.get('s3.remote-signing-enabled'),
                         'error': body.get('error') if isinstance(body, dict) else body}
    try:
        results['trino_vending_true'] = sql('SELECT * FROM vending.spike.from_trino ORDER BY id')
    except Exception as exc:
        results['trino_vending_true'] = {'error': str(exc)}
    record('delegation_modes', results)


def restart():
    old = {service: cid(service) for service in ('postgres', 'master', 'volume', 'filer', 's3', 'catalog', 'trino')}
    # Down removes every container and network, retaining only named volumes and secrets.
    logs = subprocess.run(DC + ['logs', '--no-color'], text=True, capture_output=True, check=True)
    (REPORTS / 'services-before-recreation.log').write_text(logs.stdout + logs.stderr)
    compose('down', '--timeout', '30')
    compose('up', '-d')
    hosts()
    wait('catalog after restart', lambda: subprocess.run(DC + ['exec', '-T', 'catalog', 'lakekeeper', 'healthcheck', '-s'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
    wait('Trino after restart', lambda: http('GET', 'http://trino:8080/v1/info')[1].get('starting') is False, 180)
    assert all(cid(service) != previous for service, previous in old.items())
    # A fresh independent reader matches the owner's storage fixture and avoids
    # carrying S3/signing/DNS clients across network/container replacement.
    checked = subprocess.run([sys.executable, __file__, 'verify-restart'], text=True, capture_output=True)
    print(checked.stdout, flush=True)
    print(checked.stderr, file=sys.stderr, flush=True)
    checked.check_returncode()
    check_hardening()
    return json.loads(next(line.removeprefix('RESTART_RESULT=') for line in checked.stdout.splitlines() if line.startswith('RESTART_RESULT=')))


def verify_restart():
    assert sql('SELECT * FROM iceberg.spike.from_trino ORDER BY id') == [[1, 'alpha'], [2, 'updated']]
    assert sql('SELECT * FROM iceberg.spike.from_python ORDER BY id') == [[10, 'py-alpha'], [20, 'py-beta']]
    py_read()
    assert rest_catalog().load_table('spike.from_python').scan().to_arrow().num_rows == 2
    sql("INSERT INTO iceberg.spike.from_python VALUES (30, 'after-restart')")
    assert rest_catalog().load_table('spike.from_python').scan().to_arrow().sort_by('id').to_pylist() == [
        {'id': 10, 'label': 'py-alpha'}, {'id': 20, 'label': 'py-beta'}, {'id': 30, 'label': 'after-restart'}]
    result = {'static_mode': 'Both engines reread both tables; new Trino write read by PyIceberg'}
    try:
        result['fresh_client_remote_signing'] = py_read(delegation='remote-signing', with_credentials=False)
    except Exception as exc:
        result['fresh_client_remote_signing'] = {'error': str(exc)}
        traceback.print_exc()
    print('RESTART_RESULT=' + json.dumps(result), flush=True)


if sys.argv[1:] == ['verify-restart']:
    CREDS = json.loads((RUNTIME / 'credentials.json').read_text())
    verify_restart()
    sys.exit(0)


try:
    prepare()
    warehouse_id = start()
    probe('trino_create_insert_select', trino_write)
    probe('pyiceberg_reads_trino_before_mutations', lambda: py_read([
        {'id': 1, 'label': 'alpha'}, {'id': 2, 'label': 'beta'}, {'id': 3, 'label': 'gamma'}]))
    probe('trino_update_delete_history', mutate)
    probe('pyiceberg_reads_trino', py_read)
    probe('trino_reads_pyiceberg', py_write)
    modes(warehouse_id)
    probe('pyiceberg_client_managed_static', lambda: py_read(delegation='client-managed'))
    probe('pyiceberg_remote_signing_without_s3_credentials', lambda: py_read(delegation='remote-signing', with_credentials=False))
    probe('all_services_recreated', restart)
except Exception as exc:
    record('fatal', {'status': 'fail', 'error': str(exc)})
    traceback.print_exc()
finally:
    record('total_runtime_seconds', round(time.monotonic() - START, 2))
assert not any(isinstance(v, dict) and v.get('status') == 'fail' for v in RESULTS.values()), 'See reports/results.json'
