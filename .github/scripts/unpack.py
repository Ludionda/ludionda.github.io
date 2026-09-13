"""Validate a public-only archive before publishing. Never execute uploaded files."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import io
import json
import os
import re
import stat
import tempfile
import zipfile

ALLOWED_EXTENSIONS = {'.html', '.css', '.js', '.svg', '.png', '.jpg', '.webp', '.ico'}

def unpack(inputs, output):
    if not re.fullmatch(r'[0-9a-f]{40}', inputs['source_sha']):
        raise ValueError('Invalid source SHA')
    if not re.fullmatch(r'[0-9a-f]{64}', inputs['bundle_sha256']):
        raise ValueError('Invalid bundle hash')
    if len(json.dumps(inputs)) > 60000:
        raise ValueError('Bundle input is too large')
    raw = base64.b64decode(inputs['bundle_base64'], validate=True)
    if hashlib.sha256(raw).hexdigest() != inputs['bundle_sha256']:
        raise ValueError('Bundle hash mismatch')
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists')
    validated = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if not 1 <= len(entries) <= 200 or sum(e.file_size for e in entries) > 10_000_000:
            raise ValueError('Invalid publication size or file count')
        for entry in entries:
            name = entry.filename
            path = PurePosixPath(name)
            if (path.is_absolute() or '..' in path.parts or str(path) != name or '\\' in name
                    or name in validated or not path.parts):
                raise ValueError('Unsafe or duplicate publication path')
            if name != '.nojekyll' and (any(p.startswith('.') for p in path.parts) or path.suffix not in ALLOWED_EXTENSIONS):
                raise ValueError('Not a supported public asset')
            file_type = stat.S_IFMT(entry.external_attr >> 16)
            if entry.is_dir() or file_type not in (0, stat.S_IFREG) or entry.flag_bits & 1:
                raise ValueError('Not a regular unencrypted file')
            validated[name] = archive.read(entry)
    if 'index.html' not in validated:
        raise ValueError('A homepage is required')
    # Validate parent/file conflicts before writing anything.
    for name in validated:
        if any(str(parent) in validated for parent in PurePosixPath(name).parents):
            raise ValueError('Conflicting publication paths')
    with tempfile.TemporaryDirectory(prefix='pages-stage-', dir=output.parent) as tmp:
        stage = Path(tmp) / 'site'
        stage.mkdir()
        for name, data in validated.items():
            dest = stage / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            dest.chmod(0o644)
        stage.rename(output)
    return {name: hashlib.sha256(data).hexdigest() for name, data in validated.items()}

if __name__ == '__main__':
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    paths = unpack(event['inputs'], Path(os.environ['RUNNER_TEMP']) / 'pages-site')
    print(f'Validated {len(paths)} public files.')
