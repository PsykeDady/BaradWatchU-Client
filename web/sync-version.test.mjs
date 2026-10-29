import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

function fixture(run) {
  const dir = mkdtempSync(join(tmpdir(), 'baradwatchu version '));
  try {
    const web = join(dir, 'web');
    mkdirSync(join(web, 'src'), { recursive: true });
    copyFileSync(new URL('./sync-version.mjs', import.meta.url), join(web, 'sync-version.mjs'));
    writeFileSync(join(web, 'package.json'), '{"name":"fixture","version":"0.0.0"}\n');
    writeFileSync(join(web, 'package-lock.json'), '{"version":"0.0.0","lockfileVersion":3,"packages":{"":{"version":"0.0.0"}}}\n');
    writeFileSync(join(web, 'src/app-version.ts'), 'old version\n');
    const invoke = (...args) => spawnSync(process.execPath, [join(web, 'sync-version.mjs'), ...args], { encoding: 'utf8', cwd: tmpdir() });
    run({ dir, web, invoke });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('reads only workspace.package version, regardless of section order', () => fixture(({ dir, web, invoke }) => {
  writeFileSync(join(dir, 'Cargo.toml'), '[package]\nversion = "9.9.9"\n[workspace.package]\nversion="0.0.1" # authoritative\n[dependencies]\nversion = "8.8.8"\n');
  assert.equal(invoke().status, 0);
  assert.equal(JSON.parse(readFileSync(join(web, 'package.json'))).version, '0.0.1');
  const lock = JSON.parse(readFileSync(join(web, 'package-lock.json')));
  assert.equal(lock.version, '0.0.1');
  assert.equal(lock.packages[''].version, '0.0.1');
  assert.match(readFileSync(join(web, 'src/app-version.ts'), 'utf8'), /APP_VERSION = '0.0.1'/);
}));

test('--check rejects stale metadata without writing files', () => fixture(({ dir, web, invoke }) => {
  writeFileSync(join(dir, 'Cargo.toml'), '[workspace.package]\nversion = "0.0.1"\n');
  const before = readFileSync(join(web, 'package.json'), 'utf8');
  assert.equal(invoke('--check').status, 1);
  assert.equal(readFileSync(join(web, 'package.json'), 'utf8'), before);
  assert.equal(invoke().status, 0);
  assert.equal(invoke('--check').status, 0);
}));

test('missing or invalid workspace version never changes metadata', () => fixture(({ dir, web, invoke }) => {
  const before = readFileSync(join(web, 'package.json'), 'utf8');
  for (const cargo of ['[package]\nversion="0.0.1"\n', '[workspace.package]\nversion="01.0.1"\n']) {
    writeFileSync(join(dir, 'Cargo.toml'), cargo);
    assert.notEqual(invoke().status, 0);
    assert.equal(readFileSync(join(web, 'package.json'), 'utf8'), before);
  }
}));

test('unknown options return usage exit code 2', () => fixture(({ invoke }) => {
  assert.equal(invoke('--unknown').status, 2);
}));
