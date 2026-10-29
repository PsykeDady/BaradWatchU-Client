import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== '--check')) {
  console.error('Usage: node sync-version.mjs [--check]');
  process.exit(2);
}
const check = args[0] === '--check';
const webDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(webDir, '..');
const cargo = readFileSync(resolve(root, 'Cargo.toml'), 'utf8');
let inWorkspacePackage = false;
let version;
for (const line of cargo.split(/\r?\n/)) {
  const section = line.match(/^\s*\[([^\]]+)\]\s*(?:#.*)?$/);
  if (section) {
    inWorkspacePackage = section[1] === 'workspace.package';
    continue;
  }
  if (!inWorkspacePackage) continue;
  const match = line.match(/^\s*version\s*=\s*"((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))"\s*(?:#.*)?$/);
  if (match) {
    if (version) throw new Error('Duplicate workspace version in Cargo.toml');
    version = match[1];
  }
}
if (!version) throw new Error('Cannot read SemVer version from [workspace.package] in Cargo.toml');

const updates = [];
const packagePath = resolve(webDir, 'package.json');
const pkg = JSON.parse(readFileSync(packagePath, 'utf8'));
pkg.version = version;
updates.push([packagePath, `${JSON.stringify(pkg, null, 2)}\n`]);
const lockPath = resolve(webDir, 'package-lock.json');
if (existsSync(lockPath)) {
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  lock.version = version;
  if (lock.packages?.['']) lock.packages[''].version = version;
  updates.push([lockPath, `${JSON.stringify(lock, null, 2)}\n`]);
}
updates.push([resolve(webDir, 'src/app-version.ts'),
  `// Generated from the authoritative Cargo workspace version by sync-version.mjs.\nexport const APP_VERSION = '${version}';\n`]);

const changed = updates.filter(([path, content]) => !existsSync(path) || readFileSync(path, 'utf8') !== content);
if (check && changed.length) {
  console.error('Version metadata is out of sync; run npm run sync-version');
  process.exit(1);
}
for (const [path, content] of changed) writeFileSync(path, content);
console.log(`Angular package and UI version ${check ? 'verified' : 'synchronized'}: ${version}`);
