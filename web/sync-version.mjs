import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const webDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(webDir, '..');
const cargo = readFileSync(resolve(root, 'Cargo.toml'), 'utf8');
const version = cargo.match(/^version\s*=\s*"(\d+\.\d+\.\d+)"\s*$/m)?.[1];
if (!version) throw new Error('Cannot read SemVer workspace version from Cargo.toml');

const packagePath = resolve(webDir, 'package.json');
const pkg = JSON.parse(readFileSync(packagePath, 'utf8'));
pkg.version = version;
writeFileSync(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);
const lockPath = resolve(webDir, 'package-lock.json');
if (existsSync(lockPath)) {
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  lock.version = version;
  if (lock.packages?.['']) lock.packages[''].version = version;
  writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
}
writeFileSync(resolve(webDir, 'src/app-version.ts'),
  `// Generated from the authoritative Cargo workspace version by sync-version.mjs.\nexport const APP_VERSION = '${version}';\n`);
console.log(`Angular package and UI version synchronized to ${version}`);
