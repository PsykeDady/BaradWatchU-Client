const [major, minor, patch] = process.versions.node.split('.').map(Number);
if (major !== 20 || minor < 11 || (minor === 11 && patch < 1)) {
  console.error(`Node.js 20.11.1+ within Node 20 is required; found ${process.versions.node}. In web/, run nvm use (or select Node 20), then npm ci.`);
  process.exit(1);
}
