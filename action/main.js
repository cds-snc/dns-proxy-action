// Starts the DNS proxy in the background and records its PID so the post
// step can stop it at the end of the job.
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const binaries = { x64: "dns-proxy-action-amd64", arm64: "dns-proxy-action-arm64" };
const binary = binaries[process.arch];
if (!binary) {
  console.log(`::error::Unsupported architecture: ${process.arch}`);
  process.exit(1);
}

const out = fs.openSync("/tmp/dns-proxy-action.out", "w");
const proxy = spawn(
  "sudo",
  ["-E", path.join(__dirname, "..", "release", "latest", binary)],
  { detached: true, stdio: ["ignore", out, out] },
);
proxy.unref();
fs.appendFileSync(process.env.GITHUB_STATE, `pid=${proxy.pid}\n`);

proxy.on("exit", (code) => {
  console.log(`::warning::DNS proxy exited early with code ${code}, see /tmp/dns-proxy-action.out`);
});

// Give the proxy time to start listening before later steps make lookups.
setTimeout(() => process.exit(0), 3000);
