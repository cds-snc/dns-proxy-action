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

const outFile = "/tmp/dns-proxy-action.out";
const out = fs.openSync(outFile, "w");
const proxy = spawn(
  "sudo",
  ["-E", path.join(__dirname, "..", "release", "latest", binary)],
  { detached: true, stdio: ["ignore", out, out] },
);
proxy.unref();
fs.appendFileSync(process.env.GITHUB_STATE, `pid=${proxy.pid}\n`);

// Wait for the proxy to replace the DNS config and start listening, then
// give systemd-resolved a moment to pick up the change.
const startTimeoutMs = 15000;
const settleMs = 1000;
const started = Date.now();
const timer = setInterval(() => {
  const listening = fs.readFileSync(outFile, "utf8").includes("DNS proxy server listening");
  if (listening || Date.now() - started > startTimeoutMs) {
    clearInterval(timer);
    if (!listening) {
      console.log(`::warning::DNS proxy did not start listening within ${startTimeoutMs / 1000} seconds`);
    }
    setTimeout(() => process.exit(0), settleMs);
  }
}, 100);

proxy.on("exit", (code) => {
  console.log(`::warning::DNS proxy exited early with code ${code}, see ${outFile}`);
  process.exit(0);
});
