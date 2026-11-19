// Stops the DNS proxy with SIGTERM so it sends its queued Sentinel records,
// then waits for it to exit.
const { execFileSync } = require("child_process");
const fs = require("fs");

// The proxy needs up to 5 seconds to send its last records.
const timeoutMs = 10000;
const outFile = "/tmp/dns-proxy-action.out";
const pid = process.env.STATE_pid;

function isRunning() {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    // The state follows the command name, which is in parentheses.
    return stat.slice(stat.lastIndexOf(")") + 2, stat.lastIndexOf(")") + 3) !== "Z";
  } catch {
    return false;
  }
}

function outputSize() {
  try {
    return fs.statSync(outFile).size;
  } catch {
    return 0;
  }
}

async function main() {
  if (!pid || !isRunning()) {
    console.log("DNS proxy is not running");
    return;
  }

  const offset = outputSize();
  // sudo runs as root, so signalling it needs sudo. It passes the signal on to the proxy.
  execFileSync("sudo", ["kill", "-TERM", pid], { stdio: "inherit" });

  const deadline = Date.now() + timeoutMs;
  while (isRunning() && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (isRunning()) {
    console.log(`::warning::DNS proxy did not exit within ${timeoutMs / 1000} seconds`);
  } else {
    console.log("DNS proxy stopped");
  }

  // Show what the proxy logged while shutting down, such as unsent records.
  const size = outputSize();
  if (size > offset) {
    const fd = fs.openSync(outFile, "r");
    const buf = Buffer.alloc(size - offset);
    fs.readSync(fd, buf, 0, buf.length, offset);
    fs.closeSync(fd);
    process.stdout.write(buf.toString());
  }
}

main().catch((err) => {
  console.log(`::warning::Unable to stop the DNS proxy: ${err.message}`);
});
