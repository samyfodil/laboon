// Node smoke test for the Windows backend (windows/m8/run.sh). One line per
// check; exits non-zero if any failed. "--offline" skips the outbound fetch.
const fs = require("fs"), crypto = require("crypto"), os = require("os");
const http = require("http"), cp = require("child_process");
const { Worker } = require("worker_threads");
const offline = process.argv.includes("--offline");
let failed = 0;
const ok = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${extra === "" ? "" : " " + extra}`);
  if (!cond) failed++;
};
const timeout = (p, ms, name) =>
  Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(name + " timed out")), ms))]);

function jit() {
  let n = 0;
  for (let i = 0; i < 5e6; i++) n = (n + i * 7) % 1000003;
  const f = new Function("a", "b", "return a * b + 1");
  let s = 0;
  for (let i = 0; i < 1e6; i++) s = f(i & 7, 3) + (s & 0xffff);
  ok("jit.loop", n === 840 && s > 0, n);
}

function cryptoChecks() {
  ok("crypto.sha256", crypto.createHash("sha256").update("abc").digest("hex") ===
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", key, iv);
  const enc = Buffer.concat([c.update("laboon on windows"), c.final()]);
  const d = crypto.createDecipheriv("aes-256-cbc", key, iv);
  ok("crypto.aes", Buffer.concat([d.update(enc), d.final()]).toString() === "laboon on windows");
  ok("crypto.hmac", crypto.createHmac("sha1", "k").update("v").digest("hex").length === 40);
}

function fsChecks() {
  const p = "/tmp/node-smoke.txt";
  fs.writeFileSync(p, "hello");
  fs.appendFileSync(p, " world");
  const st = fs.statSync(p);
  ok("fs.rw", fs.readFileSync(p, "utf8") === "hello world" && st.size === 11 && st.isFile());
  fs.mkdirSync("/tmp/node-smoke.d", { recursive: true });
  fs.renameSync(p, "/tmp/node-smoke.d/x");
  ok("fs.dir", fs.readdirSync("/tmp/node-smoke.d").includes("x"));
  fs.rmSync("/tmp/node-smoke.d", { recursive: true });
  ok("os", os.platform() === "linux" && os.cpus().length > 0, os.arch());
}

async function asyncFs() {
  const d = await fs.promises.readFile("/etc/os-release", "utf8");
  ok("fs.promises", d.includes("Alpine"));
}

async function timers() {
  const t0 = Date.now();
  await new Promise(r => setTimeout(r, 100));
  const dt = Date.now() - t0;
  let ticks = 0;
  await new Promise(r => { const iv = setInterval(() => { if (++ticks === 3) { clearInterval(iv); r(); } }, 10); });
  await new Promise(r => setImmediate(r));
  ok("timers", dt >= 95 && ticks === 3, dt);
}

async function worker() {
  const w = new Worker("const { parentPort } = require('worker_threads'); parentPort.on('message', m => parentPort.postMessage(m * 6))", { eval: true });
  const got = await timeout(new Promise((res, rej) => { w.once("message", res); w.once("error", rej); w.postMessage(7); }), 30000, "worker");
  await w.terminate();
  ok("worker_threads", got === 42);
}

async function child() {
  const r = cp.spawnSync("/bin/sh", ["-c", "echo out; echo err >&2; exit 3"], { encoding: "utf8" });
  ok("child.spawnSync", r.stdout === "out\n" && r.stderr === "err\n" && r.status === 3);
  const out = await new Promise((res, rej) => cp.exec("echo $((6*7))", (e, so) => (e ? rej(e) : res(so))));
  ok("child.exec", out === "42\n");
  const p = cp.spawn(process.execPath, ["-e", "process.stdin.pipe(process.stdout)"]);
  let got = "";
  p.stdout.on("data", d => (got += d));
  p.stdin.end("piped through node");
  const code = await new Promise(r => p.on("close", r));
  ok("child.spawn.node", code === 0 && got === "piped through node", JSON.stringify(got));
}

async function httpLoopback() {
  const srv = http.createServer((req, res) => res.end("hello " + req.url));
  await new Promise(r => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const body = await new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path: "/x" }, res => {
      let d = "";
      res.on("data", c => (d += c));
      res.on("end", () => resolve(d));
    }).on("error", reject);
  });
  ok("http.loopback", body === "hello /x", JSON.stringify(body));
  const r = await fetch(`http://127.0.0.1:${port}/f`);
  ok("fetch.loopback", (await r.text()) === "hello /f");
  srv.close();
}

async function outbound() {
  if (offline) return;
  const r = await fetch("http://example.com/");
  ok("fetch.example.com", r.status === 200 && (await r.text()).includes("Example Domain"), r.status);
  let refused = false;
  try {
    await timeout(fetch("http://example.org/"), 20000, "fetch.example.org");
  } catch {
    refused = true;
  }
  ok("egress.denied", refused);
}

(async () => {
  for (const [name, f] of [["jit", jit], ["crypto", cryptoChecks], ["fs", fsChecks], ["fs.promises", asyncFs],
    ["timers", timers], ["worker", worker], ["child", child], ["http", httpLoopback], ["outbound", outbound]]) {
    try {
      await timeout(Promise.resolve(f()), 60000, name);
    } catch (e) {
      ok(name, false, e && `${e.message}${e.cause ? " (" + (e.cause.code || e.cause.message) + ")" : ""}`);
    }
  }
  console.log(failed ? `${failed} FAILED` : "ALL PASS");
  process.exit(failed ? 1 : 0);
})();
