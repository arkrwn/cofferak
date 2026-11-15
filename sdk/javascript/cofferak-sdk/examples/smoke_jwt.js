#!/usr/bin/env node
// Smoke test for workload identity (JWT) sessions. Run by
// scripts/workload-check.sh against a real cofferakd with real signed JWTs;
// see the CONTRACT in that script's header.
//
// Usage: COFFERAK_SOCKET=... COFFERAK_JWT_DIR=... COFFERAK_JWT_EXPIRES_IN=<s> \
//   COFFERAK_REVOKE_CMD=<shell command> \
//   node examples/smoke_jwt.js <allowed-path-prefix> <denied-path>
//
// Uses the compiled dist/ output, like smoke.js.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execSync } = require("node:child_process");
const { Client, DeniedError } = require("../dist/index.js");

function env(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`${name} must be set`);
    process.exit(1);
  }
  return v;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const socketPath = env("COFFERAK_SOCKET");
  const jwtDir = env("COFFERAK_JWT_DIR");
  const expiresIn = Number(env("COFFERAK_JWT_EXPIRES_IN"));
  const revokeCmd = env("COFFERAK_REVOKE_CMD");
  const prefix = process.argv[2] || "app/javascript";
  const deniedPath = process.argv[3] || "other/denied";
  const jwt = (name) => path.join(jwtDir, name);

  const client = new Client(socketPath);
  const binary = Buffer.from(Array.from({ length: 256 }, (_, i) => i));

  // a. a valid token acts as the bound service
  const s = await client.sessionJwtFile(jwt("good.jwt"));
  try {
    assert.equal(s.service, "app1");
    const p = `${prefix}/jwt`;
    await s.set(p, binary);
    assert.ok((await s.get(p)).equals(binary), "binary value must round-trip");
    assert.ok((await s.getMany([p, `${prefix}/missing`])).get(p).equals(binary));
    assert.ok((await s.getAll(prefix)).get(p).equals(binary));
    assert.ok((await s.list(prefix)).includes(p));
    await assert.rejects(s.get(deniedPath), DeniedError);
    await assert.rejects(s.getMany([deniedPath]), DeniedError);
    await s.ping();
  } finally {
    s.close();
  }

  // b. every bad token is denied at open
  for (const name of ["wrong-aud.jwt", "unbound.jwt", "expired.jwt", "wrong-key.jwt"]) {
    await assert.rejects(client.sessionJwtFile(jwt(name)), DeniedError, name);
  }

  // c. reconnect with the fresh token from the (rotated) file
  const current = jwt("current.jwt");
  const cs = await client.sessionJwtFile(current);
  const opened = Date.now();
  try {
    await cs.get(`${prefix}/jwt`);
    const tmp = path.join(jwtDir, "current.jwt.tmp");
    fs.writeFileSync(tmp, fs.readFileSync(jwt("long.jwt")));
    fs.renameSync(tmp, current);
    const wait = expiresIn * 1000 + 1500 - (Date.now() - opened);
    if (wait > 0) await sleep(wait);
    assert.ok(
      (await cs.get(`${prefix}/jwt`)).equals(binary),
      "the session must reconnect with the fresh token"
    );
  } finally {
    cs.close();
  }

  // e. a provider function (before d: the revocation removes the binding)
  const calls = { n: 0 };
  const ps = await client.sessionJwt(async () => {
    calls.n++;
    return fs.readFileSync(jwt("long.jwt"), "utf8").trim();
  });
  try {
    assert.equal(ps.service, "app1");
    assert.ok(calls.n >= 1);
  } finally {
    ps.close();
  }
  // a provider error is passed on unchanged, never turned into DeniedError
  const boom = new Error("provider failed");
  await assert.rejects(
    client.sessionJwt(() => Promise.reject(boom)),
    (e) => e === boom
  );

  // d. revocation: the binding is removed while the session is open
  const rs = await client.sessionJwtFile(jwt("good.jwt"));
  try {
    await rs.get(`${prefix}/jwt`);
    execSync(revokeCmd, { stdio: "inherit" });
    await assert.rejects(rs.get(`${prefix}/jwt`), DeniedError);
  } finally {
    rs.close();
  }

  console.log("javascript SDK JWT smoke test passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
