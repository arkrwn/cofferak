// Session (protocol version 2) checks shared by smoke.js and smoke_tls.js,
// so both transports prove the same behaviour against a real cofferakd.
// Uses the compiled dist/ output, like the examples themselves.

const assert = require("node:assert/strict");
const { DeniedError, NotFoundError } = require("../dist/index.js");

async function sessionChecks(client, token, allowedPath, deniedPath) {
  const base = `${allowedPath}-session`;
  const a = `${base}/A`;
  const b = `${base}/B`;
  const binary = Buffer.from(Array.from({ length: 256 }, (_, i) => i));

  const s = await client.session(token);
  try {
    assert.ok(s.service, "the session must report its service id");
    await s.ping();
    await s.set(a, Buffer.from("alpha"));
    await s.set(b, binary);
    assert.ok((await s.get(b)).equals(binary), "binary value must round-trip");

    const expectBoth = (values, what) => {
      assert.equal(values.size, 2, `${what} must return exactly the two values`);
      assert.ok(values.get(a).equals(Buffer.from("alpha")), what);
      assert.ok(values.get(b).equals(binary), what);
    };
    expectBoth(await s.getMany([a, b, `${base}/MISSING`]), "getMany");
    expectBoth(await s.getAll(base), "getAll");
    assert.deepEqual((await s.list(base)).sort(), [a, b]);

    // Calls made at the same time share the one connection, in order.
    const together = await Promise.all([s.get(a), s.get(b), s.get(a)]);
    assert.ok(together[0].equals(Buffer.from("alpha")) && together[1].equals(binary));

    await assert.rejects(s.get(deniedPath), DeniedError);
    await assert.rejects(s.getMany([deniedPath]), DeniedError);

    // With $COFFERAK_SMOKE_IDLE_SECS the daemon closes idle sessions after
    // that many seconds: wait it out, the next call must reconnect.
    const idle = process.env.COFFERAK_SMOKE_IDLE_SECS;
    if (idle) {
      await new Promise((r) => setTimeout(r, (Number(idle) + 1) * 1000));
    }
    assert.ok((await s.get(a)).equals(Buffer.from("alpha")), "session must reconnect");
    // A closed session reconnects when used again.
    s.close();
    await s.rm(a);
    await s.rm(b);
    await assert.rejects(s.get(a), NotFoundError);
  } finally {
    s.close();
  }

  await assert.rejects(client.session("0".repeat(64)), DeniedError);
}

module.exports = { sessionChecks };
