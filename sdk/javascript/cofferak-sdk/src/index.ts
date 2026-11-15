/**
 * Minimal TypeScript/JavaScript client SDK for cofferak.
 *
 * Connects to a running `cofferakd` over its Unix socket, or (server
 * mode, ADR 0008) over TLS-wrapped TCP, and speaks the same
 * newline-delimited JSON protocol documented in
 * `cofferakd/src/protocol.rs` (`Request`/`Response`, serde's default
 * externally-tagged enum encoding). Node.js standard library only
 * (`net`, `tls`, `fs`) - no runtime dependencies, including for TLS.
 *
 * ```ts
 * import { Client } from "cofferak-sdk";
 *
 * const client = new Client("/run/cofferak/cofferakd.sock");
 * await client.set("my-token", "myapp/DB_PASSWORD", Buffer.from("s3cr3t"));
 * const value = await client.get("my-token", "myapp/DB_PASSWORD");
 * ```
 *
 * Server mode:
 *
 * ```ts
 * const client = Client.connectTls({
 *   addr: "cofferak.example.internal:8443",
 *   serverName: "cofferak.example.internal",
 *   caCertPath: "/path/to/ca.pem",
 * });
 * ```
 *
 * Sessions (protocol version 2): authenticate once, keep one connection,
 * and read many values in one round trip:
 *
 * ```ts
 * const session = await client.session("my-token");
 * const password = await session.get("myapp/DB_PASSWORD");
 * const config = await session.getAll("myapp"); // Map of path to value
 * session.close();
 * ```
 *
 * The compiled `dist/index.js` (CommonJS) works the same way from plain
 * JavaScript - this is one package serving both runtimes.
 */

import * as fs from "node:fs";
import * as net from "node:net";
import * as tls from "node:tls";

/** Mirrors cofferakd's `protocol::MAX_LINE_BYTES` (and the Rust/Go/Python
 * SDKs' identical constant) - a hard ceiling on one response line, so a
 * malicious or compromised daemon that never terminates a response
 * can't grow this client's buffer without limit. */
const MAX_LINE_BYTES = 16 * 1024 * 1024;

/** Bounds how long one call can block on the network - a stalled or
 * malicious daemon otherwise ties up the caller indefinitely. Matches
 * cofferakd's own per-connection timeout (ADR 0008). */
const IO_TIMEOUT_MS = 30_000;

/** Mirrors cofferakd's `protocol::MAX_BATCH_PATHS`: the most paths one
 * `GetMany` request may carry. `Session.getMany` splits longer lists. */
const MAX_BATCH_PATHS = 256;

/** Base class for every error this SDK raises. */
export class CofferakError extends Error {}

/** The token doesn't have access to the requested path, or the token is
 * unknown to the daemon. */
export class DeniedError extends CofferakError {
  constructor() {
    super("denied");
    this.name = "DeniedError";
  }
}

/** The requested path has no value set. */
export class NotFoundError extends CofferakError {
  constructor() {
    super("not found");
    this.name = "NotFoundError";
  }
}

/** The daemon returned an error message. */
export class RemoteError extends CofferakError {
  constructor(message: string) {
    super(`remote error: ${message}`);
    this.name = "RemoteError";
  }
}

/** The daemon's response didn't match any known `Response` shape, or
 * exceeded this client's size limit. */
export class ProtocolError extends CofferakError {
  constructor(message: string) {
    super(`protocol error: ${message}`);
    this.name = "ProtocolError";
  }
}

type WireResponse =
  | { Value: number[] }
  | { Listed: string[] }
  | { Err: string }
  | "Ok"
  | "Denied"
  | "NotFound";

/** Options for connecting over TLS/TCP (server mode, ADR 0008) instead
 * of the Unix socket. */
export interface TlsOptions {
  /** `"host:port"` to connect to (matches the daemon's `$COFFERAK_TLS_ADDR`). */
  addr: string;
  /** Verified against the server's certificate (its subject/SAN) - this
   * is NOT where you disable verification, there is no option to do
   * that in this SDK. */
  serverName: string;
  /** PEM file containing the CA that signed the server's certificate.
   * cofferak's TLS is for a self-managed deployment, not the public web -
   * this client trusts ONLY this CA, never Node's bundled public root
   * store (passing `ca` to `tls.connect` replaces the default trust
   * store rather than adding to it). */
  caCertPath: string;
  /** Client certificate + private key (PEM), both set together, for
   * mutual TLS. cofferakd's server mode always requires them (ADR 0011);
   * they are optional here only so a client can be built to prove that a
   * certificate-less connection is refused. */
  clientCertPath?: string;
  clientKeyPath?: string;
}

type Transport =
  | { kind: "unix"; socketPath: string }
  | {
      kind: "tls";
      host: string;
      port: number;
      serverName: string;
      ca: Buffer;
      cert?: Buffer;
      key?: Buffer;
    };

/**
 * A client connected to one cofferakd endpoint - a Unix socket, or
 * (server mode) a TLS/TCP address. Each call opens a fresh connection,
 * matching the convention established by cofferakd's own CLI client.
 */
export class Client {
  private readonly transport: Transport;

  constructor(socketPath: string) {
    this.transport = { kind: "unix", socketPath };
  }

  private static fromTransport(transport: Transport): Client {
    // Bypasses the public (Unix-socket) constructor entirely - there is
    // no intermediate "empty"/placeholder Client ever created.
    const client = Object.create(Client.prototype) as Client;
    (client as unknown as { transport: Transport }).transport = transport;
    return client;
  }

  /** Build a client for the daemon's TLS/TCP listener (server mode,
   * ADR 0008). Loads the CA (and, if given, client cert/key) eagerly,
   * so a misconfiguration fails here rather than on the first call. */
  static connectTls(options: TlsOptions): Client {
    const [host, portStr] = splitHostPort(options.addr);
    const ca = fs.readFileSync(options.caCertPath);
    let cert: Buffer | undefined;
    let key: Buffer | undefined;
    if (options.clientCertPath || options.clientKeyPath) {
      if (!options.clientCertPath || !options.clientKeyPath) {
        throw new Error("clientCertPath and clientKeyPath must both be set, or neither");
      }
      cert = fs.readFileSync(options.clientCertPath);
      key = fs.readFileSync(options.clientKeyPath);
    }
    return Client.fromTransport({
      kind: "tls",
      host,
      port: Number(portStr),
      serverName: options.serverName,
      ca,
      cert,
      key,
    });
  }

  /** Start one connection to the daemon. For TLS the socket is usable
   * once `secureConnect` fires, for the Unix socket once `connect` does. */
  private createSocket(): net.Socket {
    const transport = this.transport;
    return transport.kind === "tls"
      ? tls.connect({
          host: transport.host,
          port: transport.port,
          servername: transport.serverName,
          ca: transport.ca,
          cert: transport.cert,
          key: transport.key,
          minVersion: "TLSv1.3",
          maxVersion: "TLSv1.3",
          // Only the AES-256-GCM-SHA384 suite, matching the server
          // (ADR 0011).
          ciphers: "TLS_AES_256_GCM_SHA384",
          // rejectUnauthorized defaults to true and is never set to
          // false anywhere in this SDK - that is the one setting
          // that would disable certificate verification.
        })
      : net.createConnection({ path: transport.socketPath });
  }

  /** Open one connection and wait until it can carry requests. Used by
   * {@link Session}. */
  openConnection(): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const sock = this.createSocket();
      const ready = this.transport.kind === "tls" ? "secureConnect" : "connect";
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error("timed out"));
      }, IO_TIMEOUT_MS);
      sock.once(ready, () => {
        clearTimeout(timer);
        sock.removeAllListeners("error");
        resolve(sock);
      });
      sock.once("error", (e) => {
        clearTimeout(timer);
        sock.destroy();
        reject(e);
      });
    });
  }

  /** Open a session (protocol version 2): authenticate once with
   * `token`, then make any number of calls on one connection. Call
   * `close()` when done. Rejects with {@link DeniedError} if the token is
   * not accepted, and {@link ProtocolError} if the daemon is too old for
   * sessions. */
  session(token: string): Promise<Session> {
    return Session.open(this, token);
  }

  private send(request: unknown): Promise<WireResponse> {
    return new Promise((resolve, reject) => {
      const transport = this.transport;
      const sock: net.Socket = this.createSocket();

      let buf = Buffer.alloc(0);
      let settled = false;

      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        sock.destroy();
        reject(err);
      };
      const succeed = (value: WireResponse) => {
        if (settled) return;
        settled = true;
        sock.end();
        resolve(value);
      };

      sock.setTimeout(IO_TIMEOUT_MS, () => fail(new Error("timed out")));

      sock.on("connect", () => {
        sock.write(JSON.stringify(request) + "\n");
      });
      // For the TLS transport `connect` fires on the underlying TCP
      // socket before the handshake completes, writing the request is
      // deferred to `secureConnect` there instead.
      if (transport.kind === "tls") {
        (sock as tls.TLSSocket).on("secureConnect", () => {
          sock.write(JSON.stringify(request) + "\n");
        });
      }
      sock.on("data", (chunk: Buffer) => {
        if (settled) return;
        if (buf.length + chunk.length > MAX_LINE_BYTES) {
          fail(new ProtocolError("response line exceeded the maximum allowed size"));
          return;
        }
        buf = Buffer.concat([buf, chunk]);
        const idx = buf.indexOf(0x0a); // '\n'
        if (idx !== -1) {
          try {
            succeed(JSON.parse(buf.subarray(0, idx).toString("utf8")) as WireResponse);
          } catch (e) {
            fail(new ProtocolError(`invalid JSON response: ${(e as Error).message}`));
          }
        }
      });
      sock.on("error", (e) => fail(e));
    });
  }

  private static checkOk(response: WireResponse): void {
    if (response === "Ok") return;
    if (response === "Denied") throw new DeniedError();
    if (response === "NotFound") throw new NotFoundError();
    if (typeof response === "object" && "Err" in response) {
      throw new RemoteError(response.Err);
    }
    throw new ProtocolError(
      `unexpected response to a write/delete request: ${JSON.stringify(response)}`
    );
  }

  /** Read a secret's value. */
  async get(token: string, path: string): Promise<Buffer> {
    const response = await this.send({ Get: { token, path } });
    if (typeof response === "object" && "Value" in response) {
      return Buffer.from(response.Value);
    }
    if (response === "Denied") throw new DeniedError();
    if (response === "NotFound") throw new NotFoundError();
    if (typeof response === "object" && "Err" in response) {
      throw new RemoteError(response.Err);
    }
    throw new ProtocolError(`unexpected response to Get: ${JSON.stringify(response)}`);
  }

  /** Write a secret's value. Requires a read-write token. */
  async set(token: string, path: string, value: Uint8Array): Promise<void> {
    const response = await this.send({
      Set: { token, path, value: Array.from(value) },
    });
    Client.checkOk(response);
  }

  /** Remove a secret. Requires a read-write token. */
  async rm(token: string, path: string): Promise<void> {
    const response = await this.send({ Rm: { token, path } });
    Client.checkOk(response);
  }

  /** List secret paths under `prefix`. */
  async list(token: string, prefix: string): Promise<string[]> {
    const response = await this.send({ List: { token, prefix } });
    if (typeof response === "object" && "Listed" in response) {
      return response.Listed;
    }
    if (response === "Denied") throw new DeniedError();
    if (typeof response === "object" && "Err" in response) {
      throw new RemoteError(response.Err);
    }
    throw new ProtocolError(`unexpected response to List: ${JSON.stringify(response)}`);
  }
}

/** The connection under a session was lost: the one failure a session
 * answers by reconnecting. */
class ConnectionLost extends Error {}

type SessionResponse =
  | { Hello: { version: number; features?: string[] } }
  | { Authed: { service: string } }
  | { Value: string }
  | { Values: { path: string; value?: string; error?: string }[] }
  | { Listed: string[] }
  | { Err: string }
  | "Ok"
  | "Denied"
  | "NotFound";

/**
 * An authenticated connection to cofferakd (protocol version 2).
 *
 * One connection carries every call, so over TLS the handshake is paid
 * once instead of once per secret. If the daemon closes the connection (it
 * does after an idle period), the next call reconnects and authenticates
 * again without the caller noticing. Calls made at the same time run one
 * after another. An idle session does not keep the Node.js process alive.
 */
export class Session {
  /** The service id the daemon knows this session's token as. */
  service = "";

  private sock: net.Socket | null = null;
  private buf: Buffer = Buffer.alloc(0);
  private waiter: { resolve: (line: Buffer) => void; reject: (e: Error) => void } | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(
    private readonly client: Client,
    private readonly token: string
  ) {}

  /** Use {@link Client.session}. */
  static async open(client: Client, token: string): Promise<Session> {
    const session = new Session(client, token);
    await session.connect();
    return session;
  }

  /** Close the connection. The session reconnects if used again. */
  close(): void {
    const sock = this.sock;
    this.sock = null;
    this.buf = Buffer.alloc(0);
    if (sock) sock.destroy();
    this.failWaiter(new ConnectionLost("session closed"));
  }

  private failWaiter(err: Error): void {
    const waiter = this.waiter;
    this.waiter = null;
    if (waiter) waiter.reject(err);
  }

  private async connect(): Promise<void> {
    this.close();
    const sock = await this.client.openConnection();
    this.sock = sock;
    const lost = (err: Error) => {
      if (this.sock !== sock) return;
      this.sock = null;
      this.buf = Buffer.alloc(0);
      sock.destroy();
      this.failWaiter(err);
    };
    sock.on("error", (e) => lost(new ConnectionLost(e.message)));
    sock.on("close", () => lost(new ConnectionLost("cofferakd closed the connection")));
    sock.on("data", (chunk: Buffer) => {
      if (this.sock !== sock) return;
      if (this.buf.length + chunk.length > MAX_LINE_BYTES) {
        lost(new ProtocolError("response line exceeded the maximum allowed size"));
        return;
      }
      this.buf = Buffer.concat([this.buf, chunk]);
      this.deliver();
    });

    try {
      const hello = await this.roundtrip({ Hello: { version: 2 } });
      if (typeof hello !== "object" || !("Hello" in hello)) {
        throw new ProtocolError(
          "this cofferakd does not support sessions (protocol version 2), " +
            "upgrade it or use the per-call Client methods"
        );
      }
      const authed = await this.roundtrip({
        Auth: { method: "token", credential: this.token },
      });
      if (typeof authed === "object" && "Authed" in authed) {
        this.service = authed.Authed.service;
      } else {
        Session.raise(authed, "Auth");
      }
    } catch (e) {
      this.close();
      throw e;
    }
  }

  /** Hand the first complete response line to whoever waits for it. */
  private deliver(): void {
    if (!this.waiter) return;
    const idx = this.buf.indexOf(0x0a); // '\n'
    if (idx === -1) return;
    const line = this.buf.subarray(0, idx);
    this.buf = this.buf.subarray(idx + 1);
    const waiter = this.waiter;
    this.waiter = null;
    waiter.resolve(line);
  }

  private roundtrip(request: unknown): Promise<SessionResponse> {
    return new Promise<Buffer>((resolve, reject) => {
      const sock = this.sock;
      if (!sock) {
        reject(new ConnectionLost("not connected"));
        return;
      }
      sock.ref();
      const timer = setTimeout(() => {
        if (this.sock === sock) {
          this.sock = null;
          sock.destroy();
        }
        this.failWaiter(new Error("timed out"));
      }, IO_TIMEOUT_MS);
      const done = () => {
        clearTimeout(timer);
        // An idle session must not keep the process alive.
        sock.unref();
      };
      this.waiter = {
        resolve: (line) => {
          done();
          resolve(line);
        },
        reject: (e) => {
          done();
          reject(e);
        },
      };
      sock.write(JSON.stringify(request) + "\n");
      this.deliver();
    }).then((line) => {
      try {
        return JSON.parse(line.toString("utf8")) as SessionResponse;
      } catch (e) {
        throw new ProtocolError(`invalid JSON response: ${(e as Error).message}`);
      }
    });
  }

  /** Send one request, after any call already in flight. If the
   * connection is gone, reconnect and send it again once - except when
   * `retry` is false (a request that must not be repeated). */
  private call(request: unknown, retry = true): Promise<SessionResponse> {
    const run = async (): Promise<SessionResponse> => {
      if (!this.sock) await this.connect();
      try {
        return await this.roundtrip(request);
      } catch (e) {
        if (!(e instanceof ConnectionLost) || !retry) throw e;
      }
      await this.connect();
      return this.roundtrip(request);
    };
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => undefined);
    return result;
  }

  private static raise(response: SessionResponse, what: string): never {
    if (response === "Denied") throw new DeniedError();
    if (response === "NotFound") throw new NotFoundError();
    if (typeof response === "object" && "Err" in response) {
      throw new RemoteError(response.Err);
    }
    throw new ProtocolError(`unexpected response to ${what}: ${JSON.stringify(response)}`);
  }

  /** Read a secret's value. */
  async get(path: string): Promise<Buffer> {
    const response = await this.call({ Get: { path } });
    if (typeof response === "object" && "Value" in response) {
      return Buffer.from(response.Value, "base64");
    }
    return Session.raise(response, "Get");
  }

  /** Read several secrets in one round trip. Resolves to the values of
   * the paths that exist, a path with no value is left out. Rejects with
   * {@link DeniedError} if any path is outside what the token may read. */
  async getMany(paths: string[]): Promise<Map<string, Buffer>> {
    const out = new Map<string, Buffer>();
    for (let start = 0; start < paths.length; start += MAX_BATCH_PATHS) {
      const chunk = paths.slice(start, start + MAX_BATCH_PATHS);
      const response = await this.call({ GetMany: { paths: chunk } });
      if (typeof response !== "object" || !("Values" in response)) {
        return Session.raise(response, "GetMany");
      }
      for (const item of response.Values) {
        if (item.error === undefined && item.value !== undefined) {
          out.set(item.path, Buffer.from(item.value, "base64"));
        } else if (item.error === "denied") {
          throw new DeniedError();
        } else if (item.error !== "not_found") {
          throw new RemoteError(`could not read ${item.path}`);
        }
      }
    }
    return out;
  }

  /** Read every secret under `prefix`. */
  async getAll(prefix: string): Promise<Map<string, Buffer>> {
    return this.getMany(await this.list(prefix));
  }

  /** Write a secret's value. Requires a read-write token. */
  async set(path: string, value: Uint8Array): Promise<void> {
    const response = await this.call({
      Set: { path, value: Buffer.from(value).toString("base64") },
    });
    if (response !== "Ok") Session.raise(response, "Set");
  }

  /** Remove a secret. Requires a read-write token. */
  async rm(path: string): Promise<void> {
    // Not repeated on a lost connection: a second try after a removal
    // that did go through would wrongly report "not found".
    const response = await this.call({ Rm: { path } }, false);
    if (response !== "Ok") Session.raise(response, "Rm");
  }

  /** List secret paths under `prefix`. */
  async list(prefix: string): Promise<string[]> {
    const response = await this.call({ List: { prefix } });
    if (typeof response === "object" && "Listed" in response) {
      return response.Listed;
    }
    return Session.raise(response, "List");
  }

  /** Check that the daemon answers on this session. */
  async ping(): Promise<void> {
    const response = await this.call("Ping");
    if (response !== "Ok") Session.raise(response, "Ping");
  }
}

function splitHostPort(addr: string): [string, string] {
  const idx = addr.lastIndexOf(":");
  if (idx === -1) {
    throw new Error(`addr must be "host:port", got ${JSON.stringify(addr)}`);
  }
  return [addr.slice(0, idx), addr.slice(idx + 1)];
}
