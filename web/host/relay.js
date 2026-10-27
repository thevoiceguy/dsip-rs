// @ts-check
// The relay connection: one WebSocket, `hello` first, the relay's `hello` verified (its `in_reply_to` must be our
// id: anti-splicing), then frames both ways; reconnects with backoff.
//
// Spec: §13.2 (ws/1.0, hello first, capabilities), §20.5 (anti-splicing). The verification of the relay's hello
// is the engine's (`relay_hello`); this file only moves bytes and keeps the socket alive.

/** @typedef {import('../pkg/dsip_wasm.js').RelayHello} RelayHello */

/**
 * What the owner of a connection listens for. Every handler is optional.
 * @typedef {object} RelayHandlers
 * @property {(r: Extract<RelayHello, {ok: true}>) => unknown} [bound]
 * @property {(text: string) => unknown} [frame]
 * @property {(wasBound: boolean) => void} [closed]
 * @property {(r: Extract<RelayHello, {ok: false}>) => void} [refused]
 * @property {(code: string) => void} [rejected]
 * @property {(frame: string) => void} [dropped]
 */

export class Relay {
  /** `engine` is the wasm Endpoint or Messenger: each signs our hello and verifies the relay's.
   *  @param {string} url
   *  @param {{ hello_frame(now: number): string, relay_hello(frame: string, now: number): RelayHello }} engine
   *  @param {RelayHandlers} on
   *  @param {() => number} now */
  constructor(url, engine, on, now) {
    this.url = url; this.engine = engine; this.on = on; this.now = now;
    /** @type {WebSocket | null} */
    this.ws = null; this.bound = false; this.backoff = 1000; this.closedByUs = false;
    /** @type {string | null} */
    this.rejected = null;         // the code of the last hello refusal, until a hello is accepted
    /** @type {ReturnType<typeof setTimeout> | null} */
    this.retry = null;
    this.replacedByRelay = false;
    /** @type {string | null} the relay's DID once bound, for a peer relay the page keeps */
    this.did = null;
    /** @type {((r: Relay) => void)[]} who waits for a peer relay to bind */
    this.waiting = [];
  }

  connect() {
    this.closedByUs = false; this.replacedByRelay = false;
    const ws = new WebSocket(this.url);
    this.ws = ws; this.bound = false;
    ws.onopen = () => { ws.send(this.engine.hello_frame(this.now())); };
    ws.onmessage = async (ev) => {
      if (!this.bound) {
        const r = this.engine.relay_hello(ev.data, this.now());   // the Endpoint's or the Messenger's: one shape
        if (r.ok === false) { this.on.refused?.(r); ws.close(); return; }
        this.bound = true; this.backoff = 1000; this.rejected = null;
        this.on.bound?.(r);
        return;
      }
      await this.on.frame?.(ev.data);
    };
    ws.onclose = (ev) => {
      const was = this.bound; this.bound = false; this.ws = null;
      // The relay refuses a hello by closing with the reason in the close frame (`transport.hello-rejected: <code>`).
      // A revoked delegation (§7.4) will not verify next time either: stop reconnecting and tell the app.
      const rejected = /^transport\.hello-rejected: (.*)$/.exec(ev.reason || '');
      if (rejected) { this.rejected = rejected[1]; this.on.rejected?.(rejected[1]); if (rejected[1] === 'delegation-revoked') this.closedByUs = true; }
      this.on.closed?.(was);
      // a close() between now and the retry cancels it: a replaced connection must not come back
      if (!this.closedByUs) { this.retry = setTimeout(() => { this.retry = null; if (!this.closedByUs) this.connect(); }, this.backoff); this.backoff = Math.min(this.backoff * 2, 15000); }
    };
    ws.onerror = () => {};
  }

  /** @param {string} frame */
  send(frame) { if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(frame); else this.on.dropped?.(frame); }

  close() { this.closedByUs = true; clearTimeout(this.retry ?? undefined); this.retry = null; this.ws?.close(); }

  /** The relay said `transport.replaced` (verified by the engine): this device bound there on another connection (another
   *  tab, another window), and the relay is closing this one. Do not reconnect: that would replace the other in turn
   *  (§13.2, spec-gap 158). `connect()` again, on the user's word, takes the binding back. */
  replaced() { this.replacedByRelay = true; this.close(); }
}
