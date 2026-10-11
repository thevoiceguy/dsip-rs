// The relay connection: one WebSocket, `hello` first, the relay's `hello` verified (its `in_reply_to` must be our
// id: anti-splicing), then frames both ways; reconnects with backoff.
//
// Spec: §13.2 (ws/1.0, hello first, capabilities), §20.5 (anti-splicing). The verification of the relay's hello
// is the engine's (`relay_hello`); this file only moves bytes and keeps the socket alive.

export class Relay {
  /** `engine` is the wasm Endpoint; `on` = {bound(relayInfo), frame(text), closed(wasBound), refused(r), rejected(code), dropped(frame)}. */
  constructor(url, engine, on, now) {
    this.url = url; this.engine = engine; this.on = on; this.now = now;
    this.ws = null; this.bound = false; this.backoff = 1000; this.closedByUs = false;
    this.rejected = null;         // the code of the last hello refusal, until a hello is accepted
  }

  connect() {
    this.closedByUs = false;
    const ws = new WebSocket(this.url);
    this.ws = ws; this.bound = false;
    ws.onopen = () => { ws.send(this.engine.hello_frame(this.now())); };
    ws.onmessage = async (ev) => {
      if (!this.bound) {
        const r = JSON.parse(this.engine.relay_hello(ev.data, this.now()));
        if (!r.ok) { this.on.refused?.(r); ws.close(); return; }
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
      if (!this.closedByUs) { setTimeout(() => this.connect(), this.backoff); this.backoff = Math.min(this.backoff * 2, 15000); }
    };
    ws.onerror = () => {};
  }

  send(frame) { if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(frame); else this.on.dropped?.(frame); }

  close() { this.closedByUs = true; this.ws?.close(); }
}
