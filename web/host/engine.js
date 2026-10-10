// The engine host: wraps the wasm `Endpoint` (verifier + §12 engine + payload builder + first-contact state) and
// turns its JSON events into callbacks. Every normative decision is inside the wasm; this file drives it with the
// browser's clock, delivers its frames to the relay, and persists its contact file.
//
// Spec: none (infrastructure). The event vocabulary is the engine's (`impl/vectors/README.md`, kind `state`).

export class Engine {
  /** `Endpoint` from the wasm package; `identity` the JSON object; `config` = {first_contact_required, video}. */
  constructor(Endpoint, identity, config, now) {
    this.now = now;
    this.ep = new Endpoint(JSON.stringify(identity), JSON.stringify(config), now());
    this.on = {};                 // send(frame, meta), received(r), emission(e), rejected(code, detail), changed()
    this.timer = null;
  }

  whoami() { return JSON.parse(this.ep.whoami()); }
  state(sid) { const s = JSON.parse(this.ep.session(sid))[sid]; return s ? s.state : null; }
  contacts() { return JSON.parse(this.ep.contacts_snapshot()); }
  requests() { return JSON.parse(this.ep.requests()); }
  contactsFile() { return this.ep.contacts_json(); }
  loadContactsFile(text) { if (text) this.ep.load_contacts(text); }
  newId() { return this.ep.new_id(this.now()); }

  /** A local event by name (`place_call`, `alert`, `accept`, `decline`, `cancel`, `hangup`, `update`, …). */
  async local(ev) { return this.drive(this.ep.local(JSON.stringify(ev), this.now())); }
  async inbound(frame) { return this.drive(this.ep.inbound(frame, this.now())); }
  async tick() { return this.drive(this.ep.tick(this.now())); }

  setSdp(sdp) { this.ep.set_sdp(sdp ?? undefined); }
  setInfoData(data) { this.ep.set_info_data(JSON.stringify(data)); }

  startTimers() { this.timer ??= setInterval(() => this.tick(), 1000); }   // §12.9

  async drive(eventsJson) {
    const events = JSON.parse(eventsJson);
    for (const e of events) {
      if (e.send) this.on.send?.(e.send.frame, e.send);
      else if (e.received) await this.on.received?.(e.received);
      else if (e.emission) await this.on.emission?.(e.emission);
      else if (e.rejected) this.on.rejected?.(e.rejected.code, e.rejected.detail);
    }
    this.on.changed?.();
    return events;
  }
}
