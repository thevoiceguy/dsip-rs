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
  setVideo(v) { this.ep.set_video(!!v); }      // the next offer's descriptors match the SDP (B§2.1)
  /** The video codecs the next offer lists, taken from the SDP's video section so the descriptors match it (B§3.4). */
  setVideoCodecsFromSdp(sdp) {
    const names = { VP8: 'codec:video/vp8', VP9: 'codec:video/vp9', H264: 'codec:video/h264', AV1: 'codec:video/av1' };
    const section = sdp.split(/\r?\nm=/).find((s) => s.startsWith('video'));
    const ids = [];
    for (const m of (section || '').matchAll(/a=rtpmap:\d+ ([A-Za-z0-9]+)\//g)) { const id = names[m[1].toUpperCase()]; if (id && !ids.includes(id)) ids.push(id); }
    this.ep.set_video_codecs(JSON.stringify(ids));
  }
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
