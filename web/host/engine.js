// The engine host: wraps the wasm `Endpoint` (verifier + §12 engine + payload builder + first-contact state + the
// call glue) and turns its JSON events into callbacks. Every normative decision is inside the wasm; this file drives
// it with the browser's clock, delivers its frames to the relay, and persists its contact file. The page is the media
// host: it does the media work the call glue asks for (`mediaRequest`) and hands back SDP and local candidates.
//
// Spec: none (infrastructure). The event vocabulary is the engine's (`impl/vectors/README.md`, kind `state`).

export class Engine {
  /** `Endpoint` from the wasm package; `identity` the JSON object; `config` = {first_contact_required, video}. */
  constructor(Endpoint, identity, config, now) {
    this.now = now;
    this.ep = new Endpoint(JSON.stringify(identity), JSON.stringify(config), now());
    // send(frame, meta), frame(text, dir), received(r), emission(e), rejected(code, detail), mediaRequest(m), call(e),
    // resolve(did), changed()
    this.on = {};
    this.timer = null;
  }

  whoami() { return JSON.parse(this.ep.whoami()); }
  state(sid) { if (!sid) return null; const s = JSON.parse(this.ep.session(sid))[sid]; return s ? s.state : null; }
  contacts() { return JSON.parse(this.ep.contacts_snapshot()); }
  requests() { return JSON.parse(this.ep.requests()); }
  contactsFile() { return this.ep.contacts_json(); }
  loadContactsFile(text) { if (text) this.ep.load_contacts(text); }
  newId() { return this.ep.new_id(this.now()); }

  /** A local event by name (`place_call`, `alert`, `accept`, `decline`, `cancel`, `hangup`, `update`, …), with what
   *  its message carries beside it: `sdp` (place_call, accept, update, answer_update), `claims` and `patch` (place_call),
   *  `data` (info). */
  async local(ev) { return this.drive(this.ep.local(JSON.stringify(ev), this.now())); }
  async inbound(frame) { return this.drive(this.ep.inbound(frame, this.now()), frame); }
  async tick() { return this.drive(this.ep.tick(this.now())); }

  /** The other side's recording in `sid` (C§4): `{disclosure, pending, hold_media, …}`, or null. */
  recording(sid) { return JSON.parse(this.ep.recording(sid)); }

  /** Place a call through the call glue: `invite` = {claims?, patch?}. Returns `{session, go}`: the session id at
   *  once (so the page can route it before anything is sent), and `go()`, which drives the first events (the request
   *  for the SDP offer; the invite goes out when the page hands it back). */
  place(to, invite) {
    const r = JSON.parse(this.ep.place(to, JSON.stringify(invite || {}), this.now()));
    return { session: r.session, go: () => this.drive(JSON.stringify(r.events)) };
  }
  /** A call command (`accept`, `screen`, `decline`, `cancel`, `hangup`, `update`, `escalate`, `answer_update`,
   *  `reject_update`, `accept_recording`, `decline_recording`) for `session`. */
  async call(command, session) { return this.drive(this.ep.call(JSON.stringify({ command, session }), this.now())); }
  /** The page's answer to a media request (`{kind: 'offer'|'answer', session, sdp}`), or a local candidate
   *  (`{kind: 'candidate', session, candidate|null}`). */
  async media(result) { return this.drive(this.ep.media(JSON.stringify(result), this.now())); }
  /** The outcome of a `resolve`: the document's text, or '' and why the fetch failed (§8.4). */
  async resolved(did, text, error) { return this.drive(this.ep.resolved(did, text || '', error || '', this.now())); }
  setSeal(on) { this.ep.set_seal(!!on); }
  seal() { return this.ep.seal(); }

  setVideo(v) { this.ep.set_video(!!v); }      // the next offer's descriptors match the SDP (B§2.1)
  /** The video codecs the next offer lists, taken from the SDP's video section so the descriptors match it (B§3.4). */
  setVideoCodecsFromSdp(sdp) {
    const names = { VP8: 'codec:video/vp8', VP9: 'codec:video/vp9', H264: 'codec:video/h264', AV1: 'codec:video/av1' };
    const section = sdp.split(/\r?\nm=/).find((s) => s.startsWith('video'));
    const ids = [];
    for (const m of (section || '').matchAll(/a=rtpmap:\d+ ([A-Za-z0-9]+)\//g)) { const id = names[m[1].toUpperCase()]; if (id && !ids.includes(id)) ids.push(id); }
    this.ep.set_video_codecs(JSON.stringify(ids));
  }

  startTimers() { this.timer ??= setInterval(() => this.tick(), 1000); }   // §12.9

  /** `inFrame`: the inbound frame's text, handed to `on.frame` once the engine accepted it (C§9 evidence: the bytes
   *  exactly as received, never re-serialised, §10.2); every frame sent is handed over as it goes out. */
  async drive(eventsJson, inFrame = null) {
    const events = JSON.parse(eventsJson);
    for (const e of events) {
      if (e.send) { this.on.frame?.(e.send.frame, 'out'); this.on.send?.(e.send.frame, e.send); }
      else if (e.received) { if (inFrame) this.on.frame?.(inFrame, 'in'); await this.on.received?.(e.received); }
      else if (e.emission) await this.on.emission?.(e.emission);
      else if (e.rejected) this.on.rejected?.(e.rejected.code, e.rejected.detail);
      else if (e.media_request) await this.on.mediaRequest?.(e.media_request);
      else if (e.call) await this.on.call?.(e.call);
      else if (e.resolve) this.on.resolve?.(e.resolve.did);
    }
    this.on.changed?.();
    return events;
  }
}
