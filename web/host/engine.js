// The engine host: wraps the wasm `Endpoint` (verifier + §12 engine + payload builder + first-contact state + the
// call glue) and turns its JSON events into callbacks. Every normative decision is inside the wasm; this file drives
// it with the browser's clock, delivers its frames to the relay, and persists its contact file. The page is the media
// host: it does the media work the call glue asks for (`mediaRequest`) and hands back SDP and local candidates.
//
// Spec: none (infrastructure). The event vocabulary is the engine's (`impl/vectors/README.md`, kind `state`).
// @ts-check

/** @typedef {import('../pkg/dsip_wasm.js').CallOut} CallOut */
/** @typedef {import('../pkg/dsip_wasm.js').CoreEvent} CoreEvent */
/** @typedef {import('../pkg/dsip_wasm.js').Emission} Emission */
/** @typedef {import('../pkg/dsip_wasm.js').MediaRequest} MediaRequest */
/** @typedef {import('../pkg/dsip_wasm.js').MediaResult} MediaResult */
/** @typedef {import('../pkg/dsip_wasm.js').CallEvent} CallEvent */
/** @typedef {import('../pkg/dsip_wasm.js').CallCommand} CallCommand */
/** @typedef {import('../pkg/dsip_wasm.js').LocalCommand} LocalCommand */
/** @typedef {import('../pkg/dsip_wasm.js').Invite} Invite */
/** @typedef {import('../pkg/dsip_wasm.js').EndpointConfig} EndpointConfig */
/** @typedef {Extract<CoreEvent, {send: unknown}>['send']} Sent */
/** @typedef {Extract<CoreEvent, {received: unknown}>['received']} Received */

/**
 * What the page listens for. Every handler is optional.
 * @typedef {object} Handlers
 * @property {(frame: string, meta: Sent) => void} [send]
 * @property {(text: string, dir: 'in' | 'out') => void} [frame]
 * @property {(r: Received) => unknown} [received]
 * @property {(e: Emission) => unknown} [emission]
 * @property {(code: string, detail: string) => void} [rejected]
 * @property {(m: MediaRequest) => unknown} [mediaRequest]
 * @property {(e: CallEvent) => unknown} [call]
 * @property {(did: string) => void} [resolve]
 * @property {() => void} [changed]
 */

export class Engine {
  /**
   * @param {typeof import('../pkg/dsip_wasm.js').Endpoint} Endpoint the class from the wasm package
   * @param {object} identity the identity record
   * @param {EndpointConfig} config `{first_contact_required, video, …}`
   * @param {() => number} now the clock, seconds
   */
  constructor(Endpoint, identity, config, now) {
    this.now = now;
    this.ep = new Endpoint(JSON.stringify(identity), config, now());
    /** @type {Handlers} */
    this.on = {};
    /** @type {ReturnType<typeof setInterval> | null} */
    this.timer = null;
  }

  whoami() { return this.ep.whoami(); }
  /** @param {string | null | undefined} sid */
  state(sid) { if (!sid) return null; const s = this.ep.session(sid)[sid]; return s ? s.state : null; }
  contacts() { return this.ep.contacts_snapshot(); }
  requests() { return this.ep.requests(); }
  contactsFile() { return this.ep.contacts_json(); }
  /** @param {string | null | undefined} text */
  loadContactsFile(text) { if (text) this.ep.load_contacts(text); }
  newId() { return this.ep.new_id(this.now()); }

  /** A local event by name (`place_call`, `alert`, `accept`, `decline`, `cancel`, `hangup`, `update`, …), with what
   *  its message carries beside it: `sdp` (place_call, accept, update, answer_update), `claims` and `patch` (place_call),
   *  `data` (info).
   *  @param {LocalCommand} ev */
  async local(ev) { return this.drive(this.ep.local(ev, this.now())); }
  /** @param {string} frame */
  async inbound(frame) { return this.drive(this.ep.inbound(frame, this.now()), frame); }
  async tick() { return this.drive(this.ep.tick(this.now())); }

  /** The other side's recording in `sid` (C§4): `{disclosure, pending, hold_media, …}`, or undefined.
   *  @param {string} sid */
  recording(sid) { return this.ep.recording(sid); }

  /** Place a call through the call glue. Returns `{session, go}`: the session id at once (so the page can route it
   *  before anything is sent), and `go()`, which drives the first events (the request for the SDP offer; the invite
   *  goes out when the page hands it back).
   *  @param {string} to
   *  @param {Invite} [invite] `{claims?, patch?}` */
  place(to, invite) {
    const r = this.ep.place(to, invite || {}, this.now());
    return { session: r.session, go: () => this.drive(r.events) };
  }
  /** A call command (`accept`, `screen`, `decline`, `cancel`, `hangup`, `update`, `escalate`, `answer_update`,
   *  `reject_update`, `accept_recording`, `decline_recording`) for `session`.
   *  @param {Exclude<CallCommand['command'], 'alert' | 'accept_as'>} command
   *  @param {string} session */
  async call(command, session) { return this.drive(this.ep.call({ command, session }, this.now())); }
  /** The page's answer to a media request (`{kind: 'offer'|'answer', session, sdp}`), or a local candidate
   *  (`{kind: 'candidate', session, candidate|null}`).
   *  @param {MediaResult} result */
  async media(result) { return this.drive(this.ep.media(result, this.now())); }
  /** The outcome of a `resolve`: the document's text, or '' and why the fetch failed (§8.4).
   *  @param {string} did
   *  @param {string | null} text
   *  @param {string} [error] */
  async resolved(did, text, error) { return this.drive(this.ep.resolved(did, text || '', error || '', this.now())); }
  /** @param {boolean} on */
  setSeal(on) { this.ep.set_seal(!!on); }
  seal() { return this.ep.seal(); }

  /** @param {boolean} v */
  setVideo(v) { this.ep.set_video(!!v); }      // the next offer's descriptors match the SDP (B§2.1)
  /** The video codecs the next offer lists, taken from the SDP's video section so the descriptors match it (B§3.4).
   *  @param {string} sdp */
  setVideoCodecsFromSdp(sdp) {
    /** @type {Record<string, string>} */
    const names = { VP8: 'codec:video/vp8', VP9: 'codec:video/vp9', H264: 'codec:video/h264', AV1: 'codec:video/av1' };
    const section = sdp.split(/\r?\nm=/).find((s) => s.startsWith('video'));
    /** @type {string[]} */
    const ids = [];
    for (const m of (section || '').matchAll(/a=rtpmap:\d+ ([A-Za-z0-9]+)\//g)) { const id = names[m[1].toUpperCase()]; if (id && !ids.includes(id)) ids.push(id); }
    this.ep.set_video_codecs(ids);
  }

  startTimers() { this.timer ??= setInterval(() => this.tick(), 1000); }   // §12.9

  /** `inFrame`: the inbound frame's text, handed to `on.frame` once the engine accepted it (C§9 evidence: the bytes
   *  exactly as received, never re-serialised, §10.2); every frame sent is handed over as it goes out.
   *  @param {CallOut[]} events
   *  @param {string | null} [inFrame] */
  async drive(events, inFrame = null) {
    for (const e of events) {
      if ('send' in e) { this.on.frame?.(e.send.frame, 'out'); this.on.send?.(e.send.frame, e.send); }
      else if ('received' in e) { if (inFrame) this.on.frame?.(inFrame, 'in'); await this.on.received?.(e.received); }
      else if ('emission' in e) await this.on.emission?.(e.emission);
      else if ('rejected' in e) this.on.rejected?.(e.rejected.code, e.rejected.detail);
      else if ('media_request' in e) await this.on.mediaRequest?.(e.media_request);
      else if ('call' in e) await this.on.call?.(e.call);
      else if ('resolve' in e) this.on.resolve?.(e.resolve.did);
    }
    this.on.changed?.();
    return events;
  }
}
