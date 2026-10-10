// WebRTC for one call: the browser's RTCPeerConnection, the local stream, and the candidate buffering the binding
// requires. Candidates gathered before the session is ACTIVE wait; once active they ride in signed `info`
// (the app sends them through the engine). Remote candidates that arrive before the remote description is set wait
// too.
//
// Spec: WebRTC Media Binding B§2–B§6 (SDP in `transports[].sdp`, one answer per offer), §12.12 (candidates in
// `info`, ACTIVE-only), §14.1 (no media before a signed answer), §14.4 (screening: receive only).

export class Media {
  constructor(iceServers, on) {
    this.pc = new RTCPeerConnection({ iceServers });
    this.on = on;                       // {candidate(entry|null), track(stream), state(str)}
    this.localStream = null;
    this.pendingRemote = [];
    this.pc.onicecandidate = ({ candidate }) => {
      // Firefox marks the end of each m-section with an empty candidate string; the binding carries real candidates
      // (`^candidate:`, B§ Appendix A) and one end_of_candidates, which the final null event supplies.
      if (candidate && !candidate.candidate) return;
      this.on.candidate?.(candidate
        ? { candidate: candidate.candidate, sdp_mid: candidate.sdpMid ?? '0', sdp_m_line_index: candidate.sdpMLineIndex ?? 0 }
        : null);
    };
    this.pc.ontrack = (ev) => this.on.track?.(ev.streams[0]);
    this.pc.onconnectionstatechange = () => this.on.state?.(this.pc.connectionState);
  }

  async capture(video) {
    this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video });
    this.localStream.getTracks().forEach((t) => this.pc.addTrack(t, this.localStream));
    return this.localStream;
  }

  /** An offer to send (§16.3). */
  async offer() {
    const o = await this.pc.createOffer();
    await this.pc.setLocalDescription(o);
    return o.sdp;
  }

  /** Answer a remote offer; with `screening`, receive only (§14.4). */
  async answer(offerSdp, screening) {
    await this.pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
    if (screening) this.pc.getTransceivers().forEach((t) => { t.direction = 'recvonly'; });
    const a = await this.pc.createAnswer();
    await this.pc.setLocalDescription(a);
    await this.flushRemote();
    return a.sdp;
  }

  async acceptAnswer(sdp) {
    await this.pc.setRemoteDescription({ type: 'answer', sdp });
    await this.flushRemote();
  }

  async addRemoteCandidate(c) {
    const cand = { candidate: c.candidate, sdpMid: c.sdp_mid, sdpMLineIndex: c.sdp_m_line_index };
    if (this.pc.remoteDescription) await this.pc.addIceCandidate(cand).catch(() => {});
    else this.pendingRemote.push(cand);
  }

  async flushRemote() {
    const batch = this.pendingRemote; this.pendingRemote = [];
    for (const c of batch) await this.pc.addIceCandidate(c).catch(() => {});
  }

  /** Add a camera track for an `update` (escalation to video). */
  async addVideo() {
    if (this.localStream?.getVideoTracks().length) return;
    const v = await navigator.mediaDevices.getUserMedia({ video: true });
    v.getTracks().forEach((t) => { this.pc.addTrack(t, v); this.localStream?.addTrack(t); });
    if (!this.localStream) this.localStream = v;
  }

  /** Leave screening (§14.4 step 3): capture audio (and video if asked) and send on the transceivers that were
   *  receive-only; the caller then sees an `update` with `answered_by: "user"`. */
  async unscreen(video) {
    const s = await navigator.mediaDevices.getUserMedia({ audio: true, video });
    for (const track of s.getTracks()) {
      const t = this.pc.getTransceivers().find((x) => x.receiver.track?.kind === track.kind);
      if (t) { t.direction = 'sendrecv'; await t.sender.replaceTrack(track); } else this.pc.addTrack(track, s);
    }
    this.localStream = s;
    return s;
  }

  /** Inbound RTP packets received so far (for tests and the call screen). */
  async inboundPackets() {
    let n = 0;
    const stats = await this.pc.getStats();
    stats.forEach((s) => { if (s.type === 'inbound-rtp') n += s.packetsReceived || 0; });
    return n;
  }

  close() {
    this.pc.close();
    this.localStream?.getTracks().forEach((t) => t.stop());
    this.localStream = null;
  }
}
