// Everything that protects the room from its peers. No DOM here.
// Part 1 checks what peers send. Part 2 decides who is allowed in.

// ---- Part 1: limits, and a parser per message type. A parser returns clean data or null.

export const RELAYS = ['wss://nos.lol', 'wss://relay.primal.net', 'wss://nostr.mom'];  // also in the CSP
export const CHUNK = 256 * 1024, MAX_FILE = 2 ** 42, MAX_OFFERS = 200;
export const NAME_MAX = 200, PEER_NAME_MAX = 40, MAX_CHAT = 2000;

const isId = x => typeof x === 'string' && /^[0-9a-f]{24}$/.test(x);
const isObj = x => !!x && typeof x === 'object' && !Array.isArray(x);
const isText = (x, max) => typeof x === 'string' && x.length > 0 && x.length <= max;
const isSize = x => Number.isSafeInteger(x) && x >= 0 && x <= MAX_FILE;
// Direction overrides can make `exe.txt` display as something else.
const clean = s => s.replace(/[\u202a-\u202e\u2066-\u2069]/g, '');

export function safeName(name) {
  const s = clean(name)
    .replace(/[\\/:*?"<>|\u0000-\u001f\u007f]/g, '_')
    .replace(/^[.\s]+|[.\s]+$/g, '')
    .slice(0, NAME_MAX);
  return s || 'file';
}

export function parseOffers(x) {
  if (!isObj(x) || !isText(x.n, PEER_NAME_MAX) || !Array.isArray(x.f) || x.f.length > MAX_OFFERS) return null;
  if (!x.f.every(e => isObj(e) && isId(e.id) && isText(e.n, NAME_MAX) && isSize(e.s))) return null;
  if (new Set(x.f.map(e => e.id)).size < x.f.length) return null;
  return {n: clean(x.n).trim() || 'Anon', f: x.f.map(e => ({id: e.id, n: safeName(e.n), s: e.s}))};
}
export const parseGet = x => (isObj(x) && isId(x.t) && isId(x.id) ? {t: x.t, id: x.id} : null);
export const parseStop = x => (isObj(x) && isId(x.t) ? {t: x.t} : null);
export const parseChunk = x => (isObj(x) && isId(x.t) && isSize(x.i) ? {t: x.t, i: x.i} : null);
export const parseChat = x => (isText(x, MAX_CHAT) ? clean(x).trim() || null : null);

export const chunkCount = size => Math.ceil(size / CHUNK);
export const chunkLen = (size, i) => Math.min(CHUNK, size - i * CHUNK);

// ---- Part 2: the door.
// The creator's public key is in the link. Approving someone means signing their public key
// (a "cert"). Every member checks certs itself, so nobody has to trust the relays or each other.

const BUFFER_MS = 5000, MAX_BUFFERED = 200, MAX_PENDING = 5, MAX_KEY_FIELD = 200;
const ALG = {name: 'ECDSA', namedCurve: 'P-256'}, SIG = {name: 'ECDSA', hash: 'SHA-256'};
const subtle = crypto.subtle;
const bytes = s => new TextEncoder().encode(s);

const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const importPub = s => subtle.importKey('raw', unb64(s), ALG, false, ['verify']);

async function sign(jwk, text) {
  const key = await subtle.importKey('jwk', jwk, ALG, false, ['sign']);
  return b64(await subtle.sign(SIG, key, bytes(text)));
}
async function verify(pub, sig, text) {
  try { return await subtle.verify(SIG, await importPub(pub), unb64(sig), bytes(text)); } catch { return false; }
}
async function newKeys() {
  const k = await subtle.generateKey(ALG, true, ['sign', 'verify']);
  return {pub: b64(await subtle.exportKey('raw', k.publicKey)), priv: await subtle.exportKey('jwk', k.privateKey), cert: null};
}

const certText = pub => 'cert:' + pub;
// Bound to both ids and this connection's fingerprints, so it can't be forwarded.
const helloText = (from, to, fromPrint, toPrint) => `hello:${from}>${to}:${fromPrint}>${toPrint}`;
const storageKey = hostPub => 'p2p-filedrop:' + hostPub.slice(0, 16);
const isKeyField = x => isText(x, MAX_KEY_FIELD);

// 40 bits of the key's hash, for people to compare outside the app.
const keyCode = async pub => [...new Uint8Array(await subtle.digest('SHA-256', bytes(pub)))].slice(0, 5)
  .map(b => b.toString(16).padStart(2, '0')).join('');

// Creates the room owner's keys and returns the public key that goes in the link.
export async function createOwner(ls = sessionStorage) {
  const id = await newKeys();
  id.cert = await sign(id.priv, certText(id.pub));
  ls.setItem(storageKey(id.pub), JSON.stringify(id));
  return id.pub;
}

// `on` gets: join(peer), leave(peer), pending() when the request list changes, member() when let in.
export async function createGate({room, selfId, hostPub, on, ls = sessionStorage}) {
  await importPub(hostPub);  // a damaged link must fail closed
  const key = storageKey(hostPub);
  let me = JSON.parse(ls.getItem(key));
  if (!me) { me = await newKeys(); ls.setItem(key, JSON.stringify(me)); }

  const isHost = me.pub === hostPub, code = await keyCode(me.pub);
  let member = await verify(hostPub, me.cert, certText(me.pub));
  let myName;
  const connected = new Map();  // peer -> time it connected
  const members = new Set();    // peers whose cert checked out
  const early = new Map();      // peer -> messages waiting for its cert
  const pending = new Map();    // peer -> request to enter (host only)
  const denied = new Set();     // public keys the host rejected

  const hello = room.makeAction('_gh'), admitted = room.makeAction('_ga');

  // DTLS fingerprints of this connection. Peer ids are self-declared; these are not.
  function prints(peer) {
    const pc = room.getPeers()[peer];
    const read = d => d?.sdp?.match(/^a=fingerprint:\s*(\S+ \S+)/m)?.[1].toLowerCase();
    const local = read(pc?.currentLocalDescription), remote = read(pc?.currentRemoteDescription);
    return local && remote ? {local, remote} : null;
  }

  async function sendHello(peer) {
    const p = prints(peer);
    if (!p) return;
    const sig = await sign(me.priv, helloText(selfId, peer, p.local, p.remote));
    hello.send({pub: me.pub, cert: me.cert, name: myName, sig}, {target: peer});
  }
  function welcome(peer) {
    on.join(peer);
    early.get(peer)?.forEach(deliver => deliver());
    early.delete(peer);
  }
  function addMember(peer) {
    if (members.has(peer)) return;
    members.add(peer);
    if (pending.delete(peer)) on.pending();
    if (member) welcome(peer);
  }

  hello.onMessage = async (m, {peerId: peer}) => {
    const p = prints(peer);
    if (!p || !isKeyField(m?.pub)) return;
    if (!await verify(m.pub, m.sig, helloText(peer, selfId, p.remote, p.local))) return;
    const certified = await verify(hostPub, m.cert, certText(m.pub));
    if (!connected.has(peer)) return;  // it left while we were verifying
    if (certified) return addMember(peer);
    if (!isHost || !isKeyField(m.name) || denied.has(m.pub) || members.has(peer)) return;
    const requestCode = await keyCode(m.pub);
    if (!connected.has(peer) || pending.has(peer) || pending.size >= MAX_PENDING) return;  // a request can't change later
    pending.set(peer, {peer, pub: m.pub, name: m.name.slice(0, PEER_NAME_MAX), code: requestCode});
    on.pending();
  };

  admitted.onMessage = async m => {
    if (member || !await verify(hostPub, m?.cert, certText(me.pub))) return;
    me.cert = m.cert;
    member = true;
    on.member();
    members.forEach(welcome);
    [...connected.keys()].forEach(sendHello);
    ls.setItem(key, JSON.stringify(me));
  };

  // A message can arrive just before its sender's hello finishes verifying: it waits briefly.
  function whenMember(peer, deliver) {
    if (member && members.has(peer)) return deliver();
    if (!connected.has(peer) || Date.now() - connected.get(peer) > BUFFER_MS) return;
    const queue = early.get(peer) || [];
    if (queue.length < MAX_BUFFERED) queue.push(deliver);
    early.set(peer, queue);
  }

  // Features only get this object, so anything not listed here cannot reach peers.
  const gatedRoom = {
    makeAction(name) {
      const raw = room.makeAction(name);
      const action = {
        onMessage: null,
        async send(data, opts = {}) {
          if (!member) return;
          const wanted = opts.target === undefined ? [...members] : [].concat(opts.target);
          const target = wanted.filter(p => members.has(p));
          if (target.length) await raw.send(data, {...opts, target});
        },
      };
      raw.onMessage = (data, meta) => whenMember(meta.peerId, () => action.onMessage?.(data, meta));
      return action;
    },
  };

  function peerJoined(peer) {
    connected.set(peer, Date.now());
    sendHello(peer);
  }
  function peerLeft(peer) {
    const wasMember = member && members.has(peer);
    connected.delete(peer);
    members.delete(peer);
    early.delete(peer);
    if (pending.delete(peer)) on.pending();
    if (wasMember) on.leave(peer);
  }

  return {
    room: gatedRoom,
    isHost,
    code,
    isMember: () => member,
    pending: () => [...pending.values()],
    start() {
      room.onPeerJoin = peerJoined;
      room.onPeerLeave = peerLeft;
      Object.keys(room.getPeers()).forEach(peerJoined);
    },
    knock(name) {
      myName = name;
      [...connected.keys()].forEach(sendHello);
    },
    async admit(peer) {
      const request = pending.get(peer);
      if (!request) return;
      const cert = await sign(me.priv, certText(request.pub));
      pending.delete(peer);
      on.pending();
      admitted.send({cert}, {target: peer});
    },
    deny(peer) {
      const request = pending.get(peer);
      if (!request) return;
      denied.add(request.pub);
      pending.delete(peer);
      on.pending();
    },
  };
}
