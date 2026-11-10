// P2P file drop and chat. Read top to bottom: helpers, files, chat, room.
// The link is `#<secret>.<creator public key>`; the fragment never reaches any server.
import {joinRoom, selfId} from './vendor/trystero-nostr.mjs';
import {
  RELAYS, CHUNK, MAX_FILE, MAX_OFFERS, NAME_MAX, PEER_NAME_MAX, MAX_CHAT,
  parseOffers, parseGet, parseStop, parseChunk, parseChat, chunkCount, chunkLen,
  createGate, createOwner,
} from './security.js';

const SECRET_BYTES = 16, LINK = /^#([0-9a-f]{32})\.([A-Za-z0-9_-]{87})$/;
const STALL_MS = 20000, TICK_MS = 3000, MAX_UPLOADS_PER_PEER = 4, REVOKE_MS = 60000, MAX_CHAT_LINES = 200;
const TTL_OPTIONS = [[10, '10 min'], [60, '1 h'], [1440, '24 h'], [0, 'No limit']], TTL_DEFAULT_MIN = 60;

// ---- Helpers

const $ = id => document.getElementById(id);
const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
const randId = () => hex(crypto.getRandomValues(new Uint8Array(12)));
const post = (action, data, opts) => action.send(data, opts).catch(() => {});  // peers come and go
const toast = text => { $('tip').textContent = text; };

// Builds DOM. Strings become text nodes, so peer data can never become markup.
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) k in el ? (el[k] = v) : el.setAttribute(k, v);
  el.append(...kids.flat().filter(k => k !== null && k !== undefined));
  return el;
}
const button = (label, onclick, className = 'btn') => h('button', {className, onclick}, label);

function fmtBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  for (; n >= 1024 && i < units.length - 1; i++) n /= 1024;
  return (i ? n.toFixed(1) : n) + ' ' + units[i];
}
const fmtClock = ms => new Date(ms).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});

let myName = 'Anon';
const names = new Map();  // peer -> self-chosen name
const label = peer => (names.get(peer) || 'Anon') + ' #' + peer.slice(0, 4);  // the tag tells apart equal names

// ---- Files
// The sharer announces a list, the receiver asks for a file, the sharer sends its chunks in order.
// A gap or a silence fails the download; the receiver can remove it and ask again.

// Writes to disk where the browser allows it, otherwise keeps the file in memory.
// Must run first in a click handler, or the browser refuses the save dialog.
async function openSink(name) {
  if (window.showSaveFilePicker) {
    const out = await (await showSaveFilePicker({suggestedName: name})).createWritable();
    return {write: u8 => out.write(u8), close: () => out.close(), abort: () => out.abort()};
  }
  const parts = [];
  return {
    write: async u8 => { parts.push(new Blob([u8])); },
    close: async () => {
      const url = URL.createObjectURL(new Blob(parts));
      h('a', {href: url, download: name}).click();
      setTimeout(() => URL.revokeObjectURL(url), REVOKE_MS);
    },
    abort: async () => { parts.length = 0; },
  };
}

function startFiles(root, room) {
  const list = room.makeAction('f-list'), get = room.makeAction('f-get');
  const stop = room.makeAction('f-stop'), bin = room.makeAction('f-bin');
  const mine = new Map();       // id -> file I share
  const offers = new Map();     // peer -> files it shares
  const uploads = new Map();    // 'peer:transfer' -> running upload
  const downloads = new Map();  // transfer -> download; status is '' while receiving

  // -- Sharing

  function announce(target) {
    const f = [...mine.values()].map(m => ({id: m.id, n: m.n, s: m.file.size}));
    post(list, {n: myName.slice(0, PEER_NAME_MAX), f}, target ? {target} : undefined);
  }
  function share(picked) {
    const minutes = +ttl.value;
    for (const file of picked) {
      if (mine.size >= MAX_OFFERS || file.size > MAX_FILE) { toast('Could not add'); continue; }
      const id = randId();
      const exp = minutes ? Date.now() + minutes * 60e3 : null;
      mine.set(id, {id, file, exp, n: file.name.slice(0, NAME_MAX) || 'file'});
    }
    announce();
    draw();
  }
  function cutUpload(key) {
    uploads.get(key).ac.abort();
    uploads.delete(key);
  }
  function unshare(id) {
    mine.delete(id);
    for (const [key, up] of uploads) {
      if (up.id === id) { post(stop, {t: up.t}, {target: up.peer}); cutUpload(key); }
    }
    announce();
    draw();
  }
  async function upload(m, peer, t) {
    const key = peer + ':' + t, ac = new AbortController(), total = chunkCount(m.file.size);
    uploads.set(key, {ac, peer, t, id: m.id});
    draw();
    try {
      for (let i = 0; i < total && !ac.signal.aborted; i++) {
        const data = new Uint8Array(await m.file.slice(i * CHUNK, (i + 1) * CHUNK).arrayBuffer());
        await bin.send(data, {target: peer, metadata: {t, i}, signal: ac.signal});
      }
    } catch {
      if (!ac.signal.aborted) post(stop, {t}, {target: peer});
    }
    if (uploads.get(key)?.ac === ac) { uploads.delete(key); draw(); }
  }
  get.onMessage = (raw, {peerId: peer}) => {
    const g = parseGet(raw);
    if (!g) return;
    const m = mine.get(g.id);
    const busy = [...uploads.values()].filter(u => u.peer === peer).length >= MAX_UPLOADS_PER_PEER;
    const refused = !m || isExpired(m) || busy || uploads.has(peer + ':' + g.t);
    if (refused) post(stop, {t: g.t}, {target: peer}); else upload(m, peer, g.t);
  };
  const isExpired = m => m.exp !== null && Date.now() >= m.exp;

  // -- Receiving

  async function download(peer, offer) {
    let sink;
    try {
      sink = await openSink(offer.n);
    } catch (e) {
      if (e?.name !== 'AbortError') toast('Could not save');
      return draw();
    }
    const total = chunkCount(offer.s), t = randId();
    const d = {t, peer, offer, sink, total, next: 0, last: Date.now(), writes: Promise.resolve(), status: '', bar: null};
    downloads.set(t, d);
    draw();
    if (total) post(get, {t, id: offer.id}, {target: peer}); else finish(d);
  }
  function fail(d, status, tellPeer = true) {
    if (d.status) return;
    d.status = status;
    d.sink.abort().catch(() => {});
    if (tellPeer) post(stop, {t: d.t}, {target: d.peer});
    draw();
  }
  async function finish(d) {
    d.status = 'Saving';
    draw();
    try { await d.sink.close(); d.status = 'Done'; } catch { d.status = 'Could not save'; }
    draw();
  }
  bin.onMessage = (data, {peerId: peer, metadata}) => {
    const m = parseChunk(metadata), d = m && downloads.get(m.t);
    if (!d || d.peer !== peer || d.status) return;
    const valid = m.i === d.next && m.i < d.total
      && data instanceof Uint8Array && data.byteLength === chunkLen(d.offer.s, m.i);
    if (!valid) return fail(d, 'Interrupted');
    d.next++;
    d.last = Date.now();
    if (d.bar) d.bar.value = d.next;
    const isLast = d.next === d.total;
    d.writes = d.writes.then(async () => {
      if (d.status) return;
      await d.sink.write(data);
      if (isLast) await finish(d);
    }).catch(() => fail(d, 'Could not save'));
  };

  // -- Both directions

  stop.onMessage = (raw, {peerId: peer}) => {
    const s = parseStop(raw);
    if (!s) return;
    const d = downloads.get(s.t), key = peer + ':' + s.t;
    if (d?.peer === peer) fail(d, 'Interrupted', false);
    if (uploads.has(key)) { cutUpload(key); draw(); }
  };
  list.onMessage = (raw, {peerId: peer}) => {
    const parsed = parseOffers(raw);
    if (!parsed) return;
    offers.set(peer, parsed.f);
    if (!names.has(peer)) names.set(peer, parsed.n);  // a peer cannot rename itself mid-session
    draw();
  };
  function peerLeft(peer) {
    offers.delete(peer);
    names.delete(peer);
    for (const [key, up] of uploads) if (up.peer === peer) cutUpload(key);
    for (const d of downloads.values()) if (d.peer === peer) fail(d, 'Disconnected', false);
    draw();
  }
  setInterval(() => {
    for (const d of downloads.values()) if (!d.status && Date.now() - d.last > STALL_MS) fail(d, 'Interrupted');
    for (const m of [...mine.values()]) if (isExpired(m)) { unshare(m.id); toast('File expired'); }
  }, TICK_MS);

  // -- Screen

  const rows = h('div', {className: 'col'});
  const ttl = h('select', {'aria-label': 'Expires in'},
    TTL_OPTIONS.map(([min, text]) => h('option', {value: min, selected: min === TTL_DEFAULT_MIN}, text)));
  const picker = h('input', {type: 'file', multiple: true, hidden: true, onchange() {
    share([...picker.files]);
    picker.value = '';
  }});
  const row = (name, sub, action, bar) => h('div', {className: 'panel col'},
    h('div', {className: 'row'}, h('div', {className: 'name'}, name, h('small', null, sub)), action), bar);

  function mineRow(m) {
    const sending = [...uploads.values()].some(u => u.id === m.id);
    const sub = fmtBytes(m.file.size) + (m.exp ? ' · expires ' + fmtClock(m.exp) : '') + (sending ? ' · sending' : '');
    return row(m.n, sub, button('Remove', () => unshare(m.id)));
  }
  function offerRow(peer, o) {
    const receive = e => { e.target.disabled = true; download(peer, o); };
    return row(o.n, `${fmtBytes(o.s)} · ${label(peer)}`, button('Receive', receive, 'btn big'));
  }
  function downloadRow(d) {
    if (d.status) {
      d.bar = null;
      return row(d.offer.n, d.status, button('Remove', () => { downloads.delete(d.t); draw(); }));
    }
    d.bar = h('progress', {max: d.total, value: d.next});
    return row(d.offer.n, fmtBytes(d.offer.s), button('Cancel', () => fail(d, 'Canceled')), d.bar);
  }
  function draw() {
    const active = [...downloads.values()];
    const available = [...offers].flatMap(([peer, files]) => files
      .filter(o => !active.some(d => d.peer === peer && d.offer.id === o.id))
      .map(o => offerRow(peer, o)));
    rows.replaceChildren(...[...mine.values()].map(mineRow), ...available, ...active.map(downloadRow));
  }

  addEventListener('dragover', e => e.preventDefault());
  addEventListener('drop', e => { e.preventDefault(); share([...e.dataTransfer.files]); });
  root.replaceChildren(
    h('div', {className: 'panel col'},
      h('div', {className: 'row'},
        button('Choose files', () => picker.click(), 'btn big'), picker,
        h('label', {className: 'row'}, 'Expires in', ttl)),
      h('small', null, 'You can also drop them here. Keep this tab open.')),
    rows);
  draw();
  return {peerJoined: announce, peerLeft};
}

// ---- Chat, in memory only. The sender's label comes from the connection, never from the message.

function startChat(root, room) {
  const action = room.makeAction('chat');
  const log = h('div', {className: 'panel log'});
  const input = h('input', {placeholder: 'Message', maxLength: MAX_CHAT, 'aria-label': 'Message'});

  function add(who, text) {
    log.append(h('div', null, h('b', null, who + ' '), text));
    if (log.childElementCount > MAX_CHAT_LINES) log.firstChild.remove();
    log.scrollTop = log.scrollHeight;
  }
  action.onMessage = (raw, {peerId: peer}) => {
    const text = parseChat(raw);
    if (!text) return;
    add(label(peer), text);
    if (box.hidden) toggle.textContent = `Chat (${++unread})`;
  };
  function send(e) {
    e.preventDefault();
    const text = parseChat(input.value);
    if (!text) return;
    input.value = '';
    add('You', text);
    post(action, text);
  }
  const form = h('form', {className: 'row', onsubmit: send}, input, h('button', {className: 'btn big'}, 'Send'));
  const box = h('div', {className: 'col', hidden: true}, log, form);
  let unread = 0;
  const toggle = button('Chat', () => {
    box.hidden = !box.hidden;
    unread = 0;
    toggle.textContent = 'Chat';
    if (box.hidden) return;
    log.scrollTop = log.scrollHeight;  // a hidden log can't scroll, so catch up on opening
    input.focus();
  });
  root.replaceChildren(h('div', {className: 'row'}, toggle), box);
}

// ---- Room: read or create the link, then show the door or the app.

function refuse(text) {
  $('root').replaceChildren(h('div', {className: 'panel'}, text));
  $('st').textContent = 'No access';
}
async function linkFromUrl() {
  if (location.hash) {
    const m = location.hash.match(LINK);  // a hash that doesn't match is refused: there is no open mode
    return m && {secret: m[1], hostPub: m[2]};
  }
  const secret = hex(crypto.getRandomValues(new Uint8Array(SECRET_BYTES))), hostPub = await createOwner();
  history.replaceState(null, '', '#' + secret + '.' + hostPub);
  return {secret, hostPub};
}
async function openRoom(secret) {
  // The room name is a hash, so the secret itself is only ever used as the signaling password.
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('room:' + secret));
  const name = hex(new Uint8Array(digest)).slice(0, 32);
  return joinRoom({appId: 'p2p-filedrop', password: secret, relayConfig: {urls: RELAYS}}, name);
}

async function main() {
  addEventListener('hashchange', () => location.reload());
  $('cp').onclick = async () => {
    await navigator.clipboard?.writeText(location.href);
    toast('Link copied');
  };
  const link = await linkFromUrl();
  if (!link) { $('new').hidden = false; return refuse('Invalid link'); }

  const peers = new Set();
  let filesApp = null;
  const showCount = () => { $('st').textContent = peers.size ? `${peers.size + 1} connected` : 'Waiting for people'; };

  function enter() {
    const filesEl = h('div'), chatEl = h('div', {className: 'col'});
    $('root').replaceChildren(filesEl, chatEl);
    filesApp = startFiles(filesEl, gate.room);
    startChat(chatEl, gate.room);
    showCount();
  }
  function askToEnter() {
    const say = h('div', null, 'This room needs approval');
    const input = h('input', {placeholder: 'Your name', maxLength: PEER_NAME_MAX, 'aria-label': 'Your name'});
    const go = button('Ask to enter', () => {
      myName = input.value.trim() || myName;
      gate.knock(myName);
      input.remove();
      go.remove();
      say.textContent = 'Waiting for approval';
      say.after(h('small', null, `Your code: ${gate.code}. Tell it to the room creator.`));
    }, 'btn big');
    $('root').replaceChildren(h('div', {className: 'panel col door'}, say, input, go));
    $('st').textContent = 'No access';
  }
  function drawRequests() {
    $('reqs').replaceChildren(...gate.pending().map(r => h('div', {className: 'panel row'},
      h('div', {className: 'name'}, r.name, h('small', null, 'Code ' + r.code)),
      button('Accept', () => gate.admit(r.peer), 'btn big'),
      button('Reject', () => gate.deny(r.peer)))));
  }

  const gate = await createGate({
    room: await openRoom(link.secret),
    selfId,
    hostPub: link.hostPub,
    on: {
      join(peer) { peers.add(peer); showCount(); filesApp.peerJoined(peer); },
      leave(peer) { peers.delete(peer); showCount(); filesApp.peerLeft(peer); },
      pending: drawRequests,
      member: enter,
    },
  });
  $('new').hidden = gate.isHost;
  if (gate.isMember()) enter(); else askToEnter();
  gate.start();
}
main().catch(() => refuse('Could not open'));
