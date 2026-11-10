// node test.mjs — no dependencies, no browser.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import * as P from './security.js';
const {createGate, createOwner} = P;

// The bundle is unchanged, and the page can only load its own code and talk to the relays.
assert.equal(createHash('sha256').update(readFileSync('vendor/trystero-nostr.mjs')).digest('hex'), 'e2afd1bb76618e8187a3904e54f7c556e652bb3e9d9d388193fec270ca59f874');
const html = readFileSync('index.html', 'utf8'), csp = html.match(/Content-Security-Policy" content="([^"]+)"/)[1];
assert.ok(csp.startsWith("default-src 'none'") && !csp.includes('unsafe'));
assert.deepEqual(csp.match(/wss:\/\/[^ ;]+/g), P.RELAYS);
assert.ok(!/<script(?![^>]*\bsrc=)/.test(html) && !/<style/.test(html));

// Parsers reject anything malformed and copy only known fields.
const id = 'a'.repeat(24);
for (const bad of [null, 42, 'x', [], {}, {t: '__proto__', id: '__proto__', i: 0}, {t: 'A'.repeat(24), id, i: 0}]) {
  for (const parse of [P.parseGet, P.parseStop, P.parseChunk, P.parseOffers]) assert.equal(parse(bad), null);
}
assert.equal(P.parseChunk({t: id, i: 1.5}), null);
assert.equal(P.parseChunk({t: id, i: -1}), null);
assert.deepEqual(P.parseGet({t: id, id, evil: 1}), {t: id, id});
assert.equal(P.parseOffers({n: 'a', f: [{id, n: 'x', s: 1}, {id, n: 'y', s: 1}]}), null);
assert.equal(P.parseOffers({n: 'a', f: [{id, n: '../\u202etxt.exe', s: 1}]}).f[0].n, '_txt.exe');
assert.equal(P.safeName('...'), 'file');
assert.equal(P.safeName('a/b:c'), 'a_b_c');
assert.equal(P.parseChat('   '), null);
assert.equal(P.parseChat(5), null);
assert.equal(P.parseChat('x'.repeat(P.MAX_CHAT + 1)), null);
assert.equal(P.parseChat(' a\u202eb '), 'ab');

// Sizes.
assert.deepEqual([P.chunkCount(0), P.chunkCount(1), P.chunkCount(P.CHUNK), P.chunkCount(P.CHUNK + 1)], [0, 1, 1, 2]);
assert.deepEqual([P.chunkLen(P.CHUNK + 1, 0), P.chunkLen(P.CHUNK + 1, 1), P.chunkLen(P.CHUNK, 0)], [P.CHUNK, 1, P.CHUNK]);

// Gate over a fake network: outsiders get nothing and are ignored until the creator approves them.
const memory = () => { const m = new Map(); return {getItem: k => m.get(k) ?? null, setItem: (k, v) => m.set(k, v)}; };
const wait = () => new Promise(ok => setTimeout(ok, 60));
const net = new Map(), seenAs = new Map();  // 'viewer:peer' -> whose DTLS certificate that connection really has
const print = owner => ({sdp: `v=0\r\na=fingerprint:sha-256 ${owner}\r\n`});
function fakeRoom(id) {
  const room = {id, links: new Set(), actions: new Map(), getPeers: () => Object.fromEntries([...room.links].map(p => [p, {
    currentLocalDescription: print(id), currentRemoteDescription: print(seenAs.get(id + ':' + p) || p),
  }])),
    makeAction(name) {
      const a = {async send(d, o = {}) {
        for (const p of o.target ? [].concat(o.target) : room.links) setTimeout(() => net.get(p).actions.get(name)?.onMessage?.(d, {peerId: id}));
      }};
      room.actions.set(name, a);
      return a;
    }};
  net.set(id, room);
  return room;
}
const hostStore = memory(), hostPub = await createOwner(hostStore);
assert.ok(hostPub);
async function peer(id, ls) {
  const room = fakeRoom(id), joined = [], on = {join: p => joined.push(p), leave() {}, pending() {}, member() {}};
  const gate = await createGate({room, selfId: id, hostPub, ls, on});
  const got = [], action = gate.room.makeAction('x');
  action.onMessage = d => got.push(d);
  gate.start();
  return {id, room, gate, got, action, joined};
}
const H = await peer('H', hostStore), G = await peer('G', memory()), X = await peer('X', memory());
assert.ok(H.gate.isHost && !G.gate.isHost && H.gate.isMember() && !G.gate.isMember());
for (const [a, b] of [[H, G], [H, X], [G, X]]) { a.room.links.add(b.id); b.room.links.add(a.id); a.room.onPeerJoin(b.id); b.room.onPeerJoin(a.id); }
await wait();
await H.action.send('before');
await X.action.send('from-outsider');
await wait();
assert.deepEqual([G.got, X.got, H.got], [[], [], []]);
G.gate.knock('Gi');
await wait();
assert.deepEqual(H.gate.pending().map(r => r.name), ['Gi']);
assert.match(G.gate.code, /^[0-9a-f]{10}$/);
assert.equal(H.gate.pending()[0].code, G.gate.code);
await H.gate.admit('G');
await wait();
assert.ok(G.gate.isMember() && !X.gate.isMember());
await H.action.send('after');
await wait();
assert.deepEqual([G.got, X.got], [['after'], []]);
assert.deepEqual(H.joined, ['G']);

// An attacker between two members declares each one's id to the other: valid hellos must not pass through.
const H2 = await peer('H2', hostStore);
seenAs.set('G:H2', 'attacker');
seenAs.set('H2:G', 'attacker');
G.room.links.add('H2'); H2.room.links.add('G'); G.room.onPeerJoin('H2'); H2.room.onPeerJoin('G');
await wait();
assert.deepEqual([H2.joined, G.joined.includes('H2')], [[], false]);
await assert.rejects(createGate({room: fakeRoom('B'), selfId: 'B', hostPub: 'not-a-key', ls: memory(), on: {}}));
console.log('ok');
