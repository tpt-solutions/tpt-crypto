// Usage: node smoke.cjs <dir containing tpt_crypto_wasm.js from wasm-bindgen --target nodejs>
const t = require(process.argv[2] + "/tpt_crypto_wasm.js");
const hex = (u) => Buffer.from(u).toString("hex");
const assert = require("assert");
assert.strictEqual(hex(t.hash(new TextEncoder().encode("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
// HMAC-SHA256 RFC 4231 test 2
assert.strictEqual(hex(t.hmac(new TextEncoder().encode("Jefe"), new TextEncoder().encode("what do ya want for nothing?"))), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
const key = t.generateKey(); assert.strictEqual(key.length, 32);
const sealed = t.seal(key, new Uint8Array([1,2,3]), new Uint8Array([9]));
assert.deepStrictEqual(Array.from(t.open(key, sealed, new Uint8Array([9]))), [1,2,3]);
assert.throws(() => t.open(key, sealed, new Uint8Array([8])));
assert.throws(() => t.seal(new Uint8Array(31), new Uint8Array(0), new Uint8Array(0)), /must be 32 bytes/);
// Ed25519 RFC 8032 test 1 (empty message)
const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
assert.strictEqual(hex(t.ed25519PublicKey(seed)), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const sig = t.ed25519Sign(seed, new Uint8Array(0));
assert.strictEqual(hex(sig), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
t.ed25519Verify(t.ed25519PublicKey(seed), new Uint8Array(0), sig);
assert.throws(() => t.ed25519Verify(t.ed25519PublicKey(seed), new Uint8Array([1]), sig));
// HKDF-SHA256 RFC 5869 test 1
const okm = t.hkdfDerive(Buffer.alloc(22, 0x0b), Buffer.from("000102030405060708090a0b0c","hex"), Buffer.from("f0f1f2f3f4f5f6f7f8f9","hex"), 42);
assert.strictEqual(hex(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
assert.strictEqual(t.randomBytes(16).length, 16);
console.log("wasm smoke test: all assertions passed");
