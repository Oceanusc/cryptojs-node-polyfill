const test = require('node:test');
const assert = require('node:assert/strict');
const { CryptoRng } = require('../dist');

test('Hash_DRBG 通过 NIST CAVP SHA-256 no-reseed COUNT=0 向量', () => {
  // NIST 官方 drbgtestvectors.zip / drbgvectors_no_reseed.zip / Hash_DRBG.rsp
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
  // seed_material = EntropyInput || Nonce；无 personalization / additional_input。
  const seed = Buffer.from('a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb8581f9317517276e06e9607ddbcbcc2e', 'hex');
  const rng = new CryptoRng(seed);
  rng.generate(128);
  assert.equal(Buffer.from(rng.generate(128)).toString('hex'),
    'd3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80daaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df');
});

test('显式 seed 完整参与派生，不忽略第 55 字节之后的内容', () => {
  const a = new Uint8Array(80).fill(1);
  const b = a.slice();
  b[79] = 2;
  assert.notDeepEqual(new CryptoRng(a).generate(32), new CryptoRng(b).generate(32));
  assert.deepEqual(new CryptoRng(a).generate(32), new CryptoRng(a).generate(32));
  assert.throws(() => new CryptoRng(new Uint8Array()), /seed/i);
});

test('Hash_DRBG 限制请求长度，达到 reseed 上限必须重新播种', () => {
  const rng = new CryptoRng(new Uint8Array(32).fill(1));
  for (const length of [-1, 0.1, NaN, Infinity, 65537]) assert.throws(() => rng.generate(length), RangeError);
  assert.equal(rng.generate(0).length, 0);
  rng.reseedCounter = 2 ** 32;
  const next = rng.generate(1);
  const other = new CryptoRng(new Uint8Array(32).fill(1));
  other.generate(0);
  other.reseedCounter = 0;
  other.generate(1);
  assert.notDeepEqual(rng.V, other.V);
  assert.equal(next.length, 1);
  rng.reseedCounter = 2 ** 48 + 1;
  assert.throws(() => rng.generate(1), /reseed|重新播种/i);
});
