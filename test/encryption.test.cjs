const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const vm = require('node:vm');
const CryptoJS = require('crypto-js');
const api = require('../dist');

for (const algorithm of ['md5', 'sha1', 'sha256', 'sha512']) {
  test(`${algorithm} 与 Node 对照，支持 Unicode、二进制子视图和跨 realm 输入`, () => {
    for (const input of ['你好🌍', new Uint8Array([0, 255, 128, 1]).subarray(1, 3),
      vm.runInNewContext('new Uint8Array([0, 255, 128])')]) {
      assert.equal(api[algorithm](input), crypto.createHash(algorithm).update(input).digest('hex'));
    }
  });
}

for (const [method, algorithm] of [['hmacSha1', 'sha1'], ['hmacSha256', 'sha256']]) {
  test(`${method} 与 Node 对照`, () => {
    const message = vm.runInNewContext('new Uint8Array([0, 255, 128])');
    const key = vm.runInNewContext('new Uint8Array([1, 2, 3])');
    assert.equal(api[method](message, key), crypto.createHmac(algorithm, key).update(message).digest('hex'));
  });
}

test('Base64 / Hex / UTF-8 往返与二进制视图转换', () => {
  const bytes = vm.runInNewContext('new Uint8Array([9, 0, 255, 128, 9]).subarray(1, 4)');
  assert.equal(api.bytesToHex(bytes), '00ff80');
  assert.equal(api.bytesToBase64(bytes), 'AP+A');
  assert.deepEqual(api.base64ToBytes('AP+A'), Uint8Array.of(0, 255, 128));
  assert.deepEqual(api.hexDecode('00FF80'), Uint8Array.of(0, 255, 128));
  assert.equal(api.base64Decode(api.base64Encode('中文🌍')), '中文🌍');
  assert.equal(api.utf8Decode(api.utf8Encode('中文🌍')), '中文🌍');
  assert.equal(api.base64Decode('YQ'), 'a');
  assert.equal(api.base64Decode('YWI'), 'ab');
  assert.equal(api.base64Decode(''), '');
  assert.equal(api.hexDecode('').length, 0);
});

test('畸形 Hex / Base64 必须报错，不静默填零或截断', () => {
  for (const text of ['a', 'zz', '0g', '0x00', 'ab cd']) assert.throws(() => api.hexToBytes(text), TypeError);
  for (const text of ['A', '!!!!', 'Y=Q=', 'YQ===', 'YQ==garbage', 'YWJj=', 'YR==', 'YWJ=']) {
    assert.throws(() => api.base64ToBytes(text), TypeError);
    assert.throws(() => api.base64Decode(text), TypeError);
  }
  assert.throws(() => api.sha256(new Float32Array(2)), TypeError);
  assert.throws(() => api.sha256(null), TypeError);
});

for (const size of [16, 24, 32]) for (const mode of ['CBC', 'ECB']) {
  test(`AES-${size * 8}-${mode} 与 Node / CryptoJS 互操作`, () => {
    const key = Buffer.alloc(size, 0x42);
    const iv = mode === 'CBC' ? Buffer.alloc(16, 0x24) : null;
    const options = { mode, keyEncoding: 'hex', iv: iv?.toString('hex'), ivEncoding: 'hex' };
    for (const message of ['', 'hello 中文🌍', 'x'.repeat(32)]) for (const output of ['base64', 'hex']) {
      const cipher = crypto.createCipheriv(`aes-${size * 8}-${mode.toLowerCase()}`, key, iv);
      const expected = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]).toString(output);
      assert.equal(api.aesEncrypt(message, key.toString('hex'), { ...options, output }), expected);
      assert.equal(api.aesDecrypt(expected, key.toString('hex'), { ...options, output }), message);
      const native = CryptoJS.AES.encrypt(message, CryptoJS.enc.Hex.parse(key.toString('hex')), {
        mode: CryptoJS.mode[mode], iv: iv ? CryptoJS.enc.Hex.parse(iv.toString('hex')) : undefined,
      }).ciphertext.toString(CryptoJS.enc[output === 'hex' ? 'Hex' : 'Base64']);
      assert.equal(native, expected);
    }
  });
}

test('AES 校验模式、编码、key / IV 长度与密文分组', () => {
  const key = '1234567890abcdef';
  const options = { iv: key };
  for (const invalid of [{ mode: 'CTR' }, { output: 'binary' }, { keyEncoding: 'bogus' }, { ivEncoding: 'bogus' }]) {
    assert.throws(() => api.aesEncrypt('message', key, { ...options, ...invalid }), TypeError);
    assert.throws(() => api.aesDecrypt('00', key, { ...options, ...invalid }), TypeError);
  }
  assert.throws(() => api.aesEncrypt('message', 'short', options), TypeError);
  assert.throws(() => api.aesEncrypt('message', key), TypeError);
  assert.throws(() => api.aesEncrypt('message', key, { iv: 'short' }), TypeError);
  for (const text of ['', '00', '00'.repeat(17)]) {
    assert.throws(() => api.aesDecrypt(text, key, { ...options, output: 'hex' }), /ciphertext|密文/i);
  }
});

test('AES 严格验证整个 PKCS#7 填充，拒绝 CryptoJS 会静默接受的异常块', () => {
  const key = Buffer.alloc(16, 1);
  const iv = Buffer.alloc(16, 2);
  for (const malformed of [Buffer.alloc(16), Buffer.alloc(16, 17), Buffer.from([...Buffer.alloc(14, 1), 1, 2])]) {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv).setAutoPadding(false);
    const ciphertext = Buffer.concat([cipher.update(malformed), cipher.final()]).toString('base64');
    assert.throws(() => api.aesDecrypt(ciphertext, key.toString('hex'), {
      iv: iv.toString('hex'), keyEncoding: 'hex', ivEncoding: 'hex',
    }), /padding|填充/i);
  }
});

test('RSA 默认 OAEP-SHA256 往返，并与 Node 互操作', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const encrypted = api.rsaEncrypt('秘密🌍', publicKey);
  assert.equal(api.rsaDecrypt(encrypted, privateKey), '秘密🌍');
  assert.equal(crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256' }, Buffer.from(encrypted, 'base64')).toString(), '秘密🌍');
  const native = crypto.publicEncrypt({ key: publicKey, oaepHash: 'sha256' }, Buffer.from('native')).toString('base64');
  assert.equal(api.rsaDecrypt(native, privateKey, { padding: 'oaep' }), 'native');
  assert.throws(() => api.rsaEncrypt('message', publicKey, { padding: 'bogus' }), TypeError);
  assert.throws(() => api.rsaDecrypt('!!!!', privateKey), TypeError);
});
