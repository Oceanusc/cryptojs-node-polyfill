const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const api = require('../dist');
const { createRuntime } = require('../test-support/runtime.cjs');

test('randomBytes / UUID 正常工作，零长度调用不需要随机源', () => {
  assert.equal(api.randomBytes().length, 32);
  assert.equal(api.randomBytes(65537).length, 65537);
  assert.match(api.randomUUID(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  const browser = createRuntime().load();
  assert.equal(browser.randomBytes(0).length, 0);
  assert.equal(browser.getRandomValues(new Uint8Array()).length, 0);
});

test('getRandomValues 支持所有整型数组并保持原视图和边界', () => {
  for (const Type of [Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array,
    Int32Array, Uint32Array, BigInt64Array, BigUint64Array]) {
    const backing = new Uint8Array(40).fill(0xa5);
    const view = new Type(backing.buffer, 8, 2);
    assert.equal(api.getRandomValues(view), view);
    assert.deepEqual(backing.subarray(0, 8), new Uint8Array(8).fill(0xa5));
    assert.deepEqual(backing.subarray(8 + view.byteLength), new Uint8Array(32 - view.byteLength).fill(0xa5));
  }
  const foreign = vm.runInNewContext('new Uint16Array(3)');
  assert.equal(api.getRandomValues(foreign), foreign);
});

test('getRandomValues 拒绝伪造品牌、浮点数和非视图，并限制到 65536 字节', () => {
  const spoof = { [Symbol.toStringTag]: 'Uint8Array', buffer: new ArrayBuffer(8), byteLength: 8, byteOffset: 0 };
  const float = new Float32Array(2);
  Object.defineProperty(float, Symbol.toStringTag, { value: 'Uint8Array' });
  for (const input of [spoof, float, new Float64Array(2), new DataView(new ArrayBuffer(8)), [], null]) {
    assert.throws(() => api.getRandomValues(input), TypeError);
  }
  assert.equal(api.getRandomValues(new Uint8Array(65536)).length, 65536);
  assert.throws(() => api.getRandomValues(new Uint8Array(65537)), { name: 'QuotaExceededError' });
});

test('没有安全随机源时导入和摘要仍可用，随机 API 明确失败', () => {
  const runtime = createRuntime({}, 'Math.random = () => { throw new Error("Math.random must not be used"); };');
  const browser = runtime.load();
  assert.equal(browser.sha256('abc'), api.sha256('abc'));
  assert.throws(() => browser.randomBytes(1), /secure random source|安全随机源/i);
  assert.throws(() => browser.randomUUID(), /secure random source|安全随机源/i);
  assert.throws(() => new browser.CryptoRng(), /secure random source|安全随机源/i);
});

test('原生 Web Crypto 不被覆盖，导入不收集熵，捕获原始 receiver', () => {
  let calls = 0;
  const native = { getRandomValues(bytes) { assert.equal(this, native); calls++; bytes.fill(0xab); return bytes; } };
  const original = native.getRandomValues;
  const runtime = createRuntime({ crypto: native });
  const browser = runtime.load();
  assert.equal(calls, 0);
  assert.equal(native.getRandomValues, original);
  assert.equal(native.randomBytes, undefined);
  runtime.context.crypto = {};
  assert.deepEqual(Array.from(browser.randomBytes(3)), [0xab, 0xab, 0xab]);
});

test('Web Crypto randomBytes 按 65536 字节分块', () => {
  const sizes = [];
  const browser = createRuntime({ crypto: { getRandomValues(bytes) { sizes.push(bytes.length); bytes.fill(7); } } }).load();
  const bytes = browser.randomBytes(131073);
  assert.deepEqual(sizes, [65536, 65536, 1]);
  assert.equal(bytes.length, 131073);
  assert.ok(bytes.every((byte) => byte === 7));
});

test('setRandomSource 支持同步宿主安全随机源，重置后禁止弱随机兜底', () => {
  const browser = createRuntime().load();
  browser.setRandomSource((bytes) => { bytes.fill(9); });
  assert.deepEqual(Array.from(browser.randomBytes(4)), [9, 9, 9, 9]);
  assert.equal(new browser.CryptoRng().generate(32).length, 32);
  browser.setRandomSource(null);
  assert.throws(() => browser.randomBytes(1), /secure random source|安全随机源/i);
  assert.throws(() => browser.setRandomSource(42), { name: 'TypeError' });
  browser.setRandomSource(async () => {});
  assert.throws(() => browser.randomBytes(1), /synchronous|同步/i);
});

test('全局 crypto 及其方法只读时不会阻断导入，其它缺失方法仍可补齐', () => {
  const runtime = createRuntime({}, 'Object.defineProperty(globalThis, "crypto", { value: undefined, writable: false });');
  assert.equal(typeof runtime.load().sha256, 'function');
  const partial = {};
  Object.defineProperty(partial, 'getRandomValues', { value: undefined, writable: false });
  const browser = createRuntime({ crypto: partial }).load();
  assert.equal(partial.randomUUID, browser.randomUUID);
  browser.installGlobalCrypto();
  assert.equal(partial.randomUUID, browser.randomUUID);
});

test('randomBytes 回调异步执行，并通过回调报告随机源异常', async () => {
  for (const generate of [api.randomBytes, createRuntime().load().randomBytes]) {
    let sync = true;
    const done = new Promise((resolve, reject) => {
      generate(4, (err, bytes) => {
        try { assert.equal(sync, false); assert.ok(err ? err.message : bytes.length === 4); resolve(); } catch (error) { reject(error); }
      });
    });
    sync = false;
    await done;
  }
  await new Promise((resolve, reject) => api.randomBytes((err, bytes) => {
    try { assert.equal(err, null); assert.equal(bytes.length, 32); resolve(); } catch (error) { reject(error); }
  }));
});

test('randomBytes 及时校验长度和回调，不尝试超大分配', async () => {
  for (const size of [-1, NaN, Infinity, 1.5, 2 ** 31]) assert.throws(() => api.randomBytes(size), RangeError);
  assert.throws(() => api.randomBytes(1, 'invalid'), TypeError);
  await new Promise((resolve, reject) => api.randomBytes(-1, (err, bytes) => {
    try { assert.equal(err.name, 'RangeError'); assert.equal(bytes.length, 0); resolve(); } catch (error) { reject(error); }
  }));
});

test('没有 Node 的真实 CryptoJS 可通过全局注入使用宿主随机源', () => {
  const runtime = createRuntime();
  const browser = runtime.load();
  browser.setRandomSource((bytes) => { bytes.fill(0x24); });
  assert.equal(runtime.cryptoJs().lib.WordArray.random(8).toString(), '2424242424242424');
  browser.setRandomSource(null);
  assert.throws(() => runtime.cryptoJs().lib.WordArray.random(4), /random/i);
});

test('缺少 queueMicrotask 时回调正常降级，宿主异常只回调一次', async () => {
  const browser = createRuntime({ queueMicrotask: undefined }).load();
  browser.setRandomSource(() => { throw new Error('host unavailable'); });
  let calls = 0;
  await new Promise((resolve, reject) => browser.randomBytes(4, (err, bytes) => {
    try { calls++; assert.match(err.message, /host unavailable/); assert.equal(bytes.length, 0); resolve(); } catch (error) { reject(error); }
  }));
  assert.equal(calls, 1);
  assert.throws(() => browser.rsaEncrypt('message', 'key'), /Node/);
});
