import { CryptoRng } from './rng';
import { getNodeCrypto } from './node-crypto';
import { getGlobalObject, runInMicrotask } from './globals';

// 模块加载时先捕获原生能力引用，避免后续自身覆盖 crypto 造成递归
const nativeNodeCrypto = getNodeCrypto();
const nativeGetRandomValues = (
  getGlobalObject().crypto as Crypto | undefined
)?.getRandomValues;

// 底层随机源：优先原生（Node 内置 crypto 或浏览器 Web Crypto），否则退化为 CryptoJS 实现的 RNG
const rng = new CryptoRng();

// Web Crypto 规范：getRandomValues 单次填充上限 65536 字节，分块填充统一复用
const RANDOM_CHUNK_BYTES = 65536;

// 受支持整型 TypedArray 的品牌标记（Object.prototype.toString 结果）。
// 用品牌检查而非 instanceof：跨 realm（iframe/worker）传入的实例，instanceof 会失败。
const INTEGER_ARRAY_TAGS = new Set([
  '[object Int8Array]',
  '[object Uint8Array]',
  '[object Uint8ClampedArray]',
  '[object Int16Array]',
  '[object Uint16Array]',
  '[object Int32Array]',
  '[object Uint32Array]',
]);

/** 判断某值是否为可参与 getRandomValues 的整型 TypedArray（跨 realm 安全）。 */
function isIntegerTypedArray(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  return INTEGER_ARRAY_TAGS.has(Object.prototype.toString.call(value));
}

/**
 * 生成安全随机字节（优先原生、退化 CryptoJS）。
 * 始终返回 Uint8Array（Node 语义下为 Buffer，此处统一为 Uint8Array）。
 */
function secureRandomBytes(length: number): Uint8Array {
  if (typeof nativeNodeCrypto?.randomBytes === 'function') {
    // Node 环境：直接命中内置安全实现
    const nodeCrypto = nativeNodeCrypto as { randomBytes(size: number): Uint8Array };
    return nodeCrypto.randomBytes(length);
  }

  const out = new Uint8Array(length);
  // 原生 getRandomValues 与 CryptoRng 单次均有 65536 字节上限，
  // 而 Node 风格 randomBytes 语义不限长，统一按块填充规避差异
  for (let offset = 0; offset < length; offset += RANDOM_CHUNK_BYTES) {
    const take = Math.min(RANDOM_CHUNK_BYTES, length - offset);
    fillRandomChunk(out.subarray(offset, offset + take));
  }
  return out;
}

/** 向单个分块填充随机字节：优先原生 Web Crypto，兜底 CryptoJS CSPRNG。 */
function fillRandomChunk(chunk: Uint8Array): void {
  if (typeof nativeGetRandomValues === 'function') {
    nativeGetRandomValues.call(getGlobalObject().crypto, chunk);
    return;
  }
  chunk.set(rng.generate(chunk.length));
}

/**
 * 构造符合 Web Crypto 规范的 QuotaExceededError。
 * 以普通 Error 承载同名属性，避免在无 DOMException 的端上直接引用。
 */
function quotaExceededError(gotBytes: number): Error {
  const err = new Error(
    `The length of the ArrayBuffer ${gotBytes} exceeds the maximum of ${RANDOM_CHUNK_BYTES} bytes`,
  );
  err.name = 'QuotaExceededError';
  return err;
}

type RandomBytesCallback = (err: Error | null, bytes: Uint8Array) => void;

/**
 * Node 风格 randomBytes：支持同步（无回调）与异步（带回调/单回调）三种形式。
 */
function randomBytes(length?: number): Uint8Array;
function randomBytes(length: number, callback: RandomBytesCallback): void;
function randomBytes(callback: RandomBytesCallback): void;
function randomBytes(
  lengthOrCallback?: number | RandomBytesCallback,
  callback?: RandomBytesCallback,
): Uint8Array | void {
  // 单回调形式：randomBytes(cb)，未显式传 size 时默认 32 字节
  if (typeof lengthOrCallback === 'function') {
    callback = lengthOrCallback;
    lengthOrCallback = undefined;
  }
  const size = lengthOrCallback ?? 32; // 未传 size 时默认 32 字节

  if (!Number.isInteger(size) || size < 0) {
    const err = new RangeError(
      `The argument 'size' is invalid. Received ${size}`,
    );
    if (callback) {
      // 经统一微任务调度器延迟，跨端（小程序/RN）不会裸用 queueMicrotask
      runInMicrotask(() => callback(err, new Uint8Array(0)));
      return undefined;
    }
    throw err;
  }

  const bytes = secureRandomBytes(size);

  if (callback) {
    // 延迟到下一个微任务，保持与 Node 异步回调一致的时序（跨端降级后仍可工作）
    runInMicrotask(() => callback(null, bytes));
    return undefined;
  }
  return bytes;
}

/**
 * Web Crypto 语义的 getRandomValues：向整型 TypedArray 填充安全随机字节。
 * 支持带 byteOffset/byteLength 的部分视图，端序保持原生。
 */
function getRandomValues<T extends ArrayBufferView>(array: T): T {
  // 兼容性检查：必须属于整型 TypedArray（不支持 Float / BigInt / DataView）
  if (!isIntegerTypedArray(array)) {
    throw new TypeError(
      'getRandomValues 仅支持整型 TypedArray（不支持 Float / BigInt / DataView）',
    );
  }

  const view = array as unknown as {
    buffer: ArrayBuffer;
    byteOffset: number;
    byteLength: number;
  };

  if (view.byteLength === 0) {
    return array; // 空数组直接返回
  }

  // 遵循 Web Crypto 规范：单次填充上限 65536 字节，超出抛 QuotaExceededError
  if (view.byteLength > RANDOM_CHUNK_BYTES) {
    throw quotaExceededError(view.byteLength);
  }

  const byteView = new Uint8Array(
    view.buffer,
    view.byteOffset,
    view.byteLength,
  );
  const bytes = secureRandomBytes(view.byteLength);
  byteView.set(bytes);
  return array;
}

function randomUUID(): string {
  const bytes = secureRandomBytes(16);

  // version = 4：第 7 字节高 4 位置 0100
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  // variant：第 9 字节高 2 位置 10
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-` +
    `${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
  );
}

/** 供全局注入使用的 Crypto 实例方法集合。 */
export const cryptoMethods = {
  getRandomValues,
  randomUUID,
  randomBytes,
} as const;

export { getRandomValues, randomBytes, randomUUID };