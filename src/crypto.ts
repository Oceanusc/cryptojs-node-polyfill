import { collectEntropy, fillSecureRandom } from './entropy';
import { getNodeCrypto } from './node-crypto';
import { runInMicrotask } from './globals';

const nativeNodeCrypto = getNodeCrypto();
const RANDOM_CHUNK_BYTES = 65536;
const MAX_RANDOM_BYTES = 0x7fffffff;
const INTEGER_ARRAY_TAGS = new Set([
  'Int8Array', 'Uint8Array', 'Uint8ClampedArray', 'Int16Array', 'Uint16Array',
  'Int32Array', 'Uint32Array', 'BigInt64Array', 'BigUint64Array',
]);
const typedArrayTag = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag,
)!.get!;

/** 使用真实 TypedArray 内部品牌，支持跨 realm，并拒绝 Symbol.toStringTag 伪装。 */
function isIntegerTypedArray(value: unknown): boolean {
  return ArrayBuffer.isView(value) && INTEGER_ARRAY_TAGS.has(typedArrayTag.call(value));
}

function quotaExceededError(gotBytes: number): Error {
  const err = new Error(
    `The length of the ArrayBuffer ${gotBytes} exceeds the maximum of ${RANDOM_CHUNK_BYTES} bytes`,
  );
  err.name = 'QuotaExceededError';
  return err;
}

type RandomBytesCallback = (err: Error | null, bytes: Uint8Array) => void;

/** 支持默认 32 字节、指定长度、单回调和长度加回调；回调总是延后执行。 */
function randomBytes(length?: number): Uint8Array;
function randomBytes(length: number, callback: RandomBytesCallback): void;
function randomBytes(callback: RandomBytesCallback): void;
function randomBytes(
  lengthOrCallback?: number | RandomBytesCallback,
  callback?: RandomBytesCallback,
): Uint8Array | void {
  if (typeof lengthOrCallback === 'function') {
    callback = lengthOrCallback;
    lengthOrCallback = undefined;
  }
  if (callback !== undefined && typeof callback !== 'function') {
    throw new TypeError('callback 必须是函数');
  }
  const size = lengthOrCallback === undefined ? 32 : lengthOrCallback;
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_RANDOM_BYTES) {
    const err = new RangeError(`size 必须是 0 到 ${MAX_RANDOM_BYTES} 之间的整数`);
    if (!callback) throw err;
    runInMicrotask(() => callback(err, new Uint8Array(0)));
    return;
  }
  if (!callback) return collectEntropy(size);

  const done = callback;
  if (typeof nativeNodeCrypto?.randomBytes === 'function') {
    // Node 使用真正的异步随机字节接口，避免在主线程生成完后再模拟异步。
    nativeNodeCrypto.randomBytes(size, (err, bytes) => done(err, bytes ?? new Uint8Array(0)));
    return;
  }
  runInMicrotask(() => {
    let bytes: Uint8Array;
    try {
      bytes = collectEntropy(size);
    } catch (error) {
      done(error instanceof Error ? error : new Error(String(error)), new Uint8Array(0));
      return;
    }
    // 用户回调异常不能被误判为随机源失败、导致二次调用。
    done(null, bytes);
  });
}

/** Web Crypto 整型 TypedArray 随机填充，保留视图偏移、长度和原对象。 */
function getRandomValues<T extends ArrayBufferView>(array: T): T {
  if (!isIntegerTypedArray(array)) {
    throw new TypeError('getRandomValues 仅支持整型 TypedArray（不支持 Float / DataView）');
  }
  if (array.byteLength > RANDOM_CHUNK_BYTES) throw quotaExceededError(array.byteLength);
  fillSecureRandom(new Uint8Array(array.buffer, array.byteOffset, array.byteLength));
  return array;
}

function randomUUID(): string {
  const bytes = collectEntropy(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export const cryptoMethods = { getRandomValues, randomUUID, randomBytes } as const;
export { getRandomValues, randomBytes, randomUUID };
