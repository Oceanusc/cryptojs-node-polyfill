import { getNodeCrypto } from './node-crypto';
import { getGlobalObject } from './globals';

/** 同步填满传入视图的宿主 CSPRNG；不得使用 Math.random 或返回 Promise。 */
export type RandomSource = (bytes: Uint8Array) => void;

const nodeCrypto = getNodeCrypto();
// 同时保存方法与 receiver，防止全局注入后递归或对象替换导致 Illegal invocation。
const nativeCrypto = getGlobalObject().crypto as Crypto | undefined;
const nativeGetRandomValues = nativeCrypto?.getRandomValues;
let hostRandomSource: RandomSource | null = null;

/** 给无原生 Web Crypto 的小程序 / RN 接入同步、密码学安全的宿主随机源。 */
export function setRandomSource(source: RandomSource | null): void {
  if (source !== null && typeof source !== 'function') {
    throw new TypeError('random source 必须是同步函数或 null');
  }
  hostRandomSource = source;
}

/** 直接填充已有视图，原生路径不初始化 DRBG，也不分配中间随机字节数组。 */
export function fillSecureRandom(bytes: Uint8Array): void {
  if (bytes.length === 0) return;
  if (typeof nodeCrypto?.randomFillSync === 'function') {
    nodeCrypto.randomFillSync(bytes);
    return;
  }
  if (typeof nodeCrypto?.randomBytes === 'function') {
    bytes.set(nodeCrypto.randomBytes(bytes.length));
    return;
  }
  if (typeof nativeGetRandomValues !== 'function' && !hostRandomSource) {
    throw new Error('缺少安全随机源；请先安装原生 Web Crypto，或通过 setRandomSource 接入同步宿主 CSPRNG');
  }
  for (let offset = 0; offset < bytes.length; offset += 65536) {
    const chunk = bytes.subarray(offset, Math.min(offset + 65536, bytes.length));
    if (typeof nativeGetRandomValues === 'function') {
      nativeGetRandomValues.call(nativeCrypto, chunk);
    } else {
      const result: unknown = hostRandomSource!(chunk);
      if (result != null && typeof (result as { then?: unknown }).then === 'function') {
        // 消费错误使用 async 随机源产生的拒绝，避免额外的 unhandledRejection。
        Promise.resolve(result).catch(() => {});
        throw new TypeError('random source 必须同步填充字节，不能返回 Promise');
      }
    }
  }
}

/** 仅从密码学安全的随机源收集熵；哈希和时间采样不能补救弱随机源。 */
export function collectEntropy(length = 48): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0 || length > 0x7fffffff) {
    throw new RangeError('length 必须是 0 到 2147483647 之间的整数');
  }
  const bytes = new Uint8Array(length);
  fillSecureRandom(bytes);
  return bytes;
}
