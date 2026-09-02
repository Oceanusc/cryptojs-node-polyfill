import { cryptoMethods, getRandomValues, randomBytes, randomUUID } from './crypto';
import { CryptoRng } from './rng';
import { getGlobalObject } from './globals';

// 全局注入：向全局对象补齐缺失的 Crypto 实例方法，便于 crypto-js 等库直接使用
installGlobalCrypto();

/**
 * 若全局对象缺失 crypto 或缺少必要方法，则注入本包实现的 Crypto 实例。
 * 重复调用是安全幂等的：已注入则跳过。
 */
function installGlobalCrypto(): void {
  const g = getGlobalObject();
  const existing = g.crypto as (Record<string, unknown> & Crypto) | undefined;

  if (existing) {
    // 只补齐缺失的方法，不覆盖已有实现。
    // 用 try/catch 包裹：部分 WebKit 的 crypto 实例可能只读或不可扩展，
    // 直接赋值会抛 TypeError 并阻断整个模块加载，注入失败不应影响正常使用。
    try {
      if (typeof existing.getRandomValues !== 'function') {
        existing.getRandomValues = cryptoMethods.getRandomValues;
      }
      if (typeof existing.randomUUID !== 'function') {
        existing.randomUUID = cryptoMethods.randomUUID as Crypto['randomUUID'];
      }
    } catch {
      // 只读/不可扩展场景：放弃补方法，保持原生现状
    }
    return; // randomBytes 不属于 Web Crypto 标准方法，保持现状，由命名导出提供
  }

  // 无任何 crypto 对象：注入当前实例（含 Node 风格 randomBytes）
  g.crypto = cryptoMethods;
}

// 具名导出：供显式引用（不依赖全局副作用）
export { getRandomValues, randomBytes, randomUUID, cryptoMethods } from './crypto';
export { CryptoRng } from './rng';
export { installGlobalCrypto };

// 基于 CryptoJS 的加密封装层（差异化能力集）
export {
  sha1,
  sha256,
  sha512,
  md5,
  hmacSha1,
  hmacSha256,
  base64Encode,
  base64Decode,
  bytesToBase64,
  base64ToBytes,
  hexEncode,
  hexDecode,
  bytesToHex,
  hexToBytes,
  utf8Encode,
  utf8Decode,
  aesEncrypt,
  aesDecrypt,
  rsaEncrypt,
  rsaDecrypt,
} from './encryption';
export type { AesOptions, RsaOptions, RsaPadding } from './encryption';

export default cryptoMethods;