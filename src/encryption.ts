import CryptoJS from 'crypto-js';
import {
  bytesToWordArray,
  wordArrayToBytes,
  toBytes,
  utf8ToBytes,
  bytesToUtf8,
} from './bytes';
import { getNodeCrypto } from './node-crypto';

const { AES, enc, pad, HmacSHA1, HmacSHA256, MD5, SHA1, SHA256, SHA512 } =
  CryptoJS;

/**
 * 基于 CryptoJS 的常用加密封装层。
 * 提供 AES 对称加解密、消息摘要、HMAC 签名、Base64/Hex 编码转换，
 * 以及（可选）Node 端内置 crypto 的 RSA 公私钥加解密委托。
 * 这是与 polyfill-crypto-methods 形成差异化的核心能力集合。
 */

// ---------------------------------------------------------------------------
// 1. 消息摘要
// ---------------------------------------------------------------------------

/** SHA-1 摘要，返回小写十六进制字符串。 */
export function sha1(input: string | Uint8Array): string {
  return SHA1(bytesToWordArray(toBytes(input))).toString(enc.Hex);
}

/** SHA-256 摘要，返回小写十六进制字符串。 */
export function sha256(input: string | Uint8Array): string {
  return SHA256(bytesToWordArray(toBytes(input))).toString(enc.Hex);
}

/** SHA-512 摘要，返回小写十六进制字符串。 */
export function sha512(input: string | Uint8Array): string {
  return SHA512(bytesToWordArray(toBytes(input))).toString(enc.Hex);
}

/** MD5 摘要，返回小写十六进制字符串。 */
export function md5(input: string | Uint8Array): string {
  return MD5(bytesToWordArray(toBytes(input))).toString(enc.Hex);
}

// ---------------------------------------------------------------------------
// 2. HMAC 签名
// ---------------------------------------------------------------------------

/** 基于 SHA-1 的 HMAC 签名，返回小写十六进制字符串。 */
export function hmacSha1(message: string | Uint8Array, key: string | Uint8Array): string {
  return HmacSHA1(bytesToWordArray(toBytes(message)), bytesToWordArray(toBytes(key))).toString(
    enc.Hex,
  );
}

/** 基于 SHA-256 的 HMAC 签名，返回小写十六进制字符串。 */
export function hmacSha256(message: string | Uint8Array, key: string | Uint8Array): string {
  return HmacSHA256(bytesToWordArray(toBytes(message)), bytesToWordArray(toBytes(key))).toString(
    enc.Hex,
  );
}

// ---------------------------------------------------------------------------
// 3. 编码转换
// ---------------------------------------------------------------------------

/** 输入编码来源。 */
type EncodeSource = 'utf8' | 'hex' | 'base64';

/** 将字符串按指定编码解析为 CryptoJS WordArray。 */
function parseWordArray(input: string, encoding: EncodeSource): CryptoJS.lib.WordArray {
  if (encoding === 'hex') {
    return enc.Hex.parse(input);
  }
  if (encoding === 'base64') {
    return enc.Base64.parse(input);
  }
  return enc.Utf8.parse(input);
}

/** 将 WordArray 按指定编码输出为字符串。 */
function formatWordArray(wa: CryptoJS.lib.WordArray, output: 'base64' | 'hex'): string {
  return output === 'hex' ? wa.toString(enc.Hex) : wa.toString(enc.Base64);
}

/** 字节数组转 Base64 字符串。 */
export function bytesToBase64(bytes: Uint8Array): string {
  return enc.Base64.stringify(bytesToWordArray(bytes));
}

/** Base64 字符串解码为原始字节。 */
export function base64ToBytes(input: string): Uint8Array {
  return wordArrayToBytes(enc.Base64.parse(input));
}

/** 字节数组转小写十六进制字符串。 */
export function bytesToHex(bytes: Uint8Array): string {
  return bytesToWordArray(bytes).toString(enc.Hex);
}

/** 十六进制字符串解码为原始字节。 */
export function hexToBytes(input: string): Uint8Array {
  return wordArrayToBytes(enc.Hex.parse(input));
}

/** Base64 编码（输入可为字符串或字节，输出 Base64 字符串）。 */
export function base64Encode(input: string | Uint8Array): string {
  return bytesToBase64(toBytes(input));
}

/** Base64 解码（输入 Base64 字符串，输出 UTF-8 字符串）。 */
export function base64Decode(input: string): string {
  return enc.Utf8.stringify(enc.Base64.parse(input));
}

/** Hex 编码（输入可为字符串或字节，输出小写十六进制字符串）。 */
export function hexEncode(input: string | Uint8Array): string {
  return bytesToHex(toBytes(input));
}

/** Hex 解码（输入十六进制字符串，输出原始字节）。 */
export function hexDecode(input: string): Uint8Array {
  return hexToBytes(input);
}

/** UTF-8 字符串转字节。 */
export function utf8Encode(input: string): Uint8Array {
  return utf8ToBytes(input);
}

/** 字节转 UTF-8 字符串。 */
export function utf8Decode(input: Uint8Array): string {
  return bytesToUtf8(input);
}

// ---------------------------------------------------------------------------
// 4. AES 对称加解密
// ---------------------------------------------------------------------------

/** AES 相关配置项。 */
export interface AesOptions {
  /** 分组模式，默认 'CBC'。ECB 不需要 IV。 */
  mode?: 'CBC' | 'ECB';
  /** key 字符串的编码方式，默认 'utf8'。 */
  keyEncoding?: EncodeSource;
  /** IV 字符串（CBC 模式必填），编码方式见 ivEncoding。 */
  iv?: string;
  /** IV 字符串的编码方式，默认 'utf8'。 */
  ivEncoding?: EncodeSource;
  /** 密文输出编码，默认 'base64'。 */
  output?: 'base64' | 'hex';
}

/** 校验并解析加密模式。 */
function resolveBlockMode(mode: 'CBC' | 'ECB'): typeof CryptoJS.mode.CBC {
  return mode === 'ECB' ? CryptoJS.mode.ECB : CryptoJS.mode.CBC;
}

/** 合法的 AES 密钥字节长度。 */
const AES_KEY_LENGTHS = [16, 24, 32] as const;

/** 校验密钥字节长度是否为合法的 AES 长度（128/192/256 位）。 */
function assertValidAesKey(keyWa: CryptoJS.lib.WordArray): void {
  if (!(AES_KEY_LENGTHS as readonly number[]).includes(keyWa.sigBytes)) {
    throw new TypeError(
      `AES 密钥长度必须为 ${AES_KEY_LENGTHS.join('/')} 字节，当前为 ${keyWa.sigBytes} 字节`,
    );
  }
}

/** 校验 IV 字节长度是否为 16 字节。 */
function assertValidAesIv(ivWa: CryptoJS.lib.WordArray): void {
  if (ivWa.sigBytes !== 16) {
    throw new TypeError(`AES-CBC 的 IV 长度必须为 16 字节，当前为 ${ivWa.sigBytes} 字节`);
  }
}

/**
 * AES 加密。
 * - key 依据 keyEncoding 解析（utf8/hex/base64），长度必须是 16/24/32 字节；
 * - CBC 模式必须有 iv（依据 ivEncoding 解析）且为 16 字节；ECB 忽略 iv；
 * - 使用 PKCS#7 填充，输出为 Base64（默认）或 Hex。
 */
export function aesEncrypt(plainText: string, key: string, options?: AesOptions): string {
  const { mode = 'CBC', keyEncoding = 'utf8', ivEncoding = 'utf8', output = 'base64' } =
    options ?? {};

  const keyWa = parseWordArray(key, keyEncoding);
  assertValidAesKey(keyWa);

  const isCbc = mode === 'CBC';
  let ivWa: CryptoJS.lib.WordArray | undefined;
  if (isCbc) {
    if (options?.iv === undefined || options.iv === '') {
      throw new TypeError('AES-CBC 模式必须提供 iv');
    }
    ivWa = parseWordArray(options.iv, ivEncoding);
    assertValidAesIv(ivWa);
  }

  const cipherParams = AES.encrypt(enc.Utf8.parse(plainText), keyWa, {
    mode: resolveBlockMode(mode),
    padding: pad.Pkcs7,
    iv: ivWa,
  });

  return formatWordArray(cipherParams.ciphertext, output);
}

/**
 * AES 解密。
 * 与 aesEncrypt 使用完全一致的 key/iv/mode/编码配置，返回明文 UTF-8 字符串。
 */
export function aesDecrypt(
  cipherText: string,
  key: string,
  options?: AesOptions,
): string {
  const { mode = 'CBC', keyEncoding = 'utf8', ivEncoding = 'utf8', output = 'base64' } =
    options ?? {};

  const keyWa = parseWordArray(key, keyEncoding);
  assertValidAesKey(keyWa);

  const isCbc = mode === 'CBC';
  let ivWa: CryptoJS.lib.WordArray | undefined;
  if (isCbc) {
    if (options?.iv === undefined || options.iv === '') {
      throw new TypeError('AES-CBC 模式必须提供 iv');
    }
    ivWa = parseWordArray(options.iv, ivEncoding);
    assertValidAesIv(ivWa);
  }

  const ciphertextWa =
    output === 'hex' ? enc.Hex.parse(cipherText) : enc.Base64.parse(cipherText);

  const bytes = AES.decrypt(
    CryptoJS.lib.CipherParams.create({ ciphertext: ciphertextWa }),
    keyWa,
    {
      mode: resolveBlockMode(mode),
      padding: pad.Pkcs7,
      iv: ivWa,
    },
  );

  return enc.Utf8.stringify(bytes);
}

// ---------------------------------------------------------------------------
// 5. RSA 公私钥加解密（Node 端委托）
// ---------------------------------------------------------------------------
// 说明：CryptoJS 不包含非对称加密；此处的 RSA 委托给 Node 内置 crypto 实现，
// 仅在 Node 环境可用。这是对内置能力的薄封装，而非伪造的 CryptoJS RSA。

/** RSA 填充方式。 */
export type RsaPadding = 'pkcs1' | 'oaep';

/** RSA 加解密配置项。 */
export interface RsaOptions {
  /** 填充方式，默认 'pkcs1'；OAEP 更安全。 */
  padding?: RsaPadding;
  /** OAEP 哈希算法，默认 'sha256'。 */
  oaepHash?: string;
}

/** 根据配置解析 Node 内置加密填充常量。 */
function resolveRsaPadding(padding: RsaPadding): number {
  const constants = getNodeCrypto()?.constants;
  if (padding === 'oaep') {
    return constants?.RSA_PKCS1_OAEP_PADDING ?? 4;
  }
  return constants?.RSA_PKCS1_PADDING ?? 1;
}

/** 组装 Node 加解密参数：oaepHash 仅在 OAEP 填充下有意义，避免冗余传参。 */
function buildRsaCipherOptions(key: string, options?: RsaOptions): Record<string, unknown> {
  const { padding = 'pkcs1', oaepHash = 'sha256' } = options ?? {};
  const nodeOptions: Record<string, unknown> = {
    key,
    padding: resolveRsaPadding(padding),
  };
  if (padding === 'oaep') {
    nodeOptions.oaepHash = oaepHash;
  }
  return nodeOptions;
}

/**
 * RSA 公钥加密（Node 端）。publicKey 为 PEM 公钥字符串，返回 Base64 密文。
 * 仅限 Node 环境；不可用时抛出错误。
 */
export function rsaEncrypt(
  plainText: string,
  publicKey: string,
  options?: RsaOptions,
): string {
  const nodeCrypto = getNodeCrypto();
  if (!nodeCrypto?.publicEncrypt) {
    throw new Error('RSA 加解密仅支持 Node 环境（当前无内置 crypto.publicEncrypt）');
  }
  const encrypted = nodeCrypto.publicEncrypt(
    buildRsaCipherOptions(publicKey, options),
    utf8ToBytes(plainText),
  );
  return BufferToString(encrypted).toString('base64');
}

/**
 * RSA 私钥解密（Node 端）。privateKey 为 PEM 私钥字符串，返回明文 UTF-8 字符串。
 * 仅限 Node 环境；不可用时抛出错误。
 */
export function rsaDecrypt(
  cipherBase64: string,
  privateKey: string,
  options?: RsaOptions,
): string {
  const nodeCrypto = getNodeCrypto();
  if (!nodeCrypto?.privateDecrypt) {
    throw new Error('RSA 加解密仅支持 Node 环境（当前无内置 crypto.privateDecrypt）');
  }
  const decrypted = nodeCrypto.privateDecrypt(
    buildRsaCipherOptions(privateKey, options),
    BufferFromBase64(cipherBase64),
  );
  return bytesToUtf8(decrypted);
}

/** Node Buffer：确保加密输出为 Buffer，避免 Uint8Array 不具 toString('base64') 的问题。 */
function BufferToString(value: Uint8Array): { toString(enc: 'base64'): string } {
  // Node 的 publicEncrypt 返回 Buffer，自带 base64 toString
  return value as { toString(enc: 'base64'): string };
}

/** Node Buffer：按 base64 解析输入密文。 */
function BufferFromBase64(input: string): Uint8Array {
  const buf = typeof Buffer !== 'undefined' ? Buffer.from(input, 'base64') : null;
  if (buf) {
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  // 浏览器兜底：base64 -> WordArray -> bytes
  return wordArrayToBytes(CryptoJS.enc.Base64.parse(input));
}