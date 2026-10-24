import CryptoJS from 'crypto-js';

/**
 * 统一的字节数据工具：负责 Uint8Array 与 CryptoJS WordArray、UTF-8 字符串之间的转换。
 * 各功能模块复用此处，避免重复实现。
 */

/**
 * 将原始字节转成 CryptoJS WordArray，以便直接参与 CryptoJS 的加解密与摘要运算。
 * 显式按大端序组装，避免 CryptoJS 的 instanceof 判断误读跨 realm 字节数组。
 */
export function bytesToWordArray(bytes: Uint8Array): CryptoJS.lib.WordArray {
  if (!isUint8Array(bytes)) throw new TypeError('bytes 必须是 Uint8Array');
  const words: number[] = [];
  for (let i = 0; i < bytes.length; i += 1) {
    words[i >>> 2] = (words[i >>> 2] ?? 0) | (bytes[i] << (24 - (i % 4) * 8));
  }
  return CryptoJS.lib.WordArray.create(words, bytes.length);
}

const typedArrayTag = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag,
)!.get!;

function isUint8Array(value: unknown): value is Uint8Array {
  return ArrayBuffer.isView(value) && typedArrayTag.call(value) === 'Uint8Array';
}

/**
 * 将 CryptoJS 的 WordArray 按字节序导出为 Uint8Array。
 * words 为 32 位有符号整数，需转无符号后按大端序取字节。
 */
export function wordArrayToBytes(wa: CryptoJS.lib.WordArray): Uint8Array {
  const sigBytes = wa.sigBytes;
  const out = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i += 1) {
    const word = wa.words[i >>> 2] >>> 0;
    out[i] = (word >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return out;
}

/** 拼接两个字节数组。 */
export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** 字符串按 UTF-8 编码为字节，供需要字节输入的场景使用。 */
export function utf8ToBytes(str: string): Uint8Array {
  return wordArrayToBytes(CryptoJS.enc.Utf8.parse(str));
}

/** 由 UTF-8 字节还原字符串。 */
export function bytesToUtf8(bytes: Uint8Array): string {
  return CryptoJS.enc.Utf8.stringify(bytesToWordArray(bytes));
}

/** 统一的文本/字节输入归一化：字符串按 UTF-8 解析，字节直接使用。 */
export function toBytes(input: string | Uint8Array): Uint8Array {
  if (isUint8Array(input)) {
    return input;
  }
  if (typeof input === 'string') return utf8ToBytes(input);
  throw new TypeError('input 必须是 string 或 Uint8Array');
}
