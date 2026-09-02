import CryptoJS from 'crypto-js';
import { bytesToWordArray, concatBytes, utf8ToBytes } from './bytes';
import { getNodeCrypto } from './node-crypto';
import { getGlobalObject } from './globals';

const { SHA256 } = CryptoJS;

/**
 * 熵源收集：优先使用原生安全随机源（Node crypto.randomBytes / 全局 Web Crypto），
 * 仅当两者都不可用时，才退化到「时间抖动 + Math.random 混洗」这类弱熵。
 * 弱熵仅在完全没有安全源（老旧小程序/RN）的兜底场景被采用，README 已诚实标注强度限制。
 */

/** 尝试直接从原生安全源取 random 字节（绝不经过本包注入的 polyfill，避免递归）。 */
function tryNativeRandom(count: number): Uint8Array | null {
  const nodeCrypto = getNodeCrypto() as {
    randomBytes?: (size: number) => Uint8Array;
  } | null;
  if (nodeCrypto && typeof nodeCrypto.randomBytes === 'function') {
    return nodeCrypto.randomBytes(count);
  }

  const cryptoObj = getGlobalObject().crypto as Crypto | undefined;
  const grv = cryptoObj?.getRandomValues;
  if (typeof grv === 'function') {
    const bytes = new Uint8Array(count);
    grv.call(cryptoObj, bytes);
    return bytes;
  }
  return null;
}

/**
 * 收集弱熵源的文本混合信息串。
 * 通过多次高精度计时采样捕捉系统/环境噪声，并混入运行状态与随机采样。
 */
function collectWeakEntropyText(): string {
  const now = performanceNow();
  // 高精度计时抖动：多次采样，捕捉调度/系统噪声
  const jitter: string[] = [];
  for (let i = 0; i < 8; i += 1) {
    jitter.push(performanceNow().toFixed(6));
  }

  const parts: string[] = [
    String(now),
    jitter.join(','),
    `${Date.now()}:${Math.random().toString(36).slice(2)}`,
    String(Math.random()),
    String(Math.random()),
  ];

  // 运行环境信息
  if (typeof navigator !== 'undefined' && navigator) {
    const nav = navigator as unknown as Record<string, unknown>;
    parts.push(String(nav.hardwareConcurrency || 0));
    parts.push(String(nav.language || ''));
    parts.push(String((nav as { userAgent?: string }).userAgent || ''));
  }
  if (typeof process !== 'undefined' && process) {
    parts.push(String(process.pid || 0));
    parts.push(String(process.uptime ? process.uptime() : 0));
    const mem = process.memoryUsage ? process.memoryUsage() : null;
    parts.push(String(mem ? mem.heapUsed : 0));
    parts.push(String(process.version || ''));
    parts.push(String(process.argv ? process.argv.join(',') : ''));
  }

  // 调用栈（含时间戳），进一步增加不可预测性
  parts.push(`${Date.now()}:${new Error().stack || ''}`);
  return parts.join('|');
}

/** 跨端高精度计时，缺失时退化到 Date.now()。 */
function performanceNow(): number {
  if (typeof performance !== 'undefined' && performance && performance.now) {
    return performance.now();
  }
  return Date.now();
}

/** 将任意文本通过 SHA256 折叠为指定长度的字节。 */
function foldText(text: string, length: number): Uint8Array {
  const payload = utf8ToBytes(text);
  const out = new Uint8Array(length);
  let written = 0;
  let counter = 0;
  while (written < length) {
    const block = SHA256(bytesToWordArray(toContent(payload, counter)));
    const byteLen = Math.min(32, length - written);
    for (let i = 0; i < byteLen; i += 1) {
      const word = block.words[i >>> 2] >>> 0;
      out[written + i] = (word >>> (24 - (i % 4) * 8)) & 0xff;
    }
    written += byteLen;
    counter += 1;
  }
  return out;
}

/** 将 payload 与计数拼成可哈希内容（避免直接使用内部 WordArray 类型依赖）。 */
function toContent(payload: Uint8Array, counter: number): Uint8Array {
  return concatBytes(payload, Uint8Array.of((counter >>> 24) & 0xff, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff));
}

/**
 * 收集 entropy_total 字节的熵。
 * 有原生安全源时直接采用并混入弱熵文本去相关；否则用弱熵折叠生成（强度受限）。
 */
export function collectEntropy(length = 48): Uint8Array {
  const native = tryNativeRandom(length);
  if (native) {
    // 原生随机 + 弱熵混洗（SHA256），弱熵仅用于去相关，不削弱原生随机性
    const mixed = foldText(collectWeakEntropyText() + '::' + bytesToText(native), 32);
    const out = new Uint8Array(length);
    // 以原生字节为主体，混洗结果穿插，保证量与随机性
    out.set(native);
    for (let i = 0; i < length && i < mixed.length; i += 1) {
      out[i] ^= mixed[i];
    }
    return out;
  }
  // 兜底：弱熵折叠
  return foldText(`${collectWeakEntropyText()}::${Math.random()}`, length);
}

/** 将字节转为可组合的文本，便于进入哈希折叠。 */
function bytesToText(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length && i < 16; i += 1) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}