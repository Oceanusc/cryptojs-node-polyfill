import CryptoJS from 'crypto-js';
import { collectEntropy } from './entropy';
import {
  bytesToWordArray,
  concatBytes,
  utf8ToBytes,
  wordArrayToBytes,
} from './bytes';

const { SHA256 } = CryptoJS;

// NIST SP 800-90A Rev.1 中 Hash_DRBG 使用 SHA-256 的常量
const OUTLEN = 32; // 哈希输出字节数（SHA-256 = 256 bit）
const SEEDLEN = 55; // 状态字节数（440 bit，与 SHA-256 安全强度对应）
const MAX_BITS_PER_REQUEST = 2 ** 19; // 单次生成上限：2^19 bit = 2^16 字节
const RESEED_INTERVAL = 2 ** 48;

const PERSONALIZATION = 'cryptojs-node-polyfill.hash-drbg.v1';

/**
 * 基于 CryptoJS.SHA256 的 NIST Hash_DRBG 随机数生成器。
 *
 * 实现 SP 800-90A 的 Instantiate / Generate（不含附加输入），不代表通过 NIST 认证。
 * 显式 seed 为完整 seed_material，仅用于可复现序列；安全性由调用方的熵输入决定。
 * 不支持 reseed，达到 2^48 次请求后必须从新的安全熵创建实例。
 */
export class CryptoRng {
  private V: Uint8Array;
  private C: Uint8Array;
  private reseedCounter: number;

  constructor(seed?: Uint8Array) {
    // 实例化：seed_material = entropy || nonce || personalization（无显式 seed 时）
    // 显式 seed 场景为确定性可复现，避免额外引入随机 nonce，便于测试断言。
    let seedMaterial: Uint8Array;
    if (seed !== undefined) {
      bytesToWordArray(seed);
      if (seed.length === 0) throw new TypeError('seed 不能为空');
      seedMaterial = seed;
    } else {
      seedMaterial = concatBytes(
        concatBytes(
          collectEntropy(SEEDLEN),
          collectEntropy(32), // nonce
        ),
        utf8ToBytes(PERSONALIZATION),
      );
    }

    this.V = hashDF(SEEDLEN, seedMaterial);
    // C = Hash_df(seedlen, (0x00 || V))
    this.C = hashDF(SEEDLEN, concatBytes(Uint8Array.of(0x00), this.V));
    this.reseedCounter = 1;
  }

  /**
   * 生成 length 字节安全随机数（单次不超过 NIST 上限）。
   */
  public generate(length: number): Uint8Array {
    if (!Number.isInteger(length) || length < 0) {
      throw new RangeError('length 必须是非负整数');
    }
    const maxBytes = MAX_BITS_PER_REQUEST / 8;
    if (length > maxBytes) {
      throw new RangeError(`单次生成最多 ${maxBytes} 字节`);
    }
    if (this.reseedCounter > RESEED_INTERVAL) {
      throw new Error('Hash_DRBG 需要重新播种；请从新的安全熵创建 CryptoRng 实例');
    }

    // W = Hashgen(requested_bytes, V)
    const out = hashgen(length, this.V);

    // 状态前滚：H = Hash(0x03 || V)，V = V + H + C + reseed_counter (mod 2^seedlen)
    const h = wordArrayToBytes(
      SHA256(bytesToWordArray(concatBytes(Uint8Array.of(0x03), this.V))),
    );
    this.V = addTermsBigEndian(
      [this.V, h, this.C, counterBytes(this.reseedCounter)],
      SEEDLEN,
    );
    this.reseedCounter += 1;

    return out;
  }
}

/** Hash_df(bytes_needed, input)：按 NIST 定义重复哈希并取左端 L 位。 */
function hashDF(bytesNeeded: number, input: Uint8Array): Uint8Array {
  const m = Math.ceil(bytesNeeded / OUTLEN);
  const bits = bytesNeeded * 8;
  const L = uint32BE(bits);
  const out = new Uint8Array(bytesNeeded);
  let written = 0;

  for (let i = 1; i <= m; i += 1) {
    // SP 800-90A §10.3.1：counter 是 1 字节；仅输出位数 L 为 4 字节。
    const counter = Uint8Array.of(i);
    const block = wordArrayToBytes(
      SHA256(bytesToWordArray(concatBytes(concatBytes(counter, L), input))),
    );
    const take = Math.min(OUTLEN, bytesNeeded - written);
    out.set(block.subarray(0, take), written);
    written += take;
  }
  return out;
}

/** Hashgen(bytes_needed, data)：对 data 连续哈希并逐次 +1，取左端 L 位。 */
function hashgen(bytesNeeded: number, dataInput: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytesNeeded);
  const data = dataInput.slice();
  let written = 0;

  while (written < bytesNeeded) {
    const block = wordArrayToBytes(SHA256(bytesToWordArray(data)));
    const take = Math.min(OUTLEN, bytesNeeded - written);
    out.set(block.subarray(0, take), written);
    written += take;
    incrementBigEndian(data); // data = (data + 1) mod 2^seedlen
  }
  return out;
}

/** 把计数器编码为大端序字节（右侧对齐，代表最不显著部分）。 */
function counterBytes(value: number): Uint8Array {
  const out = new Uint8Array(7);
  for (let i = out.length - 1; i >= 0; i -= 1) {
    out[i] = value % 256;
    value = Math.floor(value / 256);
  }
  return out;
}

/** 32 位大端序编码。 */
function uint32BE(value: number): Uint8Array {
  return Uint8Array.of(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
}

/**
 * 若干大端序字节数组在固定 outLen 内求和（右侧对齐）。
 * 超出 outLen 的进位按模 2^(8*outLen) 截断，对应 NIST 的 modulo 2^seedlen。
 */
function addTermsBigEndian(terms: Uint8Array[], outLen: number): Uint8Array {
  const out = new Uint8Array(outLen);
  let carry = 0;

  for (let pos = outLen - 1; pos >= 0; pos -= 1) {
    let sum = carry;
    for (const term of terms) {
      const offset = term.length - outLen; // 右侧对齐偏移
      const idx = pos + offset;
      if (idx >= 0 && idx < term.length) {
        sum += term[idx];
      }
    }
    out[pos] = sum & 0xff;
    carry = Math.floor(sum / 256);
  }
  // 忽略最高位溢出（仍保留低位，等价于模 2^seedlen）
  return out;
}

/** 大端序 +1（用于 Hashgen 的 data 步进）。 */
function incrementBigEndian(data: Uint8Array): void {
  for (let i = data.length - 1; i >= 0; i -= 1) {
    data[i] += 1;
    if (data[i] !== 0) {
      return;
    }
  }
}
