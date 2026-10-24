/**
 * 统一的 Node 内置 crypto 访问器。
 * 用于在可用时优先复用 Node 的安全实现（如 randomBytes），并在需要公开密钥运算时提供底层能力。
 */

type NodeCryptoModule = {
  randomBytes?: {
    (size: number): Uint8Array;
    (size: number, callback: (err: Error | null, bytes: Uint8Array) => void): void;
  };
  randomFillSync?: (bytes: Uint8Array) => Uint8Array;
  publicEncrypt?: (
    options: unknown,
    buffer: ArrayBuffer | Uint8Array,
  ) => Uint8Array;
  privateDecrypt?: (
    options: unknown,
    buffer: ArrayBuffer | Uint8Array,
  ) => Uint8Array;
  constants?: Record<string, number>;
} | null;

let cachedNodeCrypto: NodeCryptoModule | undefined;

/** 是否处于 Node 运行时（以 process.versions.node 为准，浏览器/RN 的 process shim 通常无该字段）。 */
function isNodeRuntime(): boolean {
  return (
    typeof process !== 'undefined' &&
    process !== null &&
    (process as { versions?: { node?: string } }).versions?.node != null
  );
}

/**
 * 尽力读取 Node 原生 crypto 模块（结果被缓存）。
 * 在浏览器 / 小程序 / RN 等非 Node 环境直接返回 null，调用方据此做降级。
 */
export function getNodeCrypto(): NodeCryptoModule {
  if (cachedNodeCrypto !== undefined) {
    return cachedNodeCrypto;
  }
  // 非 Node 环境：提前返回，完全不触碰 require，避免构建期问题
  if (!isNodeRuntime() || typeof require !== 'function') {
    cachedNodeCrypto = null;
    return cachedNodeCrypto;
  }

  // 用变量间接调用 require，规避 Metro/小程序/webpack 等打包器在构建期对
  // 'node:crypto'/'crypto' 内置模块做静态解析（解析失败会直接导致 bundle 失败）
  const load = require as (id: string) => unknown;
  for (const id of ['node:crypto', 'crypto']) {
    try {
      const mod = load(id) as NodeCryptoModule;
      if (mod) {
        cachedNodeCrypto = mod;
        break;
      }
    } catch {
      cachedNodeCrypto = null;
    }
  }
  // 循环可能未命中任何内置模块，此时 cachedNodeCrypto 仍为 undefined，统一归一为 null
  return cachedNodeCrypto ?? null;
}

/** 是否可访问 Node 内置 crypto。 */
export function isNodeCryptoAvailable(): boolean {
  return getNodeCrypto() !== null;
}
