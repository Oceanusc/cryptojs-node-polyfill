/**
 * 跨端全局对象与基础能力归一化。
 * 小程序 / App（React Native 等）/ 苹果 WebKit 等环境的全局对象与 API 存在差异，
 * 此处统一探测，避免裸引用 globalThis / queueMicrotask 造成 ReferenceError。
 */

/** 兼容任意运行时形状的全局对象类型。 */
type GlobalLike = {
  crypto?: unknown;
  [key: string]: unknown;
};

// 各小程序宿主命名空间：这些标识符在对应端全局可见（typeof 检测安全），
// 仅作为“无法定位标准全局对象”时的最后挂载点（非 JS 全局对象，属尽力而为）。
declare const wx: unknown;
declare const tt: unknown;
declare const my: unknown;
declare const swan: unknown;
declare const qq: unknown;
declare const ks: unknown;

// 模块级兜底容器：仅在完全无法定位真实全局对象时使用。
// 保持单例，确保注入与后续读取落在同一对象上，避免“写入后被丢弃”的静默失效。
let fallbackGlobal: GlobalLike | null = null;

/**
 * 解析当前运行环境的全局对象。
 * 优先级：globalThis → self → window → global → 小程序宿主 → 模块级兜底容器。
 */
export function getGlobalObject(): GlobalLike {
  if (typeof globalThis !== 'undefined') {
    return globalThis as GlobalLike;
  }
  if (typeof self !== 'undefined') {
    return self as unknown as GlobalLike;
  }
  if (typeof window !== 'undefined') {
    return window as unknown as GlobalLike;
  }
  if (typeof global !== 'undefined') {
    return global as unknown as GlobalLike;
  }
  const host = probeHostGlobals();
  if (host) {
    return host;
  }
  return (fallbackGlobal ??= {});
}

/**
 * 直接 typeof 检测各小程序宿主命名空间，作为兜底全局对象。
 * 不再使用 Function 构造器 / 动态求值：微信等小程序会禁用 new Function 与 eval，
 * 原实现必然抛错失效；且宿主命名空间并非 JS 全局对象，挂在上面的注入仅对部分场景可见。
 */
function probeHostGlobals(): GlobalLike | null {
  // 逐个 typeof 检测：未声明标识符的 typeof 是安全的，不会触发 ReferenceError
  if (typeof wx !== 'undefined' && wx !== null) {
    return wx as GlobalLike;
  }
  if (typeof tt !== 'undefined' && tt !== null) {
    return tt as GlobalLike;
  }
  if (typeof my !== 'undefined' && my !== null) {
    return my as GlobalLike;
  }
  if (typeof swan !== 'undefined' && swan !== null) {
    return swan as GlobalLike;
  }
  if (typeof qq !== 'undefined' && qq !== null) {
    return qq as GlobalLike;
  }
  if (typeof ks !== 'undefined' && ks !== null) {
    return ks as GlobalLike;
  }
  return null;
}

/**
 * 延迟到下一轮微任务的调度器。
 * 小程序早期基础库未必暴露 queueMicrotask，这里做降级。
 */
export function runInMicrotask(fn: () => void): void {
  if (typeof queueMicrotask === 'function') {
    queueMicrotask(fn);
    return;
  }
  if (typeof Promise !== 'undefined') {
    Promise.resolve().then(fn);
    return;
  }
  if (typeof setTimeout === 'function') {
    setTimeout(fn, 0);
    return;
  }
  fn(); // 最终兜底：同步执行
}