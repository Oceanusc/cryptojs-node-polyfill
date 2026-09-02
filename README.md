# cryptojs-node-polyfill

跨端 **Crypto polyfill + CryptoJS 加密封装工具层**。为缺少 [Web Crypto API](https://developer.mozilla.org/docs/Web/API/Web_Crypto_API) 的运行环境补齐 `Crypto` 实例方法，同时内置一套基于 CryptoJS 的加密封装工具。参考了 [`polyfill-crypto-methods`](https://www.npmjs.com/package/polyfill-crypto-methods) 的注入思路与 API 形态。

## 目标环境

- **微信 / 抖音小程序**：不支持 Web Crypto API，本包自动兜底注入（含 **`randomBytes`**），让 crypto-js 等库可用；
- **App（React Native 等）**：补齐缺失的 `getRandomValues`，修复旧 RN 依赖 `Math.random` 生成 UUID 的安全问题；
- **Apple（Safari / iOS / macOS WebKit）**：原本即支持 Web Crypto，本包**只补齐缺失方法、绝不覆盖已有实现**；
- **Node.js**：直接复用内置 `crypto`，无需额外工作。

## 补齐的 Crypto 能力

- `crypto.getRandomValues()` —— 向整型 TypedArray 填充安全随机字节
- `crypto.randomUUID()` —— 生成 RFC 4122 v4 UUID
- `crypto.randomBytes()` —— Node 风格随机字节（支持同步 / 异步回调）

## 加密封装工具层（差异化能力）

| 分类 | 方法 |
| --- | --- |
| AES 对称加解密 | `aesEncrypt` / `aesDecrypt`（CBC / ECB，PKCS#7，Base64 / Hex） |
| 消息摘要 | `md5` / `sha1` / `sha256` / `sha512` |
| HMAC 签名 | `hmacSha1` / `hmacSha256` |
| 编码转换 | `base64Encode` / `base64Decode` / `hexEncode` / `hexDecode` / `utf8Encode` / `utf8Decode` |
| RSA 非对称（Node 端委托） | `rsaEncrypt` / `rsaDecrypt`（RSA-PKCS1 / RSA-OAEP） |

> 说明：CryptoJS 本身不含 RSA，`rsaEncrypt`/`rsaDecrypt` 是对 **Node 内置 `crypto`** 的薄封装委托，仅在 Node 环境可用，其余环境调用会抛出明确错误。

## 安装

```
npm i cryptojs-node-polyfill
```

## 用法

### 1. 全局注入 Crypto 实例方法

在代码入口顶部进行一次副作用引入：

```ts
import 'cryptojs-node-polyfill';

const uint32 = crypto.getRandomValues(new Uint32Array(4));
console.log(crypto.randomUUID());
const bytes = crypto.randomBytes(4);   // 同步
crypto.randomBytes(4, (err, arr) => {}); // 异步
```

### 2. 按需具名引用（不依赖全局副作用）

```ts
import {
  getRandomValues, randomUUID, randomBytes,
  aesEncrypt, aesDecrypt,
  sha256, hmacSha256,
  base64Encode, hexDecode,
} from 'cryptojs-node-polyfill';
```

### 3. AES 示例

```ts
const KEY = '1234567890abcdef1234567890abcdef'; // 32 字节
const IV  = '1234567890abcdef';                  // 16 字节

const cipher = aesEncrypt('机密数据', KEY, { iv: IV });
const plain  = aesDecrypt(cipher, KEY, { iv: IV }); // '机密数据'

// hex 输出、ECB 模式同理
aesEncrypt('data', KEY, { mode: 'ECB', output: 'hex' });
```

### 4. RSA 示例（Node 端）

```ts
const { privateKey, publicKey } = require('node:crypto');

const cipher = rsaEncrypt('机密', publicPem, { padding: 'oaep' });
const plain  = rsaDecrypt(cipher, privatePem, { padding: 'oaep' });
```

## 随机数来源选择（核心设计）

1. **Node 内置 `crypto.randomBytes`** —— 首选，直接复用安全实现；
2. **全局 Web Crypto**（`globalThis.crypto.getRandomValues`）—— 浏览器 / Apple / 新 RN 可用时复用；
3. **CryptoJS 版 CSPRNG** —— 兜底。计数器模式，密钥与输出均经 `SHA256` 前滚（具备前向安全），并混合进程级熵源初始化。

## 保持与现有能力共存

- `globalThis.crypto` 已存在（尤其 Safari 等 Apple 环境）：**只补齐缺失方法**，绝不覆盖；
- 完全不存在（如老小程序）：注入完整实例（含 `randomBytes`）。

## 常见问题

### 小程序里 `globalThis.crypto` 是 `undefined`

正常。导入本包后会自动注入；若基础库过老未暴露 `globalThis`，包会通过 `wx`/`tt` 宿主降级探测。

### 浏览器环境中会出现 `randomBytes` 侵入吗

不会。对已有 `crypto` 对象只补缺失的标准方法（`getRandomValues` / `randomUUID`），`randomBytes` 仅在无任何 `crypto` 时才注入。

## API 汇总

### 随机与 UUID
- `getRandomValues(TypedArray)`：仅整型 TypedArray，其它抛 `TypeError`；空数组直接返回
- `randomUUID()`：标准 v4 UUID
- `randomBytes([size][, callback])`：默认 32 字节，同步 / 异步回调
- `CryptoRng`：可独立使用的 CSPRNG；相同 seed 输出确定，便于测试

### 摘要 / HMAC / 编码
- 摘要：`md5` / `sha1` / `sha256` / `sha512`，输入 `string | Uint8Array`，输出小写 hex
- HMAC：`hmacSha1` / `hmacSha256(message, key)`，输出小写 hex
- 编码：`base64Encode` / `base64Decode` / `hexEncode` / `hexDecode` / `utf8Encode` / `utf8Decode`

### AES
- `aesEncrypt(plainText, key, options?)` / `aesDecrypt(cipherText, key, options?)`
- `options`：`mode`（默认 `CBC`）、`iv`、`keyEncoding` / `ivEncoding`（默认 `utf8`）、`output`（默认 `base64`）
- key 长度必须是 16/24/32 字节，CBC 的 iv 必须是 16 字节，不符会抛 `TypeError`

## 脚本

| 命令 | 说明 |
| --- | --- |
| `npm run build` | 编译 TypeScript 到 `dist/` |
| `npm test` | 构建并运行 `node:test` 单元测试（含与 Node 内置 / CryptoJS 原生的互操作对照） |

## License

MIT