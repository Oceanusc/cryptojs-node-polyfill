# cryptojs-node-polyfill

跨端 **Crypto polyfill + CryptoJS 加密封装工具层**。为缺少 [Web Crypto API](https://developer.mozilla.org/docs/Web/API/Web_Crypto_API) 的运行环境补齐 `Crypto` 实例方法，同时内置一套基于 CryptoJS 的加密封装工具。参考了 [`polyfill-crypto-methods`](https://www.npmjs.com/package/polyfill-crypto-methods) 的注入思路与 API 形态。

## 目标环境

- **微信 / 抖音小程序**：补齐随机接口（含 **`randomBytes`**）；缺少原生安全随机源时，须通过 `setRandomSource` 接入宿主同步 CSPRNG；
- **App（React Native 等）**：复用已有安全随机源，或接入同步原生桥接；绝不使用 `Math.random` 冒充安全随机数；
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
import { randomBytes } from 'cryptojs-node-polyfill';

const uint32 = crypto.getRandomValues(new Uint32Array(4));
console.log(crypto.randomUUID());
const bytes = randomBytes(4);           // 同步，具名导出在所有目标环境均可调用
randomBytes(4, (err, arr) => {});        // 异步回调
```

### 2. 具名调用（导入时仍会尝试补齐全局）

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
import { aesEncrypt, aesDecrypt, randomBytes, bytesToHex } from 'cryptojs-node-polyfill';

const key = bytesToHex(randomBytes(32)); // 32 字节原始密钥，实际使用中须安全保存
const iv = bytesToHex(randomBytes(16));  // 每次加密重新生成 IV，和密文一起保存
const options = { iv, keyEncoding: 'hex', ivEncoding: 'hex' } as const;
const cipher = aesEncrypt('机密数据', key, options);
const plain = aesDecrypt(cipher, key, options); // '机密数据'

// hex 密文输出
aesEncrypt('data', key, { ...options, output: 'hex' });
```

此接口使用 CBC / ECB + PKCS#7，不提供密文认证。协议层应先验证 MAC 再解密；需要认证加密时可使用原生 Web Crypto / Node 的 AES-GCM。ECB 仅供兼容已有协议。

### 4. RSA 示例（Node 端）

```ts
const { generateKeyPairSync } = require('node:crypto');
const { rsaEncrypt, rsaDecrypt } = require('cryptojs-node-polyfill');
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const cipher = rsaEncrypt('机密', publicKey); // 默认 OAEP + SHA-256
const plain = rsaDecrypt(cipher, privateKey);
```

RSA 仅适合小数据，其长度受密钥长度和 OAEP 哈希限制。`padding: 'pkcs1'` 保留给旧协议；私钥解密是否可用取决于 Node / OpenSSL 的隐式拒绝支持，详见 [Node 文档](https://nodejs.org/api/crypto.html#cryptoprivatedecryptprivatekey-buffer)。

## 随机数来源选择（核心设计）

1. **Node 内置 `crypto.randomFillSync` / `randomBytes`** —— 直接使用系统安全实现，回调形式委托给原生异步 `randomBytes`；
2. **导入前已有的 Web Crypto** —— 保存原生方法及所属对象，按不超过 65536 字节分块调用；
3. **显式配置的宿主 CSPRNG** —— 使用 `setRandomSource` 接入同步安全随机源；
4. 没有以上来源时，随机 API 明确抛错。导入、摘要、编码等不需要随机性的操作仍可使用。

`CryptoRng` 是独立的 SHA-256 Hash_DRBG，不用于绕过随机源要求。无显式 seed 时只从安全来源取熵；显式 seed 为完整 `seed_material`，用于可复现序列，其安全性取决于调用方的熵。实现经 [NIST CAVP 官方向量](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip)验证，不代表通过 NIST 认证。

### 接入小程序 / RN 的宿主随机源

```ts
import { setRandomSource, randomBytes } from 'cryptojs-node-polyfill';

// fillFromNativeCSPRNG 由应用的原生桥接提供：同步填满 bytes，失败时抛错。
setRandomSource((bytes) => { fillFromNativeCSPRNG(bytes); });
const bytes = randomBytes(32);
```

该函数必须同步填满每个传入视图，不得使用 `Math.random`、时间戳或返回 Promise。只有回调 / Promise 的宿主随机接口不能直接适配同步 `getRandomValues`。调用 `setRandomSource(null)` 可移除自定义来源。若使用原生 Web Crypto polyfill，应在导入本包前安装。

## 保持与现有能力共存

- `globalThis.crypto` 已存在（尤其 Safari 等 Apple 环境）：**只补齐缺失方法**，绝不覆盖；
- 完全不存在（如老小程序）：注入完整实例（含 `randomBytes`）。

## 常见问题

### 小程序里 `globalThis.crypto` 是 `undefined`

导入后会尝试注入接口，但仍需原生安全随机源或显式配置的同步宿主来源。若未暴露 `globalThis`，包会通过 `wx`/`tt` 等宿主探测；挂载到宿主命名空间不等于创建真实 JS 全局对象，优先使用具名导出。全局属性只读时，注入失败不会阻断模块加载。

### 浏览器环境中会出现 `randomBytes` 侵入吗

不会。对已有 `crypto` 对象只补缺失的标准方法（`getRandomValues` / `randomUUID`），`randomBytes` 仅在无任何 `crypto` 时才注入。

## API 汇总

### 随机与 UUID
- `getRandomValues(TypedArray)`：仅整型 TypedArray，其它抛 `TypeError`；空数组直接返回
- 支持 `BigInt64Array` / `BigUint64Array` 和跨 realm 整型数组；单次最多 65536 字节，超出抛 `QuotaExceededError`
- `randomUUID()`：标准 v4 UUID
- `randomBytes([size][, callback])`：默认 32 字节，size 为 0 到 2147483647 的整数；同步 / 异步回调，失败时回调接收错误和空数组
- `setRandomSource(source | null)`：接入 / 移除同步宿主安全随机源，原生 Node / Web Crypto 优先
- `CryptoRng`：相同非空 seed 输出确定；每次最多 65536 字节，超过 2^48 次请求后须从新熵重新创建实例

### 摘要 / HMAC / 编码
- 摘要：`md5` / `sha1` / `sha256` / `sha512`，输入 `string | Uint8Array`，输出小写 hex
- HMAC：`hmacSha1` / `hmacSha256(message, key)`，输出小写 hex
- 编码：`base64Encode` / `base64Decode` / `hexEncode` / `hexDecode` / `utf8Encode` / `utf8Decode`
- Hex 必须为偶数个十六进制字符；Base64 接受标准字符和可省略的末尾填充，非法字符、尾位和填充均抛 `TypeError`

### AES
- `aesEncrypt(plainText, key, options?)` / `aesDecrypt(cipherText, key, options?)`
- `options`：`mode`（默认 `CBC`）、`iv`、`keyEncoding` / `ivEncoding`（默认 `utf8`）、`output`（默认 `base64`）
- key 长度必须是 16/24/32 字节，CBC 的 iv 必须是 16 字节，不符会抛 `TypeError`
- 解密要求非空的完整 16 字节分组，严格检查全部 PKCS#7 填充；填充有效不代表密文已通过认证

## 兼容性变更（未发布）

- 移除基于 `Math.random` / 时间的弱熵兜底；没有安全随机源的应用须配置 `setRandomSource`。
- RSA 默认从 PKCS#1 v1.5 改为 OAEP-SHA256；旧密文须显式指定原始填充，并确认运行时支持。
- 修正 Hash_DRBG 的单字节派生计数器和 seed 截断问题；固定 seed 的输出序列与旧实现不同。
- 不再静默接受无效编码、未知算法参数、残缺密文或非法 PKCS#7 填充。

## 脚本

| 命令 | 说明 |
| --- | --- |
| `npm run build` | 编译 TypeScript 到 `dist/` |
| `npm test` | 构建并运行 `node:test` 单元测试（含与 Node 内置 / CryptoJS 原生的互操作对照） |
| `npm pack` | 自动构建并打包，包含调试映射引用的源文件 |

开发和运行测试需要 Node.js 18 或以上；库运行时仍支持 Node.js 14.18 或以上。测试包含 NIST Hash_DRBG 向量、真实 CryptoJS 的无 Node 沙箱、跨 realm / 子视图、异常编码和 AES / RSA 互操作。

## License

MIT
