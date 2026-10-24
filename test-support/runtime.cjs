const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// 独立模块缓存与全局对象，模拟没有 Node 内置模块的小程序 / 浏览器。
exports.createRuntime = function createRuntime(globals = {}, setup = '') {
  const context = vm.createContext({ Promise, queueMicrotask, setTimeout, ...globals });
  if (setup) vm.runInContext(setup, context);
  const cache = new Map();
  function loadFile(filename) {
    if (cache.has(filename)) return cache.get(filename).exports;
    const module = { exports: {} };
    cache.set(filename, module);
    const wrapper = vm.runInContext(
      `(function(require, module, exports) {\n${fs.readFileSync(filename, 'utf8')}\n})`,
      context,
      { filename },
    );
    wrapper((request) => {
      if (request === 'crypto-js') return loadFile(require.resolve('crypto-js'));
      if (request.startsWith('./')) return loadFile(path.resolve(path.dirname(filename), `${request}.js`));
      throw new Error(`Unexpected Node dependency in browser runtime: ${request}`);
    }, module, module.exports);
    return module.exports;
  }
  return {
    context,
    load: (id = 'index') => loadFile(path.resolve(__dirname, '../dist', `${id}.js`)),
    cryptoJs: () => loadFile(require.resolve('crypto-js')),
    evaluate: (source) => vm.runInContext(source, context),
  };
};
