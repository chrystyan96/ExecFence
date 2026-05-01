'use strict';

const exactSignatures = [
  ['void-dokkaebi-loader-marker', "global.i='2-30-4'"],
  ['void-dokkaebi-obfuscated-symbol-a7ae', '_$_a7ae'],
  ['void-dokkaebi-obfuscated-symbol-d609', '_$_d609'],
  ['void-dokkaebi-loader-invocation', 'tLl(5394)'],
  ['void-dokkaebi-runtime-global', "global['_V']"],
  ['cross-chain-tron-stage', 'api.trongrid.io/v1/accounts'],
  ['cross-chain-aptos-stage', 'fullnode.mainnet.aptoslabs.com/v1/accounts'],
  ['cross-chain-bsc-rpc-stage', 'bsc-dataseed.binance.org'],
  ['cross-chain-publicnode-stage', 'bsc-rpc.publicnode.com'],
  ['cross-chain-eth-transaction-stage', 'eth_getTransactionByHash'],
  ['known-auto-push-dropper', 'temp_auto_push'],
];

const regexSignatures = [
  ['vscode-folder-open-autostart', /"runOn"\s*:\s*"folderOpen"/],
  ['hidden-node-require-loader', /global\[[^\]]+\]\s*=\s*require/],
  ['dynamic-function-loader', /\b(Function|constructor)\s*\([^)]{0,160}(eval|fromCharCode|child_process)/],
];

module.exports = {
  exactSignatures,
  regexSignatures,
};
