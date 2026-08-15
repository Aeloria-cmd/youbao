# 区块链 / 智能合约漏洞操作手册

适用信号:题目给合约源码(.sol)/合约地址/RPC 端点,描述含合约、以太坊、token、钱包、链上。

## 流程

1. **读源码**:题目页或附件找 .sol;没有源码就要地址并尝试链上读(`eth_getCode` 拿到的是字节码,优先找源码)。
2. **checklist 审计**(按命中率排序):
   - **权限缺失**:敏感函数(transferOwnership/withdraw/mint/setFlag)没有 onlyOwner 或修饰符可被绕过 → 直接调用。
   - **重入**:外部调用(call/send)发生在状态更新之前;fallback 里可重入提钱/改状态。
   - **tx.origin 校验**:`require(tx.origin == owner)` → 可被钓鱼合约绕过。
   - **unchecked call / 返回值未检查**:低级调用失败不回滚。
   - **整数问题**:老 Solidity(<0.8)溢出;自定义算术 unchecked 块。
   - **预言机/价格操纵**:用池子余额当价格 → 大额 swap 打偏价格再套利。
   - **签名重放/弱随机**:`block.timestamp`/`blockhash` 当随机数;签名无 nonce/chainId。
   - **存储碰撞/delegatecall**:代理合约存储布局错位可改 owner。
3. **静态分析复核**(若环境有 slither):`slither contract.sol` 快速扫,模型对结果去误报。arm64 镜像未含 solc(官方无 arm64 版),此时跳过本步,以人工式源码审计为主。
4. **交互验证**:benchmark 题多是"触发某状态拿 flag"——用 curl 打 JSON-RPC:
   `curl -X POST RPC -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"合约","data":"编码后的调用"}, "latest"],"id":1}'`
   函数选择器用 `cast sig` 或手写 keccak 前 4 字节;发交易用 `eth_sendTransaction`(题目一般给已解锁账户/私钥)。
5. **flag 位置**:触发条件后读公开变量(`eth_call` flag()/getFlag()),或事件日志(`eth_getLogs`),或完成后端点/页面出现。

## 注意

- 先只读调用(eth_call)验证假设,再发交易——交易有状态代价。
- 所有发现写 journal(合约地址、选择器、漏洞点),链上状态不可逆,步骤要可追溯。
