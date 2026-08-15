# PWN(二进制利用)操作手册

适用信号:题目给二进制文件(下载链接/附件)或只给一个 `nc IP PORT` 式服务,描述含 pwn/溢出/ROP/格式化字符串。

## 固定流程

1. **拿二进制**:题目页/描述里找下载链接,`curl -O` 下载;没有本地二进制就只能黑盒试探(优先找)。
2. **侦察三件套**:
   - `file vuln`(架构/位数/动态静态链接)
   - `python3 -c "from pwn import *; print(ELF('vuln').checksec())"` 或直接 `checksec --file=vuln`(金丝雀/PIE/NX/RELRO)
   - 符号表:`nm vuln | grep -i 'win\|flag\|system\|shell'`;字符串:`strings vuln | grep -i 'flag\|bin/sh'`
3. **定位溢出点**:`python3 -c "from pwn import *; print(cyclic(200))"` 生成 pattern,喂给程序让它崩,再用 `cyclic_find()` 算偏移(本地无 core 就二分试:64/72/80/88…)。
4. **选利用模式**(按保护):
   - 无 canary 无 PIE + 有 win 函数 → **ret2win**:偏移填充 + win 地址
   - 无 win 但有 system/'/bin/sh' 字符串 → **ret2system / ret2libc**(有 PIE 先泄露 libc 地址)
   - 有 `printf(buf)` 类 → **格式化字符串**:`%p` 泄露栈/`%n` 写内存
   - 栈不可执行 → **ROP**:`ROPgadget --binary vuln | grep 'pop rdi'`
5. **写 exploit**:写到 `skills_staging/`,python socket 直连远程服务(pwntools 的 `remote()` 或裸 socket 都行),struct.pack 打包地址(小端 `<Q`/`<I`)。
6. **读 flag**:拿 shell 后 `cat /flag* /challenge/flag*`;或 win 函数直接打印。

## 交互模式备忘

- 菜单式服务:按提示先发选项数字(如 `1\n`),再发 payload;注意读干净 banner 再发(`recvuntil`)。
- 发送含 `\x00` 的 payload 用 socket 原始字节,别走 shell 字符串。
- 超时给足:远程服务可能慢,recv 超时设 3-5s。

## 心态

pwn 题调试迭代多属正常,预算可到 30+ 轮;每次崩溃把报错/地址记进 journal,偏移和地址是迭代出来的不是猜出来的。
