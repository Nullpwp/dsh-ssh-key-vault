#!/usr/bin/env node
/**
 * dsh-ssh-targets — 查询工作区的授权主机与绑定密钥路径。
 *
 * 真正实现在 scripts/workspace-access.mjs；这里只提供可执行入口，
 * 便于通过 package.json 的 bin 安装为 dsh-ssh-targets。
 */
import '../scripts/workspace-access.mjs'
