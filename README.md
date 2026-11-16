# SSH 密钥库（@local/dsh-ssh-key-vault）

在 DSH Web 的「设置 → SSH 密钥」中集中管理 SSH 私钥与远程主机档案，并按工作区授予使用范围。

> **一句话边界**：这是一个**本机明文密钥库 + 逻辑授权记录**，不是加密保险箱，也不是操作系统级隔离。密钥文件以 0600 明文保存在 DSH 数据目录，同一系统用户（包括 Agent 进程）可以直接读取。详见 [docs/SECURITY.md](docs/SECURITY.md)。

---

## 1. 功能概览

| 能力 | 说明 |
| --- | --- |
| 密钥管理 | 在浏览器上传无口令 SSH 私钥；解析算法、位数与 SHA256 指纹；重命名；删除 |
| 主机档案 | 维护名称、地址、端口、用户名、备注与关联密钥；增删改查 |
| 工作区授权 | 按工作区勾选可用主机；主机绑定密钥，授权主机即同时授权其密钥 |
| 按工作区展示 | 在「工作区授权」标签页选择工作区，查看已授权主机与随主机带出的密钥 |
| Agent 工具 | 全局只读工具 `ssh_targets`：按工作区返回主机、端口、用户名、绑定密钥路径与现成 ssh 命令；不返回私钥正文，不发起连接 |
| 不落私钥到浏览器 | 页面只展示名称、文件名、指纹、算法与位数，从不回传私钥内容，也不提供下载/导出 |

明确**不做**的事情：

- 不做 SSH 连接测试，不执行远程命令；只提供只读的 `ssh_targets` 查询工具；
- 不支持带口令（passphrase）的私钥；
- 不加密存储私钥；
- 不导入、不联动 `dsh-push-deploy` 已有密钥；
- 不提供私钥下载/导出，也不做系统级隔离。

---

## 2. 安装与打开

### 2.1 环境要求

| 项目 | 要求 |
| --- | --- |
| DSH | Web profile（本机为 DSH `0.2.2-rc.1`，`DSH_PROFILE=web`） |
| Node.js | 随 DSH 提供（本机 `v24.22.2`） |
| 系统工具 | OpenSSH 客户端，需能执行 `ssh-keygen`（本机 `/usr/bin/ssh-keygen`） |
| 数据目录 | `$DSH_HOME/ssh-key-vault/`（本机 `DSH_HOME=/data/dsh`） |

### 2.2 安装

插件目录（本机）：

```
/data/dsh/home/dsh-plugin-usre/dsh-ssh-key-vault
```

在 DSH Web 中打开「设置 → 插件」，选择「添加插件」，把上面的本地目录或包名 `@local/dsh-ssh-key-vault` 填入安装来源并确认。安装由插件管理器完成：它会登记依赖、启用 bundle patch，并把插件加入当前 profile 的 bundle 列表。

- 安装可能弹出审批提示，需要由你本人确认；未确认时插件不会启用。
- **不要手动修改** `$DSH_HOME/profiles/<profile>/package.json`、`cordis.patch.yml`，也不要手工编辑 `node_modules`：本插件通过 `dsh.bundle.patch` 自带 Cordis patch，跳过插件管理器会导致启用状态不一致。

### 2.3 验证安装

安装完成并刷新页面后，可以先用同源接口确认 Host 侧已加载：

```bash
curl -sS http://127.0.0.1:3080/ssh-key-vault
```

正常返回：

```json
{ "ok": true, "service": "ssh-key-vault", "version": 1 }
```

### 2.4 打开页面

「设置 → SSH 密钥」。页面顶部显示密钥数、主机数与已授权工作区数，并提供刷新按钮；下方是三个标签页：

- **密钥**：上传与密钥列表；
- **主机**：主机表单与主机列表；
- **工作区授权**：选择工作区，勾选主机，查看主机与随主机带出的密钥。

卸载插件不会自动删除数据目录，见 [§6 数据与备份](#6-数据与备份)。

---

## 3. 上传与管理密钥

### 3.1 上传要求

| 项目 | 要求 |
| --- | --- |
| 类型 | 无口令的 SSH 私钥（PEM/OpenSSH，含 `-----BEGIN ... PRIVATE KEY-----` 与 `-----END ... PRIVATE KEY-----`） |
| 大小 | 不超过 64 KiB |
| 口令 | 不支持；带口令的私钥会被拒绝 |
| 校验 | 服务端用 `ssh-keygen -y -P ''` 验证私钥无口令，再用 `ssh-keygen -lf` 解析指纹；失败即拒绝，不落盘 |
| 去重 | 相同 SHA256 指纹重复上传会被拒绝（409，`duplicate_key`） |
| 名称 | 可选，1–80 字符，同一库内不区分大小写唯一；留空时由服务端按文件名生成唯一名称（重名时追加 ` (2)` 等后缀） |
| 文件名 | 仅保留 `[A-Za-z0-9._-]`，去掉前导点，最长 96 字符 |
| 依赖 | 宿主机需有可执行的 `ssh-keygen`，否则上传返回 503（`ssh_keygen_unavailable`） |

支持的具体算法（ED25519、RSA、ECDSA 等）以本机 `ssh-keygen` 能力为准，页面会显示识别结果。

### 3.2 上传步骤

1. 打开「设置 → SSH 密钥 → 密钥」；
2. 在「上传私钥」卡片选择私钥文件；
3. 可选填写名称（留空时由服务端按文件名生成默认名称）；
4. 点击上传。成功后列表出现新密钥，显示 SHA256 指纹、算法/位数与文件名。

上传过程中私钥只提交给本机 `POST /ssh-key-vault/keys/upload`，页面不会回显私钥内容，也不会把它写入浏览器存储。

### 3.3 重命名与删除

- **重命名**：行内编辑名称，确认后立即生效；名称冲突返回 409（`key_name_conflict`）。
- **删除**：行内二次确认（确认/取消），不使用浏览器原生弹窗。
  - 若仍有主机档案引用该密钥，删除会被拒绝（409，`key_in_use`），需要先删除或改绑主机；
  - 删除成功后，密钥元数据与密钥文件移除；授权只引用主机，不再存在单独的密钥授权；
  - **删除不可撤销**，请先备份（见 §6）。

---

## 4. 维护主机档案

主机档案只存连接信息，不发起连接。字段与校验：

| 字段 | 必填 | 校验 |
| --- | --- | --- |
| 名称 `label` | 是 | 1–80 字符，库内唯一（不区分大小写） |
| 地址 `address` | 是 | 1–255 字符，IPv4 / 主机名 / `[IPv6]` / 裸 IPv6 |
| 端口 `port` | 是 | 1–65535 的整数 |
| 用户名 `username` | 是 | `[A-Za-z0-9._-]`，1–64 字符 |
| 关联密钥 `keyId` | 是 | 必须是库中已存在的密钥 |
| 备注 `note` | 否 | ≤ 500 字符，可含换行 |

操作方式：

- 「主机」标签页顶部表单新增主机；列表中「编辑」会把该行载入表单，保存后按新值（包括新 `keyId`）立即重算访问关系。
- 删除主机行内确认；删除主机时，若绑定密钥不再被其他主机使用，会连同密钥文件一起删除；仍被其他主机使用时只删除主机并保留密钥。删除主机也会移除所有工作区对它的授权。
- 没有密钥时，表单会提示先上传密钥。

示例（文档地址，勿直接用于生产）：`203.0.113.10`、`example.com`、端口 `22`、用户 `root`。

---

## 5. 工作区授权

### 5.1 语义

授权关系按工作区保存，只记录**主机**：

- 每台主机在主机档案里绑定一把密钥；
- 授权某台主机，就同时授权它绑定的密钥；
- 有效主机 = 该工作区被授权的主机；
- 有效密钥 = 这些主机绑定的密钥。

不再单独授权密钥，也不存在「授权密钥反向带出主机」的继承。工作区之间互不继承，撤销立即生效（不缓存、不轮询）。改绑主机的密钥会立即改变该工作区可用的密钥；新增一台使用同一把密钥的主机不会自动获得授权。

### 5.2 例子

主机 `H1` 绑定 `K1`，主机 `H2` 绑定 `K2`。只授权 `H2`：

- 可用主机：`H2`；
- 可用密钥：`K2`；
- `H1`/`K1` 不可用；即使 `K2` 被其他主机使用，也不会带出那些主机。

### 5.3 操作

1. 打开「工作区授权」，从下拉框选择工作区；
2. 在「SSH 主机（含绑定密钥）」复选组中勾选主机，可用全选/清空；
3. 下方「本次授权预览」显示勾选主机与随主机带出的密钥；保存是**覆盖式**的：提交的勾选结果就是该工作区被授权主机的完整集合（不是增量追加），保存后写入 `vault.json` 并立即生效；
4. 取消勾选并保存即撤销该主机授权；删除主机也会移除所有工作区对它的授权。

空工作区、空密钥库时页面会给出提示，不会显示空白表格。

> 再次强调：这里记录的是**使用范围**，不改变文件系统权限，也不阻止同一系统用户或 Agent 直接读取密钥文件。见 [docs/SECURITY.md](docs/SECURITY.md)。

### 5.4 命令行查询（可选）

插件附带一个只读命令，用于在终端确认「某个工作区有哪些主机、各自绑定哪把密钥、密钥文件在哪」：

```bash
node scripts/workspace-access.mjs auto_submit_order
node scripts/workspace-access.mjs website --json
```

也可以通过 `package.json` 的 `bin` 使用 `dsh-ssh-targets`：

```bash
./bin/dsh-ssh-targets.mjs auto_submit_order
```

不传工作区时按当前目录匹配；`--url` 指定 DSH Web 地址，`--vault-dir` 指定自定义数据目录。

> DSH 启动器把 `dsh <name>` 解释为「启动名为 `<name>` 的 profile」，只保留 `plugin` 一个内建子命令，因此插件无法注册真正的 `dsh ssh-targets`。如果确实需要这个写法，可把 `bin/dsh` 软链到 PATH 中更靠前的目录（如 `~/.local/bin/dsh`）：它只拦截 `ssh-targets`，其余参数原样转交给真正的 `dsh`，不修改 DSH 安装。该命令只读 `/state`，不复制私钥，也不构成隔离。

### 5.5 Agent 工具 `ssh_targets`

插件在 Host 的 `tools` 服务上注册一个全局只读工具 `ssh_targets`，任何 Agent 会话都可以像内置工具一样直接调用，不需要先跑 CLI。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `workspace` | 否 | 工作区名称、ID 或绝对路径；省略时使用当前会话所属工作区 |

返回内容：

- 每台被授权主机的 `address`、`port`、`username`；
- 绑定密钥的 `name`、`filename`、绝对 `path` 与 `exists`；
- 一条可直接执行的 `ssh -i ... -o IdentitiesOnly=yes user@host` 命令。

工具**不读取私钥正文、不建立连接**，真正执行 `ssh` 仍由 Agent 的 bash 工具完成。

> 工具是全局注册的：任何会话都可以传任意工作区名，因此它和 `/state` 一样只是查询，不是隔离。新增或修改 Host 侧代码后，需要重启 DSH Web（或在插件管理器中重新加载本插件）才会出现在会话的工具列表里。

---

## 6. 数据与备份

### 6.1 存放位置与权限

数据目录独立于插件代码：`$DSH_HOME/ssh-key-vault/`（本机为 `/data/dsh/ssh-key-vault/`）。

| 路径 | 内容 | 权限 |
| --- | --- | --- |
| `$DSH_HOME/ssh-key-vault/` | 数据根目录 | `0700` |
| `$DSH_HOME/ssh-key-vault/vault.json` | 密钥元数据、主机档案、工作区授权 | `0600` |
| `$DSH_HOME/ssh-key-vault/keys/` | 私钥文件（`<keyId>-<文件名>`） | `0700` |
| `$DSH_HOME/ssh-key-vault/keys/*` | 单个私钥 | `0600` |

`vault.json` 当前为 **version 2**（`access` 只保存 `hostIds`）。旧 version 1 在读取时自动迁移：把 `keyIds` 展开为当时绑定这些密钥的主机，与原有 `hostIds` 求并集；仅授权密钥但没有对应主机的条目会被丢弃。迁移只在内存中进行，下一次写入才把文件升级为 version 2；降级到旧版插件需要恢复 version 1 备份。

可自行核对权限：

```bash
stat -c '%a %n' /data/dsh/ssh-key-vault /data/dsh/ssh-key-vault/vault.json /data/dsh/ssh-key-vault/keys
```

`vault.json` 写入采用「临时文件 + 原子 rename」，并对写操作串行化；文件损坏时接口返回 500（`vault_corrupt`）并保留原文件，**不会静默清空或重建**。

> 若运行环境没有设置 `DSH_HOME`，插件会回退到 `~/.dsh/ssh-key-vault/`；请以实际 `DSH_HOME` 为准。

### 6.2 备份

1. 备份前避免在页面上操作（写入是原子的，但多文件之间仍可能处于不同版本）；
2. 复制整个 `$DSH_HOME/ssh-key-vault/` 目录，保留权限：
   ```bash
   cp -a /data/dsh/ssh-key-vault /path/to/backup/ssh-key-vault-$(date +%F)
   ```
3. 备份包含明文私钥，请按同等敏感级别保护（见 SECURITY）。

### 6.3 恢复

1. 停止 DSH Web（避免恢复期间有写入）；
2. 用备份覆盖 `$DSH_HOME/ssh-key-vault/`，恢复后执行 `chmod 700` 目录、`chmod 600` 文件；
3. 重新启动并刷新页面，确认密钥、主机与授权均可见。

> `vault.json` 与 `keys/` 必须来自同一次备份：只恢复其中之一会出现「授权存在但文件缺失」或「文件在但不可见」的不一致。

### 6.4 卸载

在插件管理器中停用或卸载插件后，数据目录仍保留。如需彻底清除：

```bash
# 确认路径无误后再执行；删除不可恢复
rm -rf /data/dsh/ssh-key-vault
```

---

## 7. HTTP API

插件在 DSH WebServer 上注册同源路由前缀 `/ssh-key-vault`，所有响应为 JSON。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/ssh-key-vault` | 健康检查 |
| GET | `/ssh-key-vault/state` | 密钥、主机、工作区、授权、统计与能力 |
| POST | `/ssh-key-vault/keys/upload` | `{ name?, filename, content }` 上传私钥 |
| POST | `/ssh-key-vault/keys/rename` | `{ id, name }` 重命名 |
| POST | `/ssh-key-vault/keys/delete` | `{ id }` 删除密钥 |
| POST | `/ssh-key-vault/hosts/save` | `{ id?, label, address, port, username, keyId, note? }` 新增或更新主机 |
| POST | `/ssh-key-vault/hosts/delete` | `{ id }` 删除主机；绑定密钥不再被其他主机使用时一并删除 |
| POST | `/ssh-key-vault/access/set` | `{ workspaceId, hostIds }` 覆盖式设置某工作区的主机授权 |

### 7.1 请求约束

- POST 必须 `Content-Type: application/json`，否则 `415`（`unsupported_media_type`）；
- 请求体上限 256 KiB，超限 `413`（`body_too_large`）；上传的 `content` 上限 64 KiB（`key_too_large`）；
- 若带 `Origin`，必须与本站同源（`Origin` 等于 WebServer origin，或 Origin 的 host 等于请求 `Host`），否则 `403`（`origin_forbidden`）；本地 `curl` 不带 `Origin` 可通过；
- 方法不匹配（如对 POST 路由发 GET）返回 `405`；
- 所有响应带 `Cache-Control: no-store` 与 `X-Content-Type-Options: nosniff`，不开放 CORS；
- 所有变更类 POST 的响应会在 `ok` 之外返回操作结果（`key`/`host`/`deletedId`/`deletedKeyId`/`keyRetained`/`access`）与最新的 `state`，调用方无需再请求一次 `/state`。

### 7.2 state 结构

`GET /ssh-key-vault/state` 返回：

```json
{
  "ok": true,
  "capabilities": { "sshKeygen": true },
  "keys": [
    {
      "id": "key_0123456789abcdef",
      "name": "生产服务器",
      "filename": "id_ed25519",
      "fingerprint": "SHA256:...",
      "algorithm": "ED25519",
      "bits": 256,
      "comment": "",
      "createdAt": "2026-01-01T00:00:00.000Z",
      "updatedAt": "2026-01-01T00:00:00.000Z",
      "hostCount": 1,
      "authorizedWorkspaceIds": ["workspace-id"]
    }
  ],
  "hosts": [
    {
      "id": "host_0123456789abcdef",
      "label": "生产 Web",
      "address": "203.0.113.10",
      "port": 22,
      "username": "root",
      "keyId": "key_0123456789abcdef",
      "note": "",
      "createdAt": "2026-01-01T00:00:00.000Z",
      "updatedAt": "2026-01-01T00:00:00.000Z",
      "authorizedWorkspaceIds": []
    }
  ],
  "workspaces": [{ "id": "workspace-id", "title": "Default", "path": "/data/dsh/home/Default" }],
  "access": {
    "workspace-id": {
      "hostIds": ["host_0123456789abcdef"]
    }
  },
  "stats": { "keys": 1, "hosts": 1, "grantedWorkspaces": 0 }
}
```

响应中**不包含**私钥内容、绝对路径或 `relativePath`。`access` 只保存每个工作区被授权的主机；密钥通过主机的 `keyId` 关联。`capabilities.sshKeygen` 为 `false` 时无法上传（见故障排查）。

### 7.3 上传示例

```bash
# 用 jq 把私钥文件转成 JSON 字符串；示例路径请替换为你的文件
jq -Rs '{name:"示例密钥", filename:"id_ed25519", content:.}' < ~/.ssh/id_ed25519 \
  | curl -sS -X POST http://127.0.0.1:3080/ssh-key-vault/keys/upload \
      -H 'Content-Type: application/json' \
      --data-binary @-
```

### 7.4 错误格式

失败统一返回：

```json
{ "ok": false, "error": "中文错误提示", "code": "duplicate_key" }
```

`code` 是稳定的机器可读标识；`500` 不返回堆栈或内部路径。常见状态码与 `code`：

| 状态码 | 典型 `code` | 含义 |
| --- | --- | --- |
| 400 | `invalid_field`、`invalid_address`、`invalid_port`、`invalid_username`、`invalid_note`、`invalid_key_content`、`invalid_name`、`invalid_json`、`empty_body`、`invalid_body`、`invalid_access`、`invalid_workspace`、`workspace_not_found`、`key_not_found`、`invalid_key_id` | 参数缺失、校验失败、未知工作区、`access/set` 的 `hostIds` 引用了不存在的主机或传了旧字段 `keyIds` |
| 403 | `origin_forbidden` | `Origin` 与本站不同源 |
| 404 | `not_found`、`host_not_found` | 路由不存在，或重命名/删除/编辑的密钥、主机 ID 不存在 |
| 405 | `method_not_allowed` | 请求方法不匹配 |
| 409 | `duplicate_key`、`key_in_use`、`key_name_conflict`、`host_label_conflict` | 重复指纹、密钥仍被主机引用、名称冲突 |
| 413 | `body_too_large`、`key_too_large` | 请求体超过 256 KiB 或私钥超过 64 KiB |
| 415 | `unsupported_media_type` | 非 `application/json` |
| 500 | `vault_corrupt`、`internal_error` | `vault.json` 损坏、读写或内部错误 |
| 503 | `ssh_keygen_unavailable` | 宿主机缺少可执行的 `ssh-keygen` |

**同一 ID 在不同接口上的返回可能不同**：例如主机保存时引用不存在的密钥是 400（`key_not_found`），而重命名不存在的密钥是 404（`not_found`）；以 HTTP 状态码与响应中的 `code` 为准。

---

## 8. 限制与安全提示

- **明文存储**：私钥以 0600 明文保存在 `$DSH_HOME/ssh-key-vault/keys/`，没有加密、没有 KMS，备份与磁盘快照同样含明文。
- **授权不是隔离**：工作区授权只记录「哪些主机可用」，主机再带出它绑定的密钥；不改变文件权限，同机同用户的进程（包括 Agent）可以绕过插件直接读文件。
- **仅无口令私钥**：带口令私钥在导入时即被拒绝；请先解密或改用 `ssh-agent`（本插件不托管口令）。
- **不可下载**：插件不提供私钥查看或导出；请自行保存原始私钥副本。
- **删除不可撤销**：删除密钥会同时删除密钥文件，无法从插件恢复；若仍有主机引用该密钥，删除会被拒绝。
- **不接 push-deploy**：本插件与 `dsh-push-deploy` 完全独立，现有 `/data/dsh/push-deploy/keys` 中的密钥不会自动导入，需要手动上传。
- **无 SSH 执行能力**：不测试连通性、不执行命令；Agent 只能通过只读的 `ssh_targets` 获取主机与密钥路径，真正连接仍需自行执行 `ssh`；主机档案仅作记录。
- **无审计日志**：不记录谁在何时使用了哪把密钥；如需审计请在操作系统层做文件访问审计。

部署加固建议（独立 OS 用户、磁盘加密、限制 `DSH_HOME` 访问等）见 [docs/SECURITY.md](docs/SECURITY.md)。

---

## 9. 故障排查

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| 设置里没有「SSH 密钥」 | 插件未安装/未启用；页面未刷新 | 到「设置 → 插件」确认状态为已安装且启用，刷新页面重开设置 |
| `GET /ssh-key-vault` 返回 404 | Host 侧插件未加载，或 bundle 未登记 | 重新安装/启用插件；确认没有手改 profile 文件 |
| 上传提示「私钥校验失败：它可能带有口令…」 | 私钥有 passphrase，或格式不受支持（`key_check_failed`） | 先用 `ssh-keygen -p -f <key>` 去掉口令（会改写原文件，请先备份）再上传 |
| 上传返回 503 `ssh_keygen_unavailable` | 宿主机没有可执行的 OpenSSH 客户端 | 安装 `openssh-client`，确认 `which ssh-keygen` 可执行后刷新页面（`capabilities.sshKeygen` 应为 `true`） |
| 上传返回 400 `invalid_key_content` | 不是私钥、内容为空或缺少 `BEGIN/END ... PRIVATE KEY` 头尾 | 确认上传的是私钥而非公钥/证书；带口令请先解密 |
| 上传返回 409 `duplicate_key` | 该指纹已在库中 | 在列表中重命名/复用已有密钥，不要重复上传 |
| 上传返回 413 `key_too_large`/`body_too_large` | 文件超过 64 KiB 或请求体超过 256 KiB | 私钥文本通常只有几 KB；检查是否误传了其他文件 |
| 删除密钥返回 409 `key_in_use` | 仍有主机引用该密钥 | 先删除主机或把主机改绑到其他密钥，再删除 |
| 删除主机后密钥也消失了 | 该密钥不再被其他主机使用 | 预期行为；密钥仍被其他主机使用时只删主机、保留密钥 |
| 编辑/删除返回 404 | 密钥/主机 ID 不存在（可能已在另一标签页删除） | 刷新页面后重试 |
| POST 返回 403 `origin_forbidden` | 反向代理改写了 `Origin`/`Host`，或跨站调用 | 从同源页面操作；代理需保持同源头 |
| 页面提示「无法读取密钥库状态」，接口 500 | `vault.json` 损坏或不可读 | 恢复备份（§6.3）；不要直接删除 `keys/` |
| 页面一直空白、接口正常 | 浏览器缓存了旧 bundle | 强制刷新（Ctrl/Cmd+Shift+R）或重启 DSH Web |

查看 Host 侧日志可确认插件是否注册了路由；日志只包含请求方法、错误 `code` 与密钥 ID 等最小信息，不会打印私钥内容。

---

## 10. 更多

- 安全模型、威胁边界与加固建议：[docs/SECURITY.md](docs/SECURITY.md)
- 运行单元测试（在插件目录内）：`node --test test/`
- 插件结构：

  ```
  dsh-ssh-key-vault/
  ├── package.json        # @local/dsh-ssh-key-vault，声明 bundle patch 与 web client
  ├── cordis.patch.yml    # 插入 id: ssh-key-vault 的 patch
  ├── index.js            # Host：注册 /ssh-key-vault 路由
  ├── lib/http.js         # 路由、请求校验（同源/JSON/大小）、响应封装
  ├── lib/store.js        # vault.json 与 keys/ 的读写、原子写、权限
  ├── lib/model.js        # 校验、ID、授权计算、状态投影
  ├── lib/tool.js         # Agent 工具：ssh_targets（只读查询）
  ├── lib/ssh.js          # ssh-keygen 校验、指纹解析、密钥落盘
  ├── lib/errors.js       # 带 HTTP 状态与稳定 code 的错误类型
  ├── client.js           # Web Client：设置页「SSH 密钥」
  ├── bin/dsh-ssh-targets.mjs  # 可选 CLI：查询工作区主机与密钥路径
  ├── scripts/workspace-access.mjs  # CLI 实现
  ├── bin/dsh             # 可选 dsh 包装脚本（拦截 ssh-targets）
  ├── locale/zh.json      # 插件管理器展示用名称/描述
  ├── locale/en.json
  ├── icon.svg
  ├── README.md           # 本文
  ├── docs/SECURITY.md    # 安全说明
  └── test/*.test.mjs     # 单元/集成测试（不含真实用户密钥）
  ```
