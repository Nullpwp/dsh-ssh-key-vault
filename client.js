window.__ModuleLoader__.load({
  id: '@local/dsh-ssh-key-vault',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const NS = 'ssh-key-vault'
    const API = '/ssh-key-vault'
    const MAX_KEY_BYTES = 64 * 1024

    const zh = {
      nav: 'SSH 密钥',
      title: 'SSH 密钥库',
      subtitle: '集中管理无口令 SSH 私钥与远程主机档案，并按工作区授予可用范围。',
      securityNote:
        '私钥以 0600 明文保存在本机 DSH 数据目录；工作区授权是使用范围记录，不是操作系统级隔离。',
      loading: '正在加载密钥库…',
      'tabs.keys': '密钥',
      'tabs.hosts': '主机',
      'tabs.access': '工作区授权',
      'stats.keys': '密钥',
      'stats.hosts': '主机',
      'stats.workspaces': '已授权工作区',
      'action.refresh': '刷新',
      'action.retry': '重试',
      'action.upload': '上传',
      'action.uploading': '上传中…',
      'action.save': '保存',
      'action.saving': '保存中…',
      'action.cancel': '取消',
      'action.edit': '编辑',
      'action.delete': '删除',
      'action.rename': '重命名',
      'action.saveName': '保存名称',
      'action.selectAll': '全选',
      'action.clearAll': '清空',
      'action.saveAccess': '保存授权',
      'action.addHost': '添加主机',
      'action.updateHost': '更新主机',
      'action.confirmDelete': '确认删除',
      'action.close': '关闭提示',
      'common.none': '无',
      'common.unknownWorkspace': '未知工作区',
      'common.unknownKey': '未知密钥',
      'notice.uploaded': '已上传密钥「{name}」。',
      'notice.renamed': '已重命名为「{name}」。',
      'notice.keyDeleted': '密钥已删除。',
      'notice.hostSaved': '主机「{label}」已保存。',
      'notice.hostDeleted': '主机已删除。',
      'notice.hostDeletedWithKey': '主机及其绑定密钥已删除。',
      'notice.hostDeletedKeyKept': '主机已删除；绑定密钥仍被其他主机使用，已保留。',
      'notice.accessSaved': '工作区「{title}」的授权已保存。',
      'keys.uploadTitle': '上传私钥',
      'keys.uploadDescription':
        '仅支持无口令私钥。服务端使用 ssh-keygen 校验；带口令或非私钥文件会被拒绝，私钥内容不会在页面中回显。',
      'keys.fileLabel': '私钥文件',
      'keys.fileHint': '支持 OpenSSH 或 PEM 格式，最大 64 KiB。',
      'keys.noFile': '尚未选择文件',
      'keys.nameLabel': '密钥名称（可选）',
      'keys.namePlaceholder': '例如：生产服务器',
      'keys.listTitle': '已上传密钥',
      'keys.empty': '还没有上传任何密钥。',
      'keys.emptyHint': '选择本机的私钥文件并上传后，这里会显示指纹、关联主机和授权工作区。',
      'keys.fingerprint': 'SHA256 指纹',
      'keys.algorithm': '算法',
      'keys.filename': '文件名',
      'keys.hostCount': '关联主机：{count}',
      'keys.workspaces': '授权工作区',
      'keys.noWorkspaces': '未授权任何工作区',
      'keys.deleteHint': '删除会移除密钥文件，且无法从插件恢复。',
      'keys.confirmDelete': '确认删除密钥「{name}」？',
      'keys.confirmDeleteHint': '删除后无法恢复；若仍有主机引用该密钥，删除会被拒绝。',
      'hosts.formAddTitle': '新增主机档案',
      'hosts.formEditTitle': '编辑主机档案',
      'hosts.label': '主机名称',
      'hosts.labelPlaceholder': '例如：生产 Web',
      'hosts.address': '地址',
      'hosts.addressPlaceholder': 'IP、主机名或 [IPv6]',
      'hosts.port': '端口',
      'hosts.username': '用户名',
      'hosts.usernamePlaceholder': '例如：root',
      'hosts.key': '关联密钥',
      'hosts.note': '备注（可选）',
      'hosts.notePlaceholder': '用途、环境或其他说明',
      'hosts.listTitle': '主机列表',
      'hosts.empty': '还没有添加任何主机。',
      'hosts.emptyHint': '填写上方表单，把远程主机与一把密钥关联起来。',
      'hosts.noKeys': '尚未上传密钥',
      'hosts.noKeysHint': '请先在「密钥」标签页上传至少一把私钥，再添加主机。',
      'hosts.keyMissing': '未知密钥',
      'hosts.confirmDelete': '确认删除主机「{label}」？',
      'hosts.confirmDeleteHint': '删除后该主机的所有工作区授权会被移除；若绑定密钥不再被其他主机使用，会一并删除，否则保留。',
      'access.workspaceLabel': '工作区',
      'access.selectWorkspace': '请选择工作区',
      'access.noWorkspaces': '当前没有可用工作区。',
      'access.noWorkspacesHint': '工作区创建后会出现在这里。',
      'access.hostsTitle': 'SSH 主机（含绑定密钥）',
      'access.emptyHosts': '还没有可授权的主机。',
      'access.directHint': '勾选主机即授权该主机及其绑定密钥；密钥随主机生效，不再单独授权密钥。',
      'access.unsaved': '有未保存的授权变更。',
      'access.selectedCount': '已选 {selected} / {total}',
      'access.previewTitle': '本次授权预览',
      'access.previewHint': '以下内容按当前勾选计算，保存后对该工作区生效。',
      'access.previewKeys': '随主机带出的密钥',
      'access.previewHosts': '授权主机',
      'access.previewEmpty': '当前没有授权主机。',
      'error.generic': '请求失败，请稍后重试。',
      'error.http': '请求失败（HTTP {status}）。',
      'error.load': '无法读取密钥库状态。',
      'error.fileTooLarge': '文件超过 64 KiB，无法上传。',
      'error.readFile': '无法读取所选文件。',
      'error.duplicateKey': '相同指纹的私钥已经存在。',
      'error.keyCheckFailed': '私钥校验失败：它可能带有口令，或不是受支持的私钥格式。',
      'error.keyFingerprintFailed': '无法读取该私钥的指纹信息。',
      'error.keyTooLarge': '私钥文件不能超过 64 KiB。',
      'error.keyInUse': '该密钥仍被主机引用，请先删除或改绑这些主机。',
      'error.keyNameConflict': '密钥名称已存在，请换一个名称。',
      'error.hostLabelConflict': '主机名称已存在，请换一个名称。',
      'error.invalidKeyContent': '文件不是受支持的 SSH 私钥。',
      'error.sshKeygenUnavailable': '服务器未安装 ssh-keygen，暂时无法校验私钥。',
      'error.vaultCorrupt': '密钥库数据文件损坏；插件未重置数据，请先备份并手动修复。',
      'error.bodyTooLarge': '请求内容过大。',
      'error.workspaceNotFound': '工作区不存在或已被删除。',
      'error.originForbidden': '请求来源不被允许。',
      'error.internal': '服务器内部错误，请稍后重试。',
      'error.invalidField': '输入内容无效，请检查后重试。',
      'error.invalidAddress': '主机地址无效，请填写 IPv4、主机名或 [IPv6]。',
      'error.invalidPort': '端口必须是 1-65535 的整数。',
      'error.invalidUsername': '用户名只能包含字母、数字、点、下划线和连字符（1-64 位）。',
      'error.invalidNote': '备注内容无效或过长。',
      'error.invalidKey': '所选密钥不存在，请刷新后重试。',
      'error.invalidAccess': '授权内容引用了不存在的密钥或主机，请刷新后重试。',
      'error.invalidRequest': '请求格式无效，请刷新页面后重试。',
      'error.notFound': '目标不存在或已被删除。',
    }

    const en = {
      nav: 'SSH keys',
      title: 'SSH key vault',
      subtitle: 'Manage unencrypted SSH private keys and remote host profiles, then grant their use per workspace.',
      securityNote:
        'Private keys are stored unencrypted with 0600 permissions in the local DSH data directory. Workspace grants record intended use; they are not operating-system isolation.',
      loading: 'Loading the key vault…',
      'tabs.keys': 'Keys',
      'tabs.hosts': 'Hosts',
      'tabs.access': 'Workspace grants',
      'stats.keys': 'Keys',
      'stats.hosts': 'Hosts',
      'stats.workspaces': 'Granted workspaces',
      'action.refresh': 'Refresh',
      'action.retry': 'Retry',
      'action.upload': 'Upload',
      'action.uploading': 'Uploading…',
      'action.save': 'Save',
      'action.saving': 'Saving…',
      'action.cancel': 'Cancel',
      'action.edit': 'Edit',
      'action.delete': 'Delete',
      'action.rename': 'Rename',
      'action.saveName': 'Save name',
      'action.selectAll': 'Select all',
      'action.clearAll': 'Clear',
      'action.saveAccess': 'Save grants',
      'action.addHost': 'Add host',
      'action.updateHost': 'Update host',
      'action.confirmDelete': 'Confirm delete',
      'action.close': 'Dismiss notice',
      'common.none': 'None',
      'common.unknownWorkspace': 'Unknown workspace',
      'common.unknownKey': 'Unknown key',
      'notice.uploaded': 'Uploaded key “{name}”.',
      'notice.renamed': 'Renamed to “{name}”.',
      'notice.keyDeleted': 'Key deleted.',
      'notice.hostSaved': 'Host “{label}” saved.',
      'notice.hostDeleted': 'Host deleted.',
      'notice.hostDeletedWithKey': 'Host and its bound key deleted.',
      'notice.hostDeletedKeyKept': 'Host deleted; its bound key is still used by another host and was kept.',
      'notice.accessSaved': 'Grants for “{title}” saved.',
      'keys.uploadTitle': 'Upload a private key',
      'keys.uploadDescription':
        'Only unencrypted private keys are supported. The server validates them with ssh-keygen; passphrase-protected or non-key files are rejected, and key contents are never shown here.',
      'keys.fileLabel': 'Private key file',
      'keys.fileHint': 'OpenSSH or PEM format, up to 64 KiB.',
      'keys.noFile': 'No file selected',
      'keys.nameLabel': 'Key name (optional)',
      'keys.namePlaceholder': 'For example, Production server',
      'keys.listTitle': 'Uploaded keys',
      'keys.empty': 'No keys have been uploaded yet.',
      'keys.emptyHint': 'Choose a private key file and upload it; its fingerprint, linked hosts, and granted workspaces will appear here.',
      'keys.fingerprint': 'SHA256 fingerprint',
      'keys.algorithm': 'Algorithm',
      'keys.filename': 'Filename',
      'keys.hostCount': 'Linked hosts: {count}',
      'keys.workspaces': 'Granted workspaces',
      'keys.noWorkspaces': 'Not granted to any workspace',
      'keys.deleteHint': 'Deleting removes the key file and cannot be undone from this plugin.',
      'keys.confirmDelete': 'Delete key “{name}”?',
      'keys.confirmDeleteHint': 'This cannot be undone. Deleting is refused while any host still references the key.',
      'hosts.formAddTitle': 'Add a host profile',
      'hosts.formEditTitle': 'Edit host profile',
      'hosts.label': 'Host name',
      'hosts.labelPlaceholder': 'For example, Production web',
      'hosts.address': 'Address',
      'hosts.addressPlaceholder': 'IP, hostname, or [IPv6]',
      'hosts.port': 'Port',
      'hosts.username': 'Username',
      'hosts.usernamePlaceholder': 'For example, root',
      'hosts.key': 'Linked key',
      'hosts.note': 'Note (optional)',
      'hosts.notePlaceholder': 'Purpose, environment, or other details',
      'hosts.listTitle': 'Hosts',
      'hosts.empty': 'No hosts have been added yet.',
      'hosts.emptyHint': 'Fill in the form above to link a remote host to a key.',
      'hosts.noKeys': 'No keys uploaded yet',
      'hosts.noKeysHint': 'Upload at least one private key on the Keys tab before adding a host.',
      'hosts.keyMissing': 'Unknown key',
      'hosts.confirmDelete': 'Delete host “{label}”?',
      'hosts.confirmDeleteHint': 'All workspace grants for this host are removed. If its key is no longer used by another host, the key is deleted too; otherwise it is kept.',
      'access.workspaceLabel': 'Workspace',
      'access.selectWorkspace': 'Select a workspace',
      'access.noWorkspaces': 'No workspaces are available.',
      'access.noWorkspacesHint': 'Workspaces appear here after they are created.',
      'access.hostsTitle': 'SSH hosts (with bound key)',
      'access.emptyHosts': 'No hosts are available to grant.',
      'access.directHint': 'Checking a host grants that host and its bound key. Keys follow hosts; there is no separate key grant.',
      'access.unsaved': 'You have unsaved grant changes.',
      'access.selectedCount': '{selected} of {total} selected',
      'access.previewTitle': 'Grant preview',
      'access.previewHint': 'This preview follows the current selection and applies to the workspace after saving.',
      'access.previewKeys': 'Keys brought by hosts',
      'access.previewHosts': 'Granted hosts',
      'access.previewEmpty': 'No hosts are currently granted.',
      'error.generic': 'The request failed. Please try again.',
      'error.http': 'The request failed (HTTP {status}).',
      'error.load': 'Could not read the key vault state.',
      'error.fileTooLarge': 'The file is larger than 64 KiB and cannot be uploaded.',
      'error.readFile': 'Could not read the selected file.',
      'error.duplicateKey': 'A key with the same fingerprint already exists.',
      'error.keyCheckFailed': 'Key validation failed: it may be passphrase-protected or in an unsupported format.',
      'error.keyFingerprintFailed': 'Could not read the fingerprint of this key.',
      'error.keyTooLarge': 'The private key file must not exceed 64 KiB.',
      'error.keyInUse': 'This key is still referenced by hosts. Delete or relink those hosts first.',
      'error.keyNameConflict': 'That key name already exists. Choose another one.',
      'error.hostLabelConflict': 'That host name already exists. Choose another one.',
      'error.invalidKeyContent': 'The file is not a supported SSH private key.',
      'error.sshKeygenUnavailable': 'ssh-keygen is not installed on the server, so keys cannot be validated right now.',
      'error.vaultCorrupt': 'The key vault data file is damaged. It was not reset; back it up and repair it manually.',
      'error.bodyTooLarge': 'The request body is too large.',
      'error.workspaceNotFound': 'The workspace does not exist or was deleted.',
      'error.originForbidden': 'The request origin is not allowed.',
      'error.internal': 'Internal server error. Please try again.',
      'error.invalidField': 'The input is invalid. Check it and try again.',
      'error.invalidAddress': 'The host address is invalid. Use IPv4, a hostname, or [IPv6].',
      'error.invalidPort': 'The port must be an integer from 1 to 65535.',
      'error.invalidUsername': 'The username may contain letters, digits, dots, underscores, and hyphens only (1–64 characters).',
      'error.invalidNote': 'The note is invalid or too long.',
      'error.invalidKey': 'The selected key no longer exists. Refresh and try again.',
      'error.invalidAccess': 'The grant references a key or host that no longer exists. Refresh and try again.',
      'error.invalidRequest': 'The request format is invalid. Refresh the page and try again.',
      'error.notFound': 'The target does not exist or was deleted.',
    }

    const ERROR_KEYS = {
      duplicate_key: 'error.duplicateKey',
      key_check_failed: 'error.keyCheckFailed',
      key_check_timeout: 'error.keyCheckFailed',
      key_fingerprint_failed: 'error.keyFingerprintFailed',
      key_too_large: 'error.keyTooLarge',
      key_in_use: 'error.keyInUse',
      key_name_conflict: 'error.keyNameConflict',
      host_label_conflict: 'error.hostLabelConflict',
      invalid_key_content: 'error.invalidKeyContent',
      ssh_keygen_unavailable: 'error.sshKeygenUnavailable',
      vault_corrupt: 'error.vaultCorrupt',
      body_too_large: 'error.bodyTooLarge',
      workspace_not_found: 'error.workspaceNotFound',
      origin_forbidden: 'error.originForbidden',
      internal_error: 'error.internal',
      read_file: 'error.readFile',
      invalid_field: 'error.invalidField',
      invalid_address: 'error.invalidAddress',
      invalid_port: 'error.invalidPort',
      invalid_username: 'error.invalidUsername',
      invalid_note: 'error.invalidNote',
      key_not_found: 'error.invalidKey',
      invalid_key_id: 'error.invalidKey',
      invalid_access: 'error.invalidAccess',
      invalid_workspace: 'error.invalidRequest',
      invalid_body: 'error.invalidRequest',
      empty_body: 'error.invalidRequest',
      invalid_json: 'error.invalidRequest',
      invalid_path: 'error.invalidRequest',
      request_aborted: 'error.invalidRequest',
      method_not_allowed: 'error.invalidRequest',
      unsupported_media_type: 'error.invalidRequest',
      not_found: 'error.notFound',
      host_not_found: 'error.notFound',
    }

    const CSS = `
      .skv-root{display:flex;flex-direction:column;gap:18px;width:100%;box-sizing:border-box;padding:4px 0 28px;color:var(--dsw-alias-label-primary);font-size:14px;line-height:22px}
      .skv-header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}
      .skv-title{margin:0;font-size:16px;font-weight:600;line-height:24px}
      .skv-subtitle{margin:4px 0 0;max-width:660px;color:var(--dsw-alias-label-secondary);font-size:12px;line-height:18px}
      .skv-security{display:flex;gap:8px;align-items:flex-start;box-sizing:border-box;padding:10px 12px;border:.5px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-secondary);font-size:12px;line-height:18px}
      .skv-security-dot{flex:none;width:6px;height:6px;margin-top:6px;border-radius:50%;background:var(--dsw-alias-brand-primary)}
      .skv-stats{display:flex;gap:8px;flex-wrap:wrap}
      .skv-stat{box-sizing:border-box;min-width:96px;padding:8px 12px;border:.5px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1)}
      .skv-stat-value{font-size:18px;font-weight:600;line-height:24px}
      .skv-stat-label{color:var(--dsw-alias-label-secondary);font-size:11px;line-height:16px}
      .skv-tabs{display:flex;gap:4px;border-bottom:.5px solid var(--dsw-alias-border-l2);padding-bottom:6px;flex-wrap:wrap}
      .skv-tab{appearance:none;border:0;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:13px;line-height:20px;padding:5px 12px;border-radius:6px;cursor:pointer}
      .skv-tab:hover{background:var(--dsw-alias-bg-layer-2)}
      .skv-tab-active{color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-layer-2);font-weight:500}
      .skv-stack{display:flex;flex-direction:column;gap:14px}
      .skv-card{box-sizing:border-box;display:flex;flex-direction:column;gap:12px;padding:16px;border:.5px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-1)}
      .skv-card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
      .skv-card-title{margin:0;font-size:14px;font-weight:600;line-height:20px}
      .skv-card-description{margin:0;color:var(--dsw-alias-label-secondary);font-size:12px;line-height:18px}
      .skv-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
      .skv-form-grid .skv-span-2{grid-column:1 / -1}
      .skv-field{display:flex;flex-direction:column;gap:5px;min-width:0}
      .skv-field-label{color:var(--dsw-alias-label-secondary);font-size:12px;line-height:18px}
      .skv-field-hint{color:var(--dsw-alias-label-secondary);font-size:11px;line-height:16px}
      .skv-input,.skv-select,.skv-textarea{box-sizing:border-box;width:100%;min-width:0;padding:0 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:6px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);font:inherit;font-size:13px;line-height:30px;height:32px}
      .skv-input:focus,.skv-select:focus,.skv-textarea:focus{outline:1px solid var(--dsw-alias-brand-primary);outline-offset:0;border-color:var(--dsw-alias-border-l2)}
      .skv-textarea{height:auto;min-height:66px;padding:7px 10px;line-height:18px;resize:vertical}
      .skv-input:disabled,.skv-select:disabled,.skv-textarea:disabled{opacity:.6;cursor:not-allowed}
      .skv-file-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
      .skv-file{max-width:100%;min-width:0;color:var(--dsw-alias-label-secondary);font-size:12px}
      .skv-file-name{overflow-wrap:anywhere;color:var(--dsw-alias-label-primary)}
      .skv-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}
      .skv-btn{appearance:none;box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;gap:6px;height:30px;padding:0 12px;border:1px solid var(--dsw-alias-border-l2);border-radius:6px;background:transparent;color:var(--dsw-alias-label-primary);font:inherit;font-size:12px;line-height:20px;cursor:pointer;white-space:nowrap}
      .skv-btn:hover:not(:disabled){background:var(--dsw-alias-bg-layer-2)}
      .skv-btn:disabled{opacity:.55;cursor:not-allowed}
      .skv-btn-primary{border-color:var(--dsw-alias-brand-primary);background:transparent;color:var(--dsw-alias-brand-primary)}
      .skv-btn-primary:hover:not(:disabled){background:var(--dsw-alias-bg-layer-2)}
      .skv-btn-danger{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-border-l2)}
      .skv-btn-danger:hover:not(:disabled){background:var(--dsw-alias-bg-layer-2)}
      .skv-btn-small{height:26px;padding:0 9px;font-size:11px}
      .skv-notice{box-sizing:border-box;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:10px 12px;border:.5px solid var(--dsw-alias-border-l2);border-radius:8px;font-size:12px;line-height:18px}
      .skv-notice-success{color:var(--dsw-alias-state-success-primary)}
      .skv-notice-error{color:var(--dsw-alias-state-error-primary)}
      .skv-notice-info{color:var(--dsw-alias-label-secondary)}
      .skv-list{display:flex;flex-direction:column;gap:10px}
      .skv-item{box-sizing:border-box;display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:12px;border:.5px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1);flex-wrap:wrap}
      .skv-item-main{display:flex;flex-direction:column;gap:5px;min-width:220px;flex:1}
      .skv-item-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
      .skv-item-title{font-size:13px;font-weight:600;line-height:20px;overflow-wrap:anywhere}
      .skv-badge{display:inline-flex;align-items:center;height:20px;padding:0 7px;border-radius:999px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-secondary);font-size:11px;line-height:20px;white-space:nowrap}
      .skv-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;line-height:17px;overflow-wrap:anywhere}
      .skv-fingerprint{color:var(--dsw-alias-label-secondary)}
      .skv-meta{color:var(--dsw-alias-label-secondary);font-size:11px;line-height:17px;overflow-wrap:anywhere}
      .skv-chips{display:flex;gap:4px;flex-wrap:wrap;margin-top:2px}
      .skv-chip{display:inline-flex;align-items:center;height:20px;padding:0 7px;border:.5px solid var(--dsw-alias-border-l2);border-radius:4px;color:var(--dsw-alias-label-secondary);font-size:11px;line-height:20px;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
      .skv-item-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
      .skv-inline-form{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
      .skv-inline-form .skv-input{width:180px}
      .skv-confirm{box-sizing:border-box;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;width:100%;padding:10px 12px;border:.5px solid var(--dsw-alias-state-error-primary);border-radius:8px;background:var(--dsw-alias-bg-layer-1);flex-wrap:wrap}
      .skv-confirm-text{display:flex;flex-direction:column;gap:3px;min-width:220px;flex:1;font-size:12px;line-height:18px}
      .skv-confirm-title{color:var(--dsw-alias-state-error-primary);font-weight:500}
      .skv-confirm-hint{color:var(--dsw-alias-label-secondary)}
      .skv-empty{display:flex;flex-direction:column;gap:4px;padding:18px 12px;text-align:center;color:var(--dsw-alias-label-secondary);font-size:12px;line-height:18px}
      .skv-empty-title{color:var(--dsw-alias-label-primary);font-size:13px;font-weight:500}
      .skv-hint{color:var(--dsw-alias-label-secondary);font-size:11px;line-height:17px}
      .skv-check-group{display:flex;flex-direction:column;gap:6px;max-height:260px;overflow:auto;padding:8px;border:.5px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1)}
      .skv-check{display:flex;align-items:flex-start;gap:8px;padding:5px 7px;border-radius:4px;cursor:pointer;font-size:12px;line-height:18px}
      .skv-check:hover{background:var(--dsw-alias-bg-layer-2)}
      .skv-check input{margin:2px 0 0;flex:none}
      .skv-check-text{display:flex;flex-direction:column;min-width:0}
      .skv-check-title{color:var(--dsw-alias-label-primary);overflow-wrap:anywhere}
      .skv-check-meta{color:var(--dsw-alias-label-secondary);font-size:11px;line-height:16px;overflow-wrap:anywhere}
      .skv-group-head{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
      .skv-group-title{display:flex;align-items:center;gap:6px;font-size:12px;font-weight:600;line-height:18px}
      .skv-count{color:var(--dsw-alias-label-secondary);font-weight:400;font-size:11px}
      .skv-access-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:14px}
      .skv-preview{display:flex;flex-direction:column;gap:8px;padding:12px;border:.5px solid var(--dsw-alias-border-l2);border-radius:8px;background:var(--dsw-alias-bg-layer-1)}
      .skv-preview-row{display:flex;flex-direction:column;gap:4px}
      .skv-preview-label{color:var(--dsw-alias-label-secondary);font-size:11px;line-height:16px}
      .skv-unsaved{color:var(--dsw-alias-state-warn-primary);font-size:11px;line-height:17px}
      @media (width<=767px){.skv-form-grid,.skv-access-grid{grid-template-columns:minmax(0,1fr)}.skv-item{align-items:stretch}.skv-item-actions{justify-content:flex-start}.skv-inline-form .skv-input{width:100%}}
    `

    function createRequester() {
      let current = null
      async function request(path, body) {
        current?.abort()
        const controller = new AbortController()
        current = controller
        try {
          const init = {
            method: body === undefined ? 'GET' : 'POST',
            signal: controller.signal,
            cache: 'no-store',
            credentials: 'same-origin',
          }
          if (body !== undefined) {
            init.headers = { 'content-type': 'application/json' }
            init.body = JSON.stringify(body)
          }
          const response = await fetch(`${API}${path}`, init)
          let data
          try {
            data = await response.json()
          } catch {
            data = undefined
          }
          if (!response.ok || !data || data.ok !== true) {
            const error = new Error('')
            error.code = data?.code || 'http_error'
            error.status = response.status
            throw error
          }
          return data
        } finally {
          if (current === controller) current = null
        }
      }
      return {
        request,
        abort() {
          current?.abort()
          current = null
        },
      }
    }

    function accessDraft(state, workspaceId) {
      const entry = state?.access?.[workspaceId]
      return {
        hostIds: Array.isArray(entry?.hostIds) ? [...entry.hostIds] : [],
      }
    }

    function sameIds(left, right) {
      if (left.length !== right.length) return false
      const sortedLeft = [...left].sort()
      const sortedRight = [...right].sort()
      return sortedLeft.every((value, index) => value === sortedRight[index])
    }

    function isDraftDirty(state, workspaceId, draft) {
      if (!state || !workspaceId || !draft) return false
      const saved = accessDraft(state, workspaceId)
      return !sameIds(saved.hostIds, draft.hostIds)
    }

    function accessPreview(state, draft) {
      const hostMap = new Map((state?.hosts ?? []).map((host) => [host.id, host]))
      const keyMap = new Map((state?.keys ?? []).map((key) => [key.id, key]))
      const hosts = (draft?.hostIds ?? []).map((id) => hostMap.get(id)).filter(Boolean)
      const keyIds = [...new Set(hosts.map((host) => host.keyId))]
      return {
        hosts,
        keys: keyIds.map((id) => keyMap.get(id)).filter(Boolean),
      }
    }

    function describeError(t, notice) {
      if (!notice) return ''
      if (notice.kind === 'success') return t(notice.key, notice.params)
      const mapped = notice.error?.code ? ERROR_KEYS[notice.error.code] : undefined
      if (mapped) return t(mapped)
      if (notice.error?.code === 'http_error') {
        return t('error.http', { status: notice.error.status ?? '' })
      }
      return t('error.generic')
    }

    function field(label, control, hint, extraClass) {
      return h(
        'label',
        { className: `skv-field${extraClass ? ` ${extraClass}` : ''}` },
        h('span', { className: 'skv-field-label' }, label),
        control,
        hint ? h('span', { className: 'skv-field-hint' }, hint) : null,
      )
    }

    function Section({ t }) {
      const requesterRef = React.useRef(null)
      if (!requesterRef.current) requesterRef.current = createRequester()
      const request = requesterRef.current.request

      const [state, setState] = React.useState(null)
      const [loading, setLoading] = React.useState(true)
      const [error, setError] = React.useState(null)
      const [notice, setNotice] = React.useState(null)
      const [busy, setBusy] = React.useState('')
      const [tab, setTab] = React.useState('keys')

      const [selectedFile, setSelectedFile] = React.useState(null)
      const [loadName, setLoadName] = React.useState('')
      const fileInputRef = React.useRef(null)
      const [renameId, setRenameId] = React.useState(null)
      const [renameValue, setRenameValue] = React.useState('')
      const [pendingDelete, setPendingDelete] = React.useState(null)

      const [hostForm, setHostForm] = React.useState({
        label: '',
        address: '',
        port: '22',
        username: 'root',
        keyId: '',
        note: '',
      })
      const [editingHostId, setEditingHostId] = React.useState(null)

      const [accessWorkspaceId, setAccessWorkspaceId] = React.useState('')
      const [draft, setDraft] = React.useState(null)

      const disabled = Boolean(busy)

      const refresh = React.useCallback(async () => {
        setLoading(true)
        setError(null)
        try {
          const data = await request('/state')
          setState(data)
        } catch (failure) {
          if (failure?.name !== 'AbortError') setError(failure)
        } finally {
          setLoading(false)
        }
      }, [request])

      React.useEffect(() => {
        void refresh()
        return () => requesterRef.current?.abort()
      }, [refresh])

      React.useEffect(() => {
        if (!state) return
        const exists = state.workspaces.some((workspace) => workspace.id === accessWorkspaceId)
        if (!exists) {
          setAccessWorkspaceId(state.workspaces[0]?.id ?? '')
          setDraft(state.workspaces[0] ? accessDraft(state, state.workspaces[0].id) : null)
        }
      }, [state, accessWorkspaceId])

      React.useEffect(() => {
        if (!state || !accessWorkspaceId) {
          setDraft(null)
          return
        }
        setDraft(accessDraft(state, accessWorkspaceId))
      }, [state, accessWorkspaceId])

      React.useEffect(() => {
        if (!state) return
        if (!state.keys.some((key) => key.id === hostForm.keyId)) {
          setHostForm((current) => ({ ...current, keyId: state.keys[0]?.id ?? '' }))
        }
      }, [state, hostForm.keyId])

      function resetHostForm() {
        setEditingHostId(null)
        setHostForm({
          label: '',
          address: '',
          port: '22',
          username: 'root',
          keyId: state?.keys[0]?.id ?? '',
          note: '',
        })
      }

      function workspaceTitle(workspaceId) {
        const workspace = state?.workspaces.find((item) => item.id === workspaceId)
        return workspace?.title || workspaceId
      }

      function keyName(keyId) {
        return state?.keys.find((key) => key.id === keyId)?.name || t('common.unknownKey')
      }

      async function handleUpload(event) {
        event.preventDefault()
        if (!selectedFile) return
        if (selectedFile.size > MAX_KEY_BYTES) {
          setNotice({ kind: 'error', error: { code: 'key_too_large', message: t('error.fileTooLarge') } })
          return
        }
        setBusy('upload')
        setNotice(null)
        try {
          let content
          try {
            content = await selectedFile.text()
          } catch {
            throw Object.assign(new Error(t('error.readFile')), { code: 'read_file' })
          }
          const data = await request('/keys/upload', {
            name: loadName.trim() || undefined,
            filename: selectedFile.name,
            content,
          })
          if (data.state) setState(data.state)
          setNotice({ kind: 'success', key: 'notice.uploaded', params: { name: data.key?.name ?? '' } })
          setSelectedFile(null)
          setLoadName('')
          if (fileInputRef.current) fileInputRef.current.value = ''
        } catch (failure) {
          if (failure?.name !== 'AbortError') setNotice({ kind: 'error', error: failure })
        } finally {
          setBusy('')
        }
      }

      async function handleRename(id) {
        const value = renameValue.trim()
        if (!value) return
        setBusy('rename')
        setNotice(null)
        try {
          const data = await request('/keys/rename', { id, name: value })
          if (data.state) setState(data.state)
          setNotice({ kind: 'success', key: 'notice.renamed', params: { name: data.key?.name ?? value } })
          setRenameId(null)
          setRenameValue('')
        } catch (failure) {
          if (failure?.name !== 'AbortError') setNotice({ kind: 'error', error: failure })
        } finally {
          setBusy('')
        }
      }

      async function handleHostSave(event) {
        event.preventDefault()
        setBusy('host')
        setNotice(null)
        try {
          const payload = {
            label: hostForm.label,
            address: hostForm.address,
            port: hostForm.port,
            username: hostForm.username,
            keyId: hostForm.keyId,
            note: hostForm.note,
          }
          if (editingHostId) payload.id = editingHostId
          const data = await request('/hosts/save', payload)
          if (data.state) setState(data.state)
          setNotice({
            kind: 'success',
            key: 'notice.hostSaved',
            params: { label: data.host?.label ?? payload.label },
          })
          resetHostForm()
        } catch (failure) {
          if (failure?.name !== 'AbortError') setNotice({ kind: 'error', error: failure })
        } finally {
          setBusy('')
        }
      }

      async function handleDelete() {
        const target = pendingDelete
        if (!target) return
        setBusy('delete')
        setNotice(null)
        try {
          const path = target.kind === 'key' ? '/keys/delete' : '/hosts/delete'
          const data = await request(path, { id: target.id })
          if (data.state) setState(data.state)
          const noticeKey = target.kind === 'key'
            ? 'notice.keyDeleted'
            : data.deletedKeyId
              ? 'notice.hostDeletedWithKey'
              : data.keyRetained
                ? 'notice.hostDeletedKeyKept'
                : 'notice.hostDeleted'
          setNotice({ kind: 'success', key: noticeKey })
          if (target.kind === 'host' && editingHostId === target.id) resetHostForm()
          if (target.kind === 'key' && renameId === target.id) {
            setRenameId(null)
            setRenameValue('')
          }
          setPendingDelete(null)
        } catch (failure) {
          if (failure?.name !== 'AbortError') setNotice({ kind: 'error', error: failure })
        } finally {
          setBusy('')
        }
      }

      async function handleAccessSave() {
        if (!accessWorkspaceId || !draft) return
        setBusy('access')
        setNotice(null)
        try {
          const data = await request('/access/set', {
            workspaceId: accessWorkspaceId,
            hostIds: draft.hostIds,
          })
          if (data.state) setState(data.state)
          setNotice({
            kind: 'success',
            key: 'notice.accessSaved',
            params: { title: workspaceTitle(accessWorkspaceId) },
          })
        } catch (failure) {
          if (failure?.name !== 'AbortError') setNotice({ kind: 'error', error: failure })
        } finally {
          setBusy('')
        }
      }

      function toggleHost(id) {
        setDraft((current) => {
          if (!current) return current
          return {
            ...current,
            hostIds: current.hostIds.includes(id)
              ? current.hostIds.filter((value) => value !== id)
              : [...current.hostIds, id],
          }
        })
      }

      function setHosts(hostIds) {
        setDraft((current) => (current ? { ...current, hostIds } : current))
      }

      function startEditHost(host) {
        setEditingHostId(host.id)
        setHostForm({
          label: host.label,
          address: host.address,
          port: String(host.port),
          username: host.username,
          keyId: host.keyId,
          note: host.note ?? '',
        })
        setNotice(null)
      }

      function renderNotice() {
        if (!notice) return null
        const isError = notice.kind === 'error'
        return h(
          'div',
          {
            className: `skv-notice ${isError ? 'skv-notice-error' : 'skv-notice-success'}`,
            role: isError ? 'alert' : 'status',
            'aria-live': 'polite',
          },
          h('span', null, describeError(t, notice)),
          h(
            'button',
            {
              type: 'button',
              className: 'skv-btn skv-btn-small',
              onClick: () => setNotice(null),
              'aria-label': t('action.close'),
            },
            '×',
          ),
        )
      }

      function renderKeysPanel() {
        if (!state) return null
        return h(
          'div',
          { className: 'skv-stack' },
          h(
            'form',
            { className: 'skv-card', onSubmit: handleUpload },
            h('h3', { className: 'skv-card-title' }, t('keys.uploadTitle')),
            h('p', { className: 'skv-card-description' }, t('keys.uploadDescription')),
            h(
              'div',
              { className: 'skv-form-grid' },
              field(
                t('keys.fileLabel'),
                h(
                  'div',
                  { className: 'skv-file-row' },
                  h('input', {
                    ref: fileInputRef,
                    type: 'file',
                    className: 'skv-file',
                    accept: '.pem,.key,id_rsa,id_ed25519,id_ecdsa',
                    disabled,
                    onChange: (event) => {
                      setSelectedFile(event.target.files?.[0] ?? null)
                      setNotice(null)
                    },
                  }),
                  h(
                    'span',
                    { className: 'skv-file-name' },
                    selectedFile ? selectedFile.name : t('keys.noFile'),
                  ),
                ),
                t('keys.fileHint'),
              ),
              field(
                t('keys.nameLabel'),
                h('input', {
                  className: 'skv-input',
                  type: 'text',
                  value: loadName,
                  maxLength: 80,
                  placeholder: t('keys.namePlaceholder'),
                  disabled,
                  autoComplete: 'off',
                  onChange: (event) => setLoadName(event.target.value),
                }),
              ),
            ),
            h(
              'div',
              { className: 'skv-actions' },
              h(
                'button',
                {
                  type: 'submit',
                  className: 'skv-btn skv-btn-primary',
                  disabled: disabled || !selectedFile,
                },
                busy === 'upload' ? t('action.uploading') : t('action.upload'),
              ),
            ),
          ),
          h(
            'div',
            { className: 'skv-card' },
            h(
              'div',
              { className: 'skv-card-head' },
              h('h3', { className: 'skv-card-title' }, t('keys.listTitle')),
              h('span', { className: 'skv-badge' }, state.keys.length),
            ),
            state.keys.length === 0
              ? h(
                  'div',
                  { className: 'skv-empty' },
                  h('span', { className: 'skv-empty-title' }, t('keys.empty')),
                  h('span', null, t('keys.emptyHint')),
                )
              : h(
                  'div',
                  { className: 'skv-list' },
                  state.keys.map((key) =>
                    h(
                      'div',
                      { className: 'skv-item', key: key.id },
                      h(
                        'div',
                        { className: 'skv-item-main' },
                        h(
                          'div',
                          { className: 'skv-item-head' },
                          h('span', { className: 'skv-item-title' }, key.name),
                          h('span', { className: 'skv-badge' }, `${key.algorithm} · ${key.bits}`),
                        ),
                        h(
                          'div',
                          { className: 'skv-mono skv-fingerprint' },
                          `${t('keys.fingerprint')}: ${key.fingerprint}`,
                        ),
                        h(
                          'div',
                          { className: 'skv-meta' },
                          `${t('keys.filename')}: ${key.filename} · ${t('keys.hostCount', {
                            count: key.hostCount,
                          })}`,
                        ),
                        h(
                          'div',
                          { className: 'skv-chips' },
                          key.authorizedWorkspaceIds.length === 0
                            ? h('span', { className: 'skv-meta' }, t('keys.noWorkspaces'))
                            : key.authorizedWorkspaceIds.map((workspaceId) =>
                                h(
                                  'span',
                                  { className: 'skv-chip', key: workspaceId },
                                  workspaceTitle(workspaceId),
                                ),
                              ),
                        ),
                        pendingDelete?.kind === 'key' && pendingDelete.id === key.id
                          ? h(
                              'div',
                              { className: 'skv-confirm' },
                              h(
                                'div',
                                { className: 'skv-confirm-text' },
                                h(
                                  'span',
                                  { className: 'skv-confirm-title' },
                                  t('keys.confirmDelete', { name: key.name }),
                                ),
                                h('span', { className: 'skv-confirm-hint' }, t('keys.confirmDeleteHint')),
                              ),
                              h(
                                'div',
                                { className: 'skv-actions' },
                                h(
                                  'button',
                                  {
                                    type: 'button',
                                    className: 'skv-btn skv-btn-danger',
                                    disabled,
                                    onClick: handleDelete,
                                  },
                                  t('action.confirmDelete'),
                                ),
                                h(
                                  'button',
                                  {
                                    type: 'button',
                                    className: 'skv-btn',
                                    disabled,
                                    onClick: () => setPendingDelete(null),
                                  },
                                  t('action.cancel'),
                                ),
                              ),
                            )
                          : null,
                      ),
                      h(
                        'div',
                        { className: 'skv-item-actions' },
                        renameId === key.id
                          ? h(
                              'div',
                              { className: 'skv-inline-form' },
                              h('input', {
                                className: 'skv-input',
                                type: 'text',
                                value: renameValue,
                                maxLength: 80,
                                disabled,
                                autoComplete: 'off',
                                'aria-label': t('keys.nameLabel'),
                                onChange: (event) => setRenameValue(event.target.value),
                                onKeyDown: (event) => {
                                  if (event.key === 'Enter') {
                                    event.preventDefault()
                                    void handleRename(key.id)
                                  }
                                },
                              }),
                              h(
                                'button',
                                {
                                  type: 'button',
                                  className: 'skv-btn skv-btn-primary skv-btn-small',
                                  disabled,
                                  onClick: () => handleRename(key.id),
                                },
                                t('action.saveName'),
                              ),
                              h(
                                'button',
                                {
                                  type: 'button',
                                  className: 'skv-btn skv-btn-small',
                                  disabled,
                                  onClick: () => {
                                    setRenameId(null)
                                    setRenameValue('')
                                  },
                                },
                                t('action.cancel'),
                              ),
                            )
                          : h(
                              'button',
                              {
                                type: 'button',
                                className: 'skv-btn skv-btn-small',
                                disabled,
                                onClick: () => {
                                  setRenameId(key.id)
                                  setRenameValue(key.name)
                                  setPendingDelete(null)
                                },
                              },
                              t('action.rename'),
                            ),
                        h(
                          'button',
                          {
                            type: 'button',
                            className: 'skv-btn skv-btn-danger skv-btn-small',
                            disabled,
                            onClick: () => {
                              setPendingDelete({ kind: 'key', id: key.id })
                              setRenameId(null)
                            },
                          },
                          t('action.delete'),
                        ),
                      ),
                    ),
                  ),
                ),
          ),
        )
      }

      function renderHostsPanel() {
        if (!state) return null
        if (state.keys.length === 0) {
          return h(
            'div',
            { className: 'skv-stack' },
            h(
              'div',
              { className: 'skv-card' },
              h(
                'div',
                { className: 'skv-empty' },
                h('span', { className: 'skv-empty-title' }, t('hosts.noKeys')),
                h('span', null, t('hosts.noKeysHint')),
                h(
                  'div',
                  { className: 'skv-actions' },
                  h(
                    'button',
                    {
                      type: 'button',
                      className: 'skv-btn',
                      onClick: () => setTab('keys'),
                    },
                    t('keys.uploadTitle'),
                  ),
                ),
              ),
            ),
          )
        }
        return h(
          'div',
          { className: 'skv-stack' },
          h(
            'form',
            { className: 'skv-card', onSubmit: handleHostSave },
            h(
              'h3',
              { className: 'skv-card-title' },
              editingHostId ? t('hosts.formEditTitle') : t('hosts.formAddTitle'),
            ),
            h(
              'div',
              { className: 'skv-form-grid' },
              field(
                t('hosts.label'),
                h('input', {
                  className: 'skv-input',
                  type: 'text',
                  value: hostForm.label,
                  maxLength: 80,
                  placeholder: t('hosts.labelPlaceholder'),
                  disabled,
                  autoComplete: 'off',
                  onChange: (event) => setHostForm({ ...hostForm, label: event.target.value }),
                }),
              ),
              field(
                t('hosts.address'),
                h('input', {
                  className: 'skv-input',
                  type: 'text',
                  value: hostForm.address,
                  maxLength: 255,
                  placeholder: t('hosts.addressPlaceholder'),
                  disabled,
                  autoComplete: 'off',
                  onChange: (event) => setHostForm({ ...hostForm, address: event.target.value }),
                }),
              ),
              field(
                t('hosts.port'),
                h('input', {
                  className: 'skv-input',
                  type: 'number',
                  min: 1,
                  max: 65535,
                  value: hostForm.port,
                  disabled,
                  onChange: (event) => setHostForm({ ...hostForm, port: event.target.value }),
                }),
              ),
              field(
                t('hosts.username'),
                h('input', {
                  className: 'skv-input',
                  type: 'text',
                  value: hostForm.username,
                  maxLength: 64,
                  placeholder: t('hosts.usernamePlaceholder'),
                  disabled,
                  autoComplete: 'off',
                  onChange: (event) => setHostForm({ ...hostForm, username: event.target.value }),
                }),
              ),
              field(
                t('hosts.key'),
                h(
                  'select',
                  {
                    className: 'skv-select',
                    value: hostForm.keyId,
                    disabled,
                    onChange: (event) => setHostForm({ ...hostForm, keyId: event.target.value }),
                  },
                  state.keys.map((key) =>
                    h('option', { value: key.id, key: key.id }, `${key.name} (${key.fingerprint})`),
                  ),
                ),
              ),
              field(
                t('hosts.note'),
                h('textarea', {
                  className: 'skv-textarea',
                  value: hostForm.note,
                  maxLength: 500,
                  placeholder: t('hosts.notePlaceholder'),
                  disabled,
                  onChange: (event) => setHostForm({ ...hostForm, note: event.target.value }),
                }),
                null,
                'skv-span-2',
              ),
            ),
            h(
              'div',
              { className: 'skv-actions' },
              editingHostId
                ? h(
                    'button',
                    {
                      type: 'button',
                      className: 'skv-btn',
                      disabled,
                      onClick: resetHostForm,
                    },
                    t('action.cancel'),
                  )
                : null,
              h(
                'button',
                {
                  type: 'submit',
                  className: 'skv-btn skv-btn-primary',
                  disabled: disabled || !hostForm.keyId,
                },
                busy === 'host'
                  ? t('action.saving')
                  : editingHostId
                    ? t('action.updateHost')
                    : t('action.addHost'),
              ),
            ),
          ),
          h(
            'div',
            { className: 'skv-card' },
            h(
              'div',
              { className: 'skv-card-head' },
              h('h3', { className: 'skv-card-title' }, t('hosts.listTitle')),
              h('span', { className: 'skv-badge' }, state.hosts.length),
            ),
            state.hosts.length === 0
              ? h(
                  'div',
                  { className: 'skv-empty' },
                  h('span', { className: 'skv-empty-title' }, t('hosts.empty')),
                  h('span', null, t('hosts.emptyHint')),
                )
              : h(
                  'div',
                  { className: 'skv-list' },
                  state.hosts.map((host) =>
                    h(
                      'div',
                      { className: 'skv-item', key: host.id },
                      h(
                        'div',
                        { className: 'skv-item-main' },
                        h(
                          'div',
                          { className: 'skv-item-head' },
                          h('span', { className: 'skv-item-title' }, host.label),
                          h('span', { className: 'skv-badge' }, `${host.address}:${host.port}`),
                        ),
                        h(
                          'div',
                          { className: 'skv-meta' },
                          `${t('hosts.username')}: ${host.username} · ${t('hosts.key')}: ${keyName(host.keyId)}`,
                        ),
                        host.note ? h('div', { className: 'skv-meta' }, host.note) : null,
                        h(
                          'div',
                          { className: 'skv-chips' },
                          host.authorizedWorkspaceIds.length === 0
                            ? h('span', { className: 'skv-meta' }, t('keys.noWorkspaces'))
                            : host.authorizedWorkspaceIds.map((workspaceId) =>
                                h(
                                  'span',
                                  { className: 'skv-chip', key: workspaceId },
                                  workspaceTitle(workspaceId),
                                ),
                              ),
                        ),
                        pendingDelete?.kind === 'host' && pendingDelete.id === host.id
                          ? h(
                              'div',
                              { className: 'skv-confirm' },
                              h(
                                'div',
                                { className: 'skv-confirm-text' },
                                h(
                                  'span',
                                  { className: 'skv-confirm-title' },
                                  t('hosts.confirmDelete', { label: host.label }),
                                ),
                                h(
                                  'span',
                                  { className: 'skv-confirm-hint' },
                                  t('hosts.confirmDeleteHint'),
                                ),
                              ),
                              h(
                                'div',
                                { className: 'skv-actions' },
                                h(
                                  'button',
                                  {
                                    type: 'button',
                                    className: 'skv-btn skv-btn-danger',
                                    disabled,
                                    onClick: handleDelete,
                                  },
                                  t('action.confirmDelete'),
                                ),
                                h(
                                  'button',
                                  {
                                    type: 'button',
                                    className: 'skv-btn',
                                    disabled,
                                    onClick: () => setPendingDelete(null),
                                  },
                                  t('action.cancel'),
                                ),
                              ),
                            )
                          : null,
                      ),
                      h(
                        'div',
                        { className: 'skv-item-actions' },
                        h(
                          'button',
                          {
                            type: 'button',
                            className: 'skv-btn skv-btn-small',
                            disabled,
                            onClick: () => {
                              startEditHost(host)
                              setPendingDelete(null)
                            },
                          },
                          t('action.edit'),
                        ),
                        h(
                          'button',
                          {
                            type: 'button',
                            className: 'skv-btn skv-btn-danger skv-btn-small',
                            disabled,
                            onClick: () => setPendingDelete({ kind: 'host', id: host.id }),
                          },
                          t('action.delete'),
                        ),
                      ),
                    ),
                  ),
                ),
          ),
        )
      }

      function renderCheckGroup(title, items, emptyText, renderPrimary, renderMeta) {
        if (!draft) return null
        const selected = draft.hostIds
        const allIds = items.map((item) => item.id)
        return h(
          'div',
          { className: 'skv-field' },
          h(
            'div',
            { className: 'skv-group-head' },
            h(
              'span',
              { className: 'skv-group-title' },
              title,
              h('span', { className: 'skv-count' }, t('access.selectedCount', {
                selected: selected.length,
                total: items.length,
              })),
            ),
            h(
              'div',
              { className: 'skv-actions' },
              h(
                'button',
                {
                  type: 'button',
                  className: 'skv-btn skv-btn-small',
                  disabled: disabled || items.length === 0,
                  onClick: () => setHosts([...allIds]),
                },
                t('action.selectAll'),
              ),
              h(
                'button',
                {
                  type: 'button',
                  className: 'skv-btn skv-btn-small',
                  disabled: disabled || selected.length === 0,
                  onClick: () => setHosts([]),
                },
                t('action.clearAll'),
              ),
            ),
          ),
          items.length === 0
            ? h('div', { className: 'skv-empty' }, emptyText)
            : h(
                'div',
                { className: 'skv-check-group' },
                items.map((item) =>
                  h(
                    'label',
                    { className: 'skv-check', key: item.id },
                    h('input', {
                      type: 'checkbox',
                      checked: selected.includes(item.id),
                      disabled,
                      onChange: () => toggleHost(item.id),
                    }),
                    h(
                      'span',
                      { className: 'skv-check-text' },
                      h('span', { className: 'skv-check-title' }, renderPrimary(item)),
                      h('span', { className: 'skv-check-meta' }, renderMeta(item)),
                    ),
                  ),
                ),
              ),
        )
      }

      function renderAccessPanel() {
        if (!state) return null
        if (state.workspaces.length === 0) {
          return h(
            'div',
            { className: 'skv-card' },
            h(
              'div',
              { className: 'skv-empty' },
              h('span', { className: 'skv-empty-title' }, t('access.noWorkspaces')),
              h('span', null, t('access.noWorkspacesHint')),
            ),
          )
        }
        const preview = draft ? accessPreview(state, draft) : { keys: [], hosts: [] }
        const dirty = isDraftDirty(state, accessWorkspaceId, draft)
        return h(
          'div',
          { className: 'skv-stack' },
          h(
            'div',
            { className: 'skv-card' },
            field(
              t('access.workspaceLabel'),
              h(
                'select',
                {
                  className: 'skv-select',
                  value: accessWorkspaceId,
                  disabled,
                  onChange: (event) => setAccessWorkspaceId(event.target.value),
                },
                state.workspaces.map((workspace) =>
                  h('option', { value: workspace.id, key: workspace.id }, workspace.title),
                ),
              ),
            ),
            h('p', { className: 'skv-card-description' }, t('access.directHint')),
            h(
              'div',
              { className: 'skv-access-grid' },
              renderCheckGroup(
                t('access.hostsTitle'),
                state.hosts,
                t('access.emptyHosts'),
                (host) => host.label,
                (host) => `${host.address}:${host.port} · ${keyName(host.keyId)}`,
              ),
            ),
            h(
              'div',
              { className: 'skv-actions' },
              dirty ? h('span', { className: 'skv-unsaved' }, t('access.unsaved')) : null,
              h(
                'button',
                {
                  type: 'button',
                  className: 'skv-btn skv-btn-primary',
                  disabled: disabled || !draft || !dirty,
                  onClick: handleAccessSave,
                },
                busy === 'access' ? t('action.saving') : t('action.saveAccess'),
              ),
            ),
          ),
          h(
            'div',
            { className: 'skv-preview' },
            h('h4', { className: 'skv-card-title' }, t('access.previewTitle')),
            h('p', { className: 'skv-card-description' }, t('access.previewHint')),
            preview.keys.length === 0 && preview.hosts.length === 0
              ? h('div', { className: 'skv-meta' }, t('access.previewEmpty'))
              : h(
                  React.Fragment,
                  null,
                  h(
                    'div',
                    { className: 'skv-preview-row' },
                    h('span', { className: 'skv-preview-label' }, t('access.previewHosts')),
                    h(
                      'div',
                      { className: 'skv-chips' },
                      preview.hosts.length === 0
                        ? h('span', { className: 'skv-meta' }, t('common.none'))
                        : preview.hosts.map((host) =>
                            h('span', { className: 'skv-chip', key: host.id }, host.label),
                          ),
                    ),
                  ),
                  h(
                    'div',
                    { className: 'skv-preview-row' },
                    h('span', { className: 'skv-preview-label' }, t('access.previewKeys')),
                    h(
                      'div',
                      { className: 'skv-chips' },
                      preview.keys.length === 0
                        ? h('span', { className: 'skv-meta' }, t('common.none'))
                        : preview.keys.map((key) =>
                            h('span', { className: 'skv-chip', key: key.id }, key.name),
                          ),
                    ),
                  ),
                ),
          ),
        )
      }

      const tabs = [
        { id: 'keys', label: t('tabs.keys') },
        { id: 'hosts', label: t('tabs.hosts') },
        { id: 'access', label: t('tabs.access') },
      ]

      return h(
        'div',
        { className: 'skv-root' },
        h('style', null, CSS),
        h(
          'div',
          { className: 'skv-header' },
          h(
            'div',
            null,
            h('h2', { className: 'skv-title' }, t('title')),
            h('p', { className: 'skv-subtitle' }, t('subtitle')),
          ),
          h(
            'div',
            { className: 'skv-actions' },
            h(
              'button',
              {
                type: 'button',
                className: 'skv-btn',
                disabled,
                onClick: () => void refresh(),
              },
              t('action.refresh'),
            ),
          ),
        ),
        h(
          'div',
          { className: 'skv-security' },
          h('span', { className: 'skv-security-dot', 'aria-hidden': 'true' }),
          h('span', null, t('securityNote')),
        ),
        h(
          'div',
          { className: 'skv-stats' },
          h(
            'div',
            { className: 'skv-stat' },
            h('div', { className: 'skv-stat-value' }, state?.stats?.keys ?? '—'),
            h('div', { className: 'skv-stat-label' }, t('stats.keys')),
          ),
          h(
            'div',
            { className: 'skv-stat' },
            h('div', { className: 'skv-stat-value' }, state?.stats?.hosts ?? '—'),
            h('div', { className: 'skv-stat-label' }, t('stats.hosts')),
          ),
          h(
            'div',
            { className: 'skv-stat' },
            h('div', { className: 'skv-stat-value' }, state?.stats?.grantedWorkspaces ?? '—'),
            h('div', { className: 'skv-stat-label' }, t('stats.workspaces')),
          ),
        ),
        error && !state
          ? h(
              'div',
              { className: 'skv-notice skv-notice-error', role: 'alert' },
              h('span', null, t('error.load')),
              h(
                'button',
                {
                  type: 'button',
                  className: 'skv-btn skv-btn-small',
                  onClick: () => void refresh(),
                },
                t('action.retry'),
              ),
            )
          : null,
        error && state
          ? h(
              'div',
              { className: 'skv-notice skv-notice-error', role: 'alert' },
              h('span', null, describeError(t, { kind: 'error', error })),
            )
          : null,
        !state && loading
          ? h('div', { className: 'skv-empty' }, h('span', null, t('loading')))
          : null,
        renderNotice(),
        state
          ? h(
              React.Fragment,
              null,
              h(
                'div',
                { className: 'skv-tabs', role: 'tablist' },
                tabs.map((item) =>
                  h(
                    'button',
                    {
                      type: 'button',
                      role: 'tab',
                      key: item.id,
                      'aria-selected': tab === item.id,
                      className: `skv-tab${tab === item.id ? ' skv-tab-active' : ''}`,
                      onClick: () => setTab(item.id),
                    },
                    item.label,
                  ),
                ),
              ),
              h(
                'div',
                { role: 'tabpanel' },
                tab === 'keys'
                  ? renderKeysPanel()
                  : tab === 'hosts'
                    ? renderHostsPanel()
                    : renderAccessPanel(),
              ),
            )
          : null,
      )
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        ctx.effect(
          () =>
            ctx.locale.register(NS, {
              zh,
              en,
            }),
          'ssh-key-vault: dictionaries',
        )
        const t = ctx.locale.bind(NS)
        ctx.slots.inject('settings.section', () =>
          ctx.slots.register(
            {
              name: 'settings.section',
              id: 'ssh-key-vault',
              order: 60,
              label: () => t('nav'),
              locale: NS,
            },
            Section,
          ),
        )
      },
    }
  },
})
