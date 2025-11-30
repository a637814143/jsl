# 等保标准自动化测评与整改工具（Linux）

> 基于等保 2.0《信息安全技术 网络安全等级保护测评要求》（GB/T 28448-2019）三级安全计算环境 8.1.4 条款的 Linux 主机自动化检查与整改脚本。:contentReference[oaicite:0]{index=0}  

---

## 功能简介

本工具是一个面向 Linux 服务器的命令行程序，用于对照 **等保 2.0 《信息安全技术 网络安全等级保护测评要求》（GB/T 28448-2019）第三级《安全计算环境》8.1.4 系列条款**，自动完成：

- 配置基线检查  
- 合规性判定（符合 / 不符合 / 检查错误）  
- 可选的自动整改（支持交互式确认）  
- 生成 Markdown 形式的测评与整改报告  

当前已覆盖的模块与条款包括（按等保条文编号划分）：:contentReference[oaicite:1]{index=1}  

- **8.1.4.1 身份鉴别（identity）**
- **8.1.4.2 访问控制（access_control）**
- **8.1.4.3 安全审计（audit）**
- **8.1.4.4 入侵防范（intrusion_prevention）**
- **8.1.4.5 恶意代码防范（malware_protection）**
- **8.1.4.6 可信验证（trusted_verification）**
- **8.1.4.7 数据完整性（data_integrity）**
- **8.1.4.8 数据保密性（data_confidentiality）**
- **8.1.4.9 数据备份恢复（data_backup_recovery）**
- **8.1.4.10 剩余信息保护（residual_information）**
- **8.1.4.11 个人信息保护（personal_information）**

---

## 主要特性

### 1. 模块化的等保条款映射

工具内部预先维护了模块与条款的映射关系：:contentReference[oaicite:2]{index=2}  

- `identity` → 8.1.4.1 身份鉴别（L3-CES1-01 ～ L3-CES1-04）
- `access_control` → 8.1.4.2 访问控制（L3-CES1-05 ～ L3-CES1-11）
- `audit` → 8.1.4.3 安全审计（L3-CES1-12 ～ L3-CES1-15）
- `intrusion_prevention` → 8.1.4.4 入侵防范（L3-CES1-17 ～ L3-CES1-22）
- `malware_protection` → 8.1.4.5 恶意代码防范（L3-CES1-23）
- `trusted_verification` → 8.1.4.6 可信验证（L3-CES1-24）
- `data_integrity` → 8.1.4.7 数据完整性（L3-CES1-25 ～ L3-CES1-26）
- `data_confidentiality` → 8.1.4.8 数据保密性（L3-CES1-27 ～ L3-CES1-28）
- `data_backup_recovery` → 8.1.4.9 数据备份恢复（L3-CES1-29 ～ L3-CES1-31）
- `residual_information` → 8.1.4.10 剩余信息保护（L3-CES1-32 ～ L3-CES1-33）
- `personal_information` → 8.1.4.11 个人信息保护（L3-CES1-34 ～ L3-CES1-35）

用户可以按模块选择只检查“身份鉴别 + 安全审计”，或者排除“入侵防范、恶意代码”等模块。

### 2. 自动检查 + 可选自动整改

对每个条款下的“实施要点”，工具会：:contentReference[oaicite:3]{index=3}  

1. 自动执行系统命令、解析配置文件（如 `/etc/pam.d/*`、`/etc/login.defs`、`/etc/ssh/sshd_config` 等），判断当前是否符合要求。  
2. 为不符合项生成详细诊断信息与建议配置。  
3. 对部分典型问题支持自动整改，例如：
   - 空口令账户锁定与强制设置复杂密码
   - 密码复杂度策略（`pwquality.conf` + PAM）
   - 密码有效期与轮换策略（`/etc/login.defs` + `chage`）
   - 登录失败锁定策略（`pam_faillock` / `pam_tally2`）
   - 审计服务启用（`auditd` / `rsyslog`）
   - 审计日志权限与轮转策略
   - SSH 安全配置（强制 SSHv2、关闭 Telnet 等明文远程服务）
   - 禁用高危服务与常见高危端口

自动整改步骤默认 **交互式执行**，每个条目会询问是否执行，并在执行命令后记录详细备注。

### 3. Markdown 报告与整改报告

工具会生成带时间戳的 Markdown 报告文件，例如：`report_20240101_120000.md`。:contentReference[oaicite:4]{index=4}  

报告内容包括：

- 封面信息（委托单位 / 测评单位 / 报告时间 占位）  
- 系统环境信息（操作系统、内核版本、CPU 架构、包管理器等）  
- 各条款下检查项的结果（符合 / 不符合 / 检查错误）  
- 详细检测输出（命令结果摘要、配置片段）  
- 每条不符合项的整改建议  
- 自动整改执行过程与结果（另有整改报告 md 文件）

---

## 环境与依赖

- **操作系统**：Linux（已在常见发行版上考虑 apt / yum / pacman / apk 包管理器）  
- **Python 版本**：Python 3.6+  
- **运行权限**：需要 root（很多检查依赖读取 `/etc/shadow`、`/var/log/*` 以及修改系统配置）:contentReference[oaicite:5]{index=5}  
- **外部命令**：
  - `systemctl` / `service`
  - `ss` / `netstat`
  - `dpkg-query` / `rpm` / `pacman` / `apk`
  - `auditd` / `rsyslog`（如需审计与日志检查）
  - `chage`, `passwd`, `chpasswd` 等

> **注意**：在生产环境执行自动整改前，请务必先在测试环境演练，并做好配置文件与关键数据的备份。

---

## 快速开始

### 1. 获取代码

```bash
git clone https://github.com/<your-account>/<your-repo>.git
cd <your-repo>
```

##### 仓库结构示例：

```
.
├── Linux.py        # 主程序：检查逻辑 + 报告生成 + 自动整改
└── README.md
```

### 2. 查看支持模块

```shell
sudo python3 Linux.py --list-modules
```

##### 示例输出：

```shell
支持的模块如下：
  - identity: 8.1.4.1 身份鉴别
  - access_control: 8.1.4.2 访问控制
  - audit: 8.1.4.3 安全审计
  - intrusion_prevention: 8.1.4.4 入侵防范
  - malware_protection: 8.1.4.5 恶意代码防范
  - trusted_verification: 8.1.4.6 可信验证
  - data_integrity: 8.1.4.7 数据完整性
  - data_confidentiality: 8.1.4.8 数据保密性
  - data_backup_recovery: 8.1.4.9 数据备份恢复
  - residual_information: 8.1.4.10 剩余信息保护
  - personal_information: 8.1.4.11 个人信息保护
```

### 3. 全量检查（所有模块）

```shell
sudo python3 Linux.py
```

##### 或显式指定模块集合：

```shell
sudo python3 Linux.py --include-module identity,access_control,audit,intrusion_prevention,malware_protection,trusted_verification,data_integrity,data_confidentiality,data_backup_recovery,residual_information,personal_information
```

### 4. 按模块检查

- **只检查身份鉴别 + 安全审计**：

  ```shell
  sudo python3 Linux.py --include-module identity,audit
  ```

- **检查全部，但跳过入侵防范 + 恶意代码防范**：

  ```shell
  sudo python3 Linux.py --exclude-module intrusion_prevention,malware_protection
  ```

### 5. 生成报告与查看

执行完毕后，在当前目录会生成类似：

- `check_report_YYYYMMDD_HHMMSS.md`（测评报告）
- `remediation_report_YYYYMMDD_HHMMSS.md`（整改记录报告，如有执行自动整改）

你可以直接在 Markdown 查看器中打开，也可以导出为 PDF 或 Word 作为正式报告附件。



## 典型使用场景

- **等级保护三级测评准备**
  - 在正式测评前，对 Linux 主机批量运行本工具，提前发现不符合条款的配置项，并自动完成部分整改。
- **运维基线巡检**
  - 定期对关键服务器执行工具，跟踪口令策略、审计策略、服务端口等基线是否被人为修改。
- **变更后复核**
  - 大版本升级 / 安全加固之后，快速核查是否仍然满足等保 2.0 要求。



## 安全注意事项

1. **务必备份**
   - 工具会对配置文件（如 `sshd_config`、`login.defs`、PAM 配置等）在修改前自动创建带时间戳的备份，但仍建议额外使用配置管理工具或快照做整体备份。Linux
2. **先在测试环境演练**
   - 不同发行版的默认配置差异较大，建议先在同版本测试机上运行，确认自动整改策略不会与现有业务冲突。
3. **最小权限原则**
   - 工具需要 root 权限，但建议仅由合规 / 安全 / 运维管理员在受控环境下运行，并记录执行过程。
4. **自动整改可跳过**
   - 每一条整改项都会询问 “是否执行该项整改（y/n）”，你可以只使用“检测功能”，把整改建议交给人工审核后再实施。



## 开发与扩展

如果你希望在本工具的基础上扩展更多能力，可以考虑：

- 增加 **更多条款的自动化检查**（如边界防护、通信网络等）
- 增加 **多主机批量执行与集中汇总** 的能力（结合 Ansible / SSH 批量等）
- 对接 **Web 管理界面或可视化报告平台**
- 增加 **本地化配置文件**，按不同单位的安全策略调整默认阈值（如密码长度、锁定次数等）

欢迎提交 Issue / PR，一起完善这个等保自动化测评与整改工具。
