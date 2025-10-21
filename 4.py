#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Lightweight harness for the (commented) Linux compliance checker logic.

The original, fully fledged remediation workflow is still preserved below as a
comment-only reference.  This executable shim adds a small command line
interface so operators can choose which模块 (module groups) to evaluate when
the full checker implementation is eventually restored.  While the detailed
checks remain disabled, the CLI itself is functional and can be wired to real
logic later on.

Usage examples
--------------

* 列出可用模块::

      python scripts/linux_compliance_checker.py --list-modules

* 仅运行身份鉴别与安全审计::

      python scripts/linux_compliance_checker.py --include-module identity \
          --include-module audit

* 跳过入侵防范模块::

      python scripts/linux_compliance_checker.py --exclude-module intrusion_prevention

"""

from __future__ import annotations

import argparse
import sys
from typing import Dict, Iterable, List, Set


# 供 CLI 使用的模块索引，键名称与之前被注释掉的 CHECK_ITEMS 结构保持一致。
CHECK_MODULES: Dict[str, Dict[str, str]] = {
    "identity": {"title": "8.1.4.1 身份鉴别"},
    "access_control": {"title": "8.1.4.2 访问控制"},
    "audit": {"title": "8.1.4.3 安全审计"},
    "intrusion_prevention": {"title": "8.1.4.4 入侵防范"},
    "malware_protection": {"title": "8.1.4.5 恶意代码防范"},
}


def _normalise(raw_values: Iterable[str]) -> List[str]:
    """Split comma-separated inputs and strip whitespace."""

    values: List[str] = []
    for value in raw_values:
        if not value:
            continue
        values.extend(chunk.strip() for chunk in value.split(",") if chunk.strip())
    return values


def _validate_modules(modules: Iterable[str]) -> Set[str]:
    """Ensure requested模块存在，若不存在则抛出带提示的异常。"""

    modules_set = set(modules)
    unknown = modules_set - CHECK_MODULES.keys()
    if unknown:
        available = ", ".join(sorted(CHECK_MODULES))
        names = ", ".join(sorted(unknown))
        raise ValueError(
            f"未知模块: {names}。可用模块包括: {available}."
        )
    return modules_set


def _determine_selection(include: Iterable[str], exclude: Iterable[str]) -> List[str]:
    """Return最终需要执行的模块列表。"""

    include_set = _validate_modules(_normalise(include)) if include else None
    exclude_set = _validate_modules(_normalise(exclude)) if exclude else set()

    available = set(CHECK_MODULES.keys())
    if include_set is not None:
        selection = include_set
    else:
        selection = available

    selection -= exclude_set

    if not selection:
        raise ValueError("根据 include/exclude 参数过滤后没有剩余模块可供检查。")

    return sorted(selection)


def run_placeholder_checks(selected_modules: Iterable[str]) -> None:
    """输出占位信息，提示真实检查逻辑仍处于注释状态。"""

    for module in selected_modules:
        title = CHECK_MODULES[module]["title"]
        print(f"[占位执行] 模块 {module} - {title}")
        print("  -> 详细检查逻辑当前已被注释保留，仅提供接口示例。\n")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Linux 合规性检查器（CLI 占位实现）",
    )
    parser.add_argument(
        "--include-module",
        action="append",
        default=[],
        help="仅执行指定模块，可重复或逗号分隔",
    )
    parser.add_argument(
        "--exclude-module",
        action="append",
        default=[],
        help="跳过指定模块，可重复或逗号分隔",
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="列出支持的模块后退出",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    if args.list_modules:
        print("支持的模块如下：")
        for key, meta in CHECK_MODULES.items():
            print(f"  - {key}: {meta['title']}")
        return 0

    try:
        selected_modules = _determine_selection(args.include_module, args.exclude_module)
    except ValueError as exc:  # pragma: no cover - CLI 参数错误时提示并退出
        print(f"错误: {exc}", file=sys.stderr)
        return 1

    run_placeholder_checks(selected_modules)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI 入口
    sys.exit(main())


# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

import os
import re
import pwd
import grp
import spwd
import shutil
import stat
import subprocess
from datetime import datetime
from getpass import getpass
import platform
from typing import Dict, List, Optional, Set, Tuple


class Colors:
    """Terminal colour helpers."""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    END = "\033[0m"


CHECK_ITEMS: Dict[str, Dict[str, object]] = {
    "identity": {
        "title": "8.1.4.1 身份鉴别",
        "items": {
            "L3-CES1-01": {
                "indicator": "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换。",
                "implementation": [
                    "应核查用户在登录时是否采用了身份鉴别措施；检查 `/etc/pam.d/` 下的认证配置（如 `system-auth`, `login`），查看是否配置了 `pam_unix.so` 或其他认证模块。",
                    "应核查用户列表确认用户身份标识是否具有唯一性；解析 `/etc/passwd`，检查用户名和UID是否唯一。",
                    "应核查用户配置信息或测试验证是否不存在空口令用户；检查 `/etc/shadow` 文件中第二个字段为空的账户（需要root权限），如 `sudo awk -F: '($2 == \"\" ) { print $1 }' /etc/shadow`。",
                    "应核查用户鉴别信息是否具有复杂度要求并定期更换。复杂度: 检查 `/etc/pam.d/system-auth` 或 `/etc/security/pwquality.conf` 中是否存在 `pam_pwquality.so` 及相关配置（如 `minlen`, `dcredit` 等）。定期更换: 检查 `/etc/login.defs` 中的 `PASS_MAX_DAYS` 等参数，以及 `/etc/shadow` 中用户密码的最后修改时间和最大天数。",
                ],
            },
            "L3-CES1-02": {
                "indicator": "应具有登录失败处理功能，应配置并启用结束会话、限制非法登录次数和当登录连接超时自动退出等相关措施。",
                "implementation": [
                    "应核查是否配置并启用了登录失败处理功能。",
                    "应核查是否配置并启用了限制非法登录功能，非法登录达到一定次数后采取特定动作，如账户锁定等；检查 `/etc/pam.d/system-auth` 和 `/etc/pam.d/sshd` 等，查找 `pam_tally2.so` 或 `pam_faillock.so` 的配置（如 `deny=`, `unlock_time=`）。",
                    "应核查是否配置并启用了登录连接超时及自动退出功能；检查全局环境变量设置（`/etc/profile`, `/etc/bash.bashrc` 中的 `TMOUT`）以及SSH服务配置（`/etc/ssh/sshd_config` 中的 `ClientAliveInterval` 和 `ClientAliveCountMax`）。",
                ],
            },
            "L3-CES1-03": {
                "indicator": "当进行远程管理时，应采取必要措施防止鉴别信息在网络传输过程中被窃听。",
                "implementation": [
                    "应核查是否采用加密等安全方式对系统进行远程管理，防止鉴别信息在网络传输过程中被窃听；检查SSH服务配置（`/etc/ssh/sshd_config`）中 `Protocol` 是否为2，并检查是否禁止了不安全的协议（如 `telnet`, `rlogin`）。",
                ],
            },
            "L3-CES1-04": {
                "indicator": "应采用口令、密码技术、生物技术等两种或两种以上组合的鉴别技术对用户进行身份鉴别，且其中一种鉴别技术至少应使用密码技术来实现。",
                "implementation": [
                    "应核查是否采用动态口令、数字证书、生物技术和设备指纹等两种或两种以上组合的鉴别技术对用户身份进行鉴别；检查PAM配置（如 `/etc/pam.d/sshd`），查看是否除了 `pam_unix.so` 外，还配置了第二个认证模块（如 `pam_google_authenticator.so`、`pam_sss.so`）。",
                    "应核查其中一种鉴别技术是否使用密码技术来实现。",
                ],
            },
        },
    },
    "access_control": {
        "title": "8.1.4.2 访问控制",
        "items": {
            "L3-CES1-05": {
                "indicator": "应对登录的用户分配账户和权限。",
                "implementation": [
                    "应核查是否为用户分配了账户和权限及相关设置情况；可以列出所有用户（`/etc/passwd`）和组（`/etc/group`）。",
                    "应核查是否已禁用或限制匿名、默认账户的访问权限；检查默认账户如 `root`, `bin`, `daemon` 等的登录shell是否为 `/sbin/nologin` 或 `/bin/false`。",
                ],
            },
            "L3-CES1-06": {
                "indicator": "应重命名或删除默认账户，修改默认账户的默认口令。",
                "implementation": [
                    "应核查是否已经重命名默认账户或默认账户已被删除；检查 `/etc/passwd` 中UID为0的账户名是否为 `root` 或其他名称，并关注 `admin`, `test` 等常见默认账户。",
                    "应核查是否已修改默认账户的默认口令。",
                ],
            },
            "L3-CES1-07": {
                "indicator": "应及时删除或停用多余的、过期的账户，避免共享账户的存在。",
                "implementation": [
                    "应核查是否不存在多余或过期账户，管理员用户与账户之间是否一一对应。",
                    "应测试验证多余的、过期的账户是否被删除或停用；可以列出所有账户，并与人工提供的合法账户清单进行比对，找出差异。",
                ],
            },
            "L3-CES1-08": {
                "indicator": "应授予管理用户所需的最小权限，实现管理用户的权限分离。",
                "implementation": [
                    "应核查是否进行角色划分。",
                    "应核查管理用户的权限是否已进行分离。",
                    "应核查管理用户权限是否为其工作任务所需的最小权限；可以检查 `sudo` 配置（`/etc/sudoers`）查看不同用户或组的权限分配，并检查系统关键文件和目录的权限。",
                ],
            },
            "L3-CES1-11": {
                "indicator": "应对重要主体和客体设置安全标记，并控制主体对有安全标记信息资源的访问。",
                "implementation": [
                    "应核查是否对主体、客体设置了安全标记。",
                    "应测试验证是否依据主体、客体安全标记控制主体对客体访问的强制访问控制策略；检查系统是否安装了SELinux或AppArmor，并且处于 `Enforcing` 模式（如 `sestatus`, `aa-status` 命令）。",
                ],
            },
        },
    },
    "audit": {
        "title": "8.1.4.3 安全审计",
        "items": {
            "L3-CES1-12": {
                "indicator": "应启用安全审计功能，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计。",
                "implementation": [
                    "应核查是否开启了安全审计功能；检查 `auditd` 服务是否运行，以及 `rsyslog`/`syslog-ng` 等日志服务状态。",
                    "应核查安全审计范围是否覆盖到每个用户。",
                    "应核查是否对重要的用户行为和重要安全事件进行审计。",
                ],
            },
            "L3-CES1-13": {
                "indicator": "审计记录应包括事件的日期和时间、用户、事件类型、事件是否成功及其他与审计相关的信息。",
                "implementation": [
                    "应核查审计记录信息是否包括事件的日期和时间、用户、事件类型、事件是否成功及其他与审计相关的信息；检查 `/etc/audit/auditd.conf` 配置，并采样分析审计日志（如 `/var/log/audit/audit.log`）或系统日志格式。",
                ],
            },
            "L3-CES1-14": {
                "indicator": "应对审计记录进行保护，定期备份，避免受到未预期的删除、修改或覆盖等。",
                "implementation": [
                    "应核查是否采取了保护措施对审计记录进行保护；检查审计日志文件的权限（通常是 `0600`）。",
                    "应核查是否采取技术措施对审计记录进行定期备份，并核查其备份策略；检查是否有日志轮转配置（如 `logrotate`）或日志服务器配置（如 `rsyslog.conf`）。",
                ],
            },
        },
    },
    "intrusion_prevention": {
        "title": "8.1.4.4 入侵防范",
        "items": {
            "L3-CES1-17": {
                "indicator": "应遵循最小安装的原则，仅安装需要的组件和应用程序。",
                "implementation": [
                    "应核查是否遵循最小安装原则。",
                    "应核查是否未安装非必要的组件和应用程序；可以列出已安装的软件包（如 `dpkg -l` 或 `rpm -qa`）并结合系统角色进行判断。",
                ],
            },
            "L3-CES1-18": {
                "indicator": "应关闭不需要的系统服务、默认共享和高危端口。",
                "implementation": [
                    "应核查是否关闭了非必要的系统服务和默认共享；检查系统上所有已启动的服务（如 `systemctl list-units --type=service --state=running`），并与白名单对比。",
                    "应核查是否不存在非必要的高危端口；检查所有监听端口（如 `ss -tuln`, `netstat -tuln`），并与白名单对比。",
                ],
            },
            "L3-CES1-19": {
                "indicator": "应通过设定终端接入方式或网络地址范围对通过网络进行管理的管理终端进行限制。",
                "implementation": [
                    "应核查配置文件或参数是否对终端接入范围进行限制；检查SSH配置（`/etc/ssh/sshd_config`）中的 `AllowUsers`, `AllowGroups`, `DenyUsers`, `DenyGroups` 或防火墙规则是否对管理源地址进行了限制。",
                ],
            },
        },
    },
    "malware_protection": {
        "title": "8.1.4.5 恶意代码防范",
        "items": {
            "L3-CES1-23": {
                "indicator": "应采用免受恶意代码攻击的技术措施或主动免疫可信验证机制及时识别入侵和病毒行为，并将其有效阻断。",
                "implementation": [
                    "应核查是否安装了防恶意代码软件或相应功能的软件，定期进行升级和更新防恶意代码库。",
                    "应核查是否采用主动免疫可信验证技术及时识别入侵和病毒行为。",
                    "应核查当识别入侵和病毒行为时是否将其有效阻断；检查防病毒软件进程是否运行，病毒库更新任务是否存在且最近成功执行。",
                ],
            },
        },
    },
}


NOLOGIN_SHELLS = {
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/nologin",
    "/usr/bin/nologin",
    "/bin/false",
    "nologin"
}


INTERACTIVE_SHELLS = {"/bin/bash"}


INSECURE_REMOTE_SERVICES = [
    "telnet",
    "rlogin",
    "rsh",
    "rexec",
    "telnetd",
]


UNNECESSARY_SERVICES = [
    "telnet",
    "telnetd",
    "rlogin",
    "rsh",
    "rsh-server",
    "rexec",
    "ypbind",
    "ypserv",
    "rpcbind",
    "xinetd",
    "tftp",
    "vsftpd",
    "samba",
    "cifs-utils",
    "xorg-x11-server-Xorg",
]


STATUS_LABELS = {
    "APPLIED": "已完成",
    "PARTIAL": "部分完成",
    "PENDING": "待处理",
    "SKIPPED": "已跳过",
    "FAILED": "失败",
}


HIGH_RISK_PORTS = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    111: "RPCBind",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "SMB",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    515: "LPD",
    873: "rsync",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    6379: "Redis",
    11211: "Memcached",
    27017: "MongoDB",
}


PORT_SERVICE_HINTS = {
    21: ["vsftpd", "proftpd", "pure-ftpd", "ftp"],
    23: ["telnet", "telnetd"],
    69: ["tftp", "tftpd", "atftpd"],
    111: ["rpcbind"],
    135: ["rpcbind", "winbind"],
    137: ["smb", "smbd", "nmbd", "samba"],
    138: ["smb", "smbd", "nmbd", "samba"],
    139: ["smb", "smbd", "samba"],
    445: ["smb", "smbd", "samba", "cifs"],
    512: ["rexec"],
    513: ["rlogin"],
    514: ["rsh", "syslog"],
    515: ["cups", "lpd", "cupsd"],
    873: ["rsync"],
    2049: ["nfs", "nfs-server", "nfsd"],
    3306: ["mysqld", "mysql"],
    3389: ["xrdp", "freerdp"],
    5900: ["vncserver", "vino-server", "x11vnc"],
    5901: ["vncserver", "vino-server", "x11vnc"],
    6379: ["redis", "redis-server"],
    11211: ["memcached"],
    27017: ["mongod", "mongodb"],
}


MANUAL_REMEDIATION_GUIDES = {
    ("L3-CES1-01", 0): [
        "1. 以 root 身份运行 `grep -E \"pam_(unix|sss|ldap|krb5)\" /etc/pam.d/system-auth /etc/pam.d/login` 检查是否已加载基础密码或单点登录认证模块，预期输出至少包含 `pam_unix.so`。",
        "2. 若命令结果未出现所需模块，请使用 `vi /etc/pam.d/system-auth` 或 `vim /etc/pam.d/login` 在 `auth required` 段落中补充 `auth required pam_unix.so`，如接入企业认证，请追加 `auth sufficient pam_sss.so` 等模块并写明顺序。",
        "3. 保存配置后执行 `systemctl restart sshd` 或 `service sshd restart` 重新加载 PAM，随后使用测试账号手动登录以确认认证链可用。",
    ],
    ("L3-CES1-01", 1): [
        "1. 执行 `getent passwd | awk -F: '{print $1\" \" $3}' | sort -k2,2` 列出所有用户名与 UID，重点观察是否有相同 UID 对应多个用户名或重复账号。",
        "2. 对检测到的重复记录，先执行 `id <用户名>` 与业务确认账号用途，再视情况运行 `usermod -u <新UID> <用户名>` 调整 UID 或使用 `userdel <用户名>` / `usermod -L <用户名>` 禁用多余账户。",
        "3. 调整完成后重新运行 `getent passwd` 确认无重复 UID，并执行 `pwck` 修复口令/组数据库中的潜在不一致。",
    ],
    ("L3-CES1-04", 0): [
        "1. 根据安全策略选定二次认证方案（如 Google Authenticator、AD/LDAP、硬件令牌），并执行 `apt install libpam-google-authenticator` 或 `yum install google-authenticator` 安装对应 PAM 模块。",
        "2. 编辑 `/etc/pam.d/sshd`，在 `auth` 阶段的 `pam_unix.so` 之后追加 `auth required pam_google_authenticator.so nullok`（如对接统一认证请替换为企业模块），保存前确认未破坏原有顺序。",
        "3. 修改 `/etc/ssh/sshd_config` 确认 `ChallengeResponseAuthentication yes`、`AuthenticationMethods password,keyboard-interactive` 均已启用，必要时同步配置 `UsePAM yes`，然后执行 `systemctl restart sshd`。",
        "4. 为每位管理员执行 `google-authenticator`（或厂商提供的初始化命令）生成令牌，扫描二维码后通过 SSH 登录验证必须同时输入密码与动态验证码。",
    ],
    ("L3-CES1-04", 1): [
        "1. 核查 `/etc/pam.d/system-auth`、`/etc/pam.d/sshd` 中是否仍包含 `auth` 阶段的 `pam_unix.so` 或 `pam_sss.so`，以确认密码技术仍在多因素组合中使用。",
        "2. 若检测到 `PasswordAuthentication no` 或去掉密码模块的配置，请使用 `sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config` 恢复密码登录（如需限制，可配合 `AuthenticationMethods password,keyboard-interactive`）。",
        "3. 通过 `passwd <用户名>` 更新管理员密码，并结合 `chage -l <用户名>` 核实轮换周期满足策略要求。",
    ],
    ("L3-CES1-05", 0): [
        "1. 运行 `getent passwd > /tmp/passwd.list` 与 `getent group > /tmp/group.list` 保存现有账户及用户组清单，便于后续比对。",
        "2. 针对关键岗位执行 `id <用户名>` 查看其所属组和附加权限，并与岗位说明书核对是否符合最小授权原则。",
        "3. 将核查结论记录到权限台账，必要时使用 `usermod -aG <目标组> <用户名>` 或 `gpasswd -d <用户名> <组名>` 调整权限。",
    ],
    ("L3-CES1-05", 1): [
        "1. 使用 `awk -F: '$7!~/nologin|false/{printf \"%s -> %s\\n\",$1,$7}' /etc/passwd` 列出仍可交互登录的默认/系统账户。",
        "2. 对不应登录的系统账户执行 `usermod -s /sbin/nologin <用户名>` 或 `passwd -l <用户名>` 禁止口令登录，必要时同步 `systemctl disable` 相关服务。",
        "3. 再次检查 `/etc/passwd` 并执行 `getent shadow <用户名>` 确认账户已锁定或 Shell 已替换为 nologin。",
    ],
    ("L3-CES1-06", 0): [
        "1. 运行 `awk -F: '($3==0){print $1}' /etc/passwd` 列出 UID 为 0 的账户并确认是否只有 `root`。",
        "2. 若存在其他 UID0 账户，先用 `passwd -l <旧名称>` 临时锁定，再通过 `usermod -l <新名称> <旧名称>` 重命名或 `userdel <旧名称>` 删除，注意同时更新 sudo/计划任务中的引用。",
        "3. 完成后执行 `grep ':0:' /etc/passwd` 核实仅剩预期的特权账号，并尝试以 root 登录验证不受影响。",
    ],
    ("L3-CES1-06", 1): [
        "1. 对默认账户执行 `passwd -S <用户名>` 查看口令状态，若显示 `Password set, MD5 crypt.` 之外的弱状态需立即处理。",
        "2. 若仍使用默认口令或状态为 `NP/LK`，执行 `passwd <用户名>` 设置复杂密码，并通过 `chage -M 90 -m 7 -W 7 <用户名>` 配置轮换策略。",
        "3. 记录修改时间，将结果同步至密码台账并安排定期复核。",
    ],
    ("L3-CES1-07", 0): [
        "1. 执行 `lastlog | head` 与 `lastlog | grep -v 'Never logged in'` 查看长时间未登录的账户，再配合 `chage -l <用户名>` 判断过期策略。",
        "2. 将系统账号清单与业务授权名册逐项比对，记录疑似无人维护或离职人员账号，并备注业务负责人。",
        "3. 与相关负责人确认处理方案，形成删除/保留清单并约定生效时间。",
    ],
    ("L3-CES1-07", 1): [
        "1. 对判定为多余/过期的账户先执行 `usermod -L <用户名>` 或 `passwd -l <用户名>` 临时锁定，并使用 `loginctl terminate-user <用户名>` 断开现有会话。",
        "2. 确认无业务依赖后运行 `userdel -r <用户名>` 删除账户与家目录，并检查 `crontab -l -u <用户名>` 等残留任务。",
        "3. 再次执行 `lastlog | grep <用户名>` 确认账户已不可用，如仍出现记录需继续排查。",
    ],
    ("L3-CES1-08", 0): [
        "1. 与安全/运维团队确认角色划分方案，形成系统管理员、安全审计员、运维人员等角色矩阵并获批。",
        "2. 在 `/etc/group` 中创建或校验对应角色组，使用 `groupadd <角色组>`（如需）后执行 `usermod -aG <角色组> <用户名>` 加入成员。",
        "3. 通过 `getent group <角色组>` 核对成员列表，与角色矩阵保持一致。",
    ],
    ("L3-CES1-08", 1): [
        "1. 打开 `/etc/sudoers` 或 `/etc/sudoers.d/` 目录下的策略文件，确认是否按角色拆分权限块（建议使用 `visudo -f` 编辑）。",
        "2. 通过 `sudo -l -U <用户名>` 验证各管理员仅拥有职责范围内的命令授权，如发现超范围命令需记录。",
        "3. 如存在权限重叠，使用 `visudo` 调整命令别名或移除多余授权，并再次执行 `sudo -l` 验证。",
    ],
    ("L3-CES1-08", 2): [
        "1. 对关键目录执行 `ls -l /etc/passwd /etc/shadow /etc/sudoers` 检查权限是否符合最小化原则，并记录不符合项。",
        "2. 使用 `chmod <权限> <文件>`、`chown <用户>:<组> <文件>` 修复权限过宽的文件，必要时结合 `setfacl` 清理多余 ACL。",
        "3. 再次执行 `sudo -l`、`getfacl <文件>` 等命令确认权限已收敛且未破坏业务。",
    ],
    ("L3-CES1-11", 0): [
        "1. 在 RedHat 系列执行 `yum install selinux-policy-targeted policycoreutils`，或在 Debian 系列执行 `apt install selinux-basics selinux-policy-default` / `apt install apparmor` 部署安全标记机制。",
        "2. 安装完成后运行 `sestatus`（SELinux）或 `aa-status`（AppArmor）确认组件已就绪且未报错。",
        "3. 若仍未启用，请编辑 `/etc/selinux/config`（SELINUX=enforcing）或 `/etc/default/grub`（追加 `security=selinux`），保存后根据提示执行 `grub2-mkconfig` 并计划维护窗口重启。",
    ],
    ("L3-CES1-11", 1): [
        "1. 对 SELinux 执行 `setenforce 1` 立即切换到 Enforcing，若使用 AppArmor 则运行 `aa-enforce /etc/apparmor.d/*`。",
        "2. 重新运行 `sestatus` 或 `aa-status` 确认当前模式显示为 enforcing/complain 之外的强制状态，并记录时间。",
        "3. 按照变更流程组织关键业务回归测试，若出现兼容性问题记录 AVC 日志并使用 `semanage`/`aa-complain` 临时放行。",
    ],
    ("L3-CES1-12", 1): [
        "1. 编辑 `/etc/audit/rules.d/hardening.rules`，按需添加登录、权限变更、关键文件访问等规则，建议参考示例：`-w /etc/passwd -p wa -k identity`。",
        "2. 保存后执行 `augenrules --load` 或 `service auditd reload` 应用新规则，如报错请检查语法。",
        "3. 使用 `auditctl -l | grep identity` 核实规则已加载，并执行一次登录/权限变更操作，随后 `ausearch -k identity` 验证日志写入。",
    ],
    ("L3-CES1-12", 2): [
        "1. 通过 `ausearch -ts recent` 或 `grep` 检查 `/var/log/audit/audit.log` 是否包含重要操作，记录缺失的事件类型。",
        "2. 根据缺失项补充 auditd 规则或在 `/etc/rsyslog.conf`、`/etc/rsyslog.d/` 调整过滤策略，确保关键日志被采集。",
        "3. 重新触发相应操作并使用 `ausearch`/`journalctl` 验证日志包含日期、用户、事件结果等字段。",
    ],
    ("L3-CES1-13", 0): [
        "1. 使用 `ausearch -ts recent` 或 `tail -f /var/log/audit/audit.log` 抽样，确认每条记录包含时间、用户、类型及结果等字段。",
        "2. 若字段不完整，修改 `/etc/audit/auditd.conf` 中 `log_format = RAW`、`name_format` 等参数，并补充 auditd 规则收集上下文。",
        "3. 执行 `service auditd reload` 后再次采样，确保日志内容完整无误。",
    ],
    ("L3-CES1-17", 0): [
        "1. 运行 `dpkg -l > /tmp/pkg.list`（Debian/Ubuntu）或 `rpm -qa > /tmp/pkg.list`（RHEL/CentOS）导出全部软件包清单。",
        "2. 将清单与业务所需组件对照，记录可卸载软件，必要时与应用负责人确认影响。",
        "3. 形成卸载计划，注明执行窗口与回退方案。",
    ],
    ("L3-CES1-17", 1): [
        "1. 按计划逐项使用 `apt purge <包名>` 或 `yum remove <包名>` 卸载非必要组件；若为服务类组件，先执行 `systemctl disable --now <服务名>` 停止运行。",
        "2. 卸载后运行 `dpkg -l | grep <包名>` 或 `rpm -qa | grep <包名>` 验证已移除，如残留配置请手动删除。",
        "3. 重新执行软件清单命令并更新资产记录，确保最小安装原则得到落实。",
    ],
    ("L3-CES1-19", 0): [
        "1. 编辑 `/etc/ssh/sshd_config`，配置 `AllowUsers admin@10.0.0.*`、`AllowGroups ops` 或 `Match Address` 段落限制可远程管理的账户与来源 IP。",
        "2. 同步更新网络层限制，可执行 `firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=<管理网段> service name=ssh accept'` 或 `iptables -A INPUT -s <管理网段> -p tcp --dport 22 -j ACCEPT`，并拒绝其他来源。",
        "3. 执行 `systemctl restart sshd` 应用配置，随后分别在允许和禁止的终端尝试连接验证限制生效。",
    ],
    ("L3-CES1-23", 0): [
        "1. 安装防病毒软件，例如 `apt install clamav-daemon` 或 `yum install clamav`，并确保 `systemctl enable --now clamav-daemon` 成功。",
        "2. 运行 `freshclam` 更新病毒库，随后执行 `systemctl enable --now clamav-freshclam` 维持自动更新。",
        "3. 使用 `crontab -e` 添加任务 `0 3 * * * clamscan -r / --log=/var/log/clamav/clamav-$(date +\%F).log`，安排每日扫描并保留日志。",
    ],
    ("L3-CES1-23", 1): [
        "1. 部署完整性监控工具，如执行 `apt install aide` 或 `yum install aide` 安装 AIDE。",
        "2. 首次运行 `aideinit` 生成基线数据库，并将 `/var/lib/aide/aide.db.new.gz` 重命名覆盖 `/var/lib/aide/aide.db.gz`。",
        "3. 在 `crontab` 或计划任务中配置 `aide --check` 的定期运行，并审阅结果确保异常及时处理。",
    ],
    ("L3-CES1-23", 2): [
        "1. 启动实时防护服务，例如执行 `systemctl enable --now clamav-daemon` 或供应商提供的守护进程，确认状态为 active。",
        "2. 在防护软件策略中配置发现恶意行为时自动隔离/阻断，并开启邮件或日志告警，必要时记录策略名称。",
        "3. 通过下载 EICAR 测试文件或模拟样本验证能够实时阻断，并检查日志/告警是否同步生成。",
    ],

}


class LinuxComplianceChecker:
    """Implements the third-level compliance checks defined in section 8.1.4."""

    def __init__(self) -> None:
        self.results: Dict[str, Dict[str, object]] = {}
        self.os_info = self.get_os_info()
        self.current_user = os.getenv("USER")
        self.package_manager: Optional[str] = self.detect_package_manager()
        self.remediation_records: List[Dict[str, object]] = []
        self.remediation_report_path: Optional[str] = None
        self.apt_cache_refreshed = False

        self.item_metadata: Dict[str, Dict[str, object]] = {}
        self.item_categories: Dict[str, str] = {}
        for category in CHECK_ITEMS.values():
            title = category.get("title", "")
            for item_id, metadata in category.get("items", {}).items():
                self.item_metadata[item_id] = metadata
                self.item_categories[item_id] = title

        self.remediation_handlers = {
            ("L3-CES1-01", 2): self.remediate_empty_passwords,
            ("L3-CES1-01", 3): self.remediate_password_complexity,
            ("L3-CES1-01", 4): self.remediate_password_rotation,
            ("L3-CES1-02", 0): self.remediate_login_failure_module,
            ("L3-CES1-02", 1): self.remediate_login_failure_module,
            ("L3-CES1-02", 2): self.remediate_session_timeout,
            ("L3-CES1-03", 0): self.remediate_ssh_protocol_security,
            ("L3-CES1-12", 0): self.remediate_audit_services,
            ("L3-CES1-14", 0): self.remediate_audit_log_permissions,
            ("L3-CES1-14", 1): self.remediate_logrotate_policy,
            ("L3-CES1-18", 0): self.remediate_disable_unnecessary_services,
            ("L3-CES1-18", 1): self.remediate_high_risk_ports,
        }

    @staticmethod
    def get_os_info() -> Dict[str, str]:
        info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "distribution": LinuxComplianceChecker.get_linux_distribution(),
        }
        return info

    @staticmethod
    def get_linux_distribution() -> str:
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                data = f.read()
            name = re.search(r'NAME="(.+?)"', data)
            version = re.search(r'VERSION_ID="(.+?)"', data)
            if name:
                if version:
                    return f"{name.group(1)} {version.group(1)}"
                return name.group(1)
        except FileNotFoundError:
            pass
        return "Unknown"

    def detect_package_manager(self) -> Optional[str]:
        for manager, binary in (
            ("dpkg", "dpkg-query"),
            ("rpm", "rpm"),
            ("pacman", "pacman"),
            ("apk", "apk"),
        ):
            if shutil.which(binary):
                return manager
        return None

    def is_package_installed(self, package: str) -> Optional[bool]:
        manager = self.package_manager or self.detect_package_manager()
        if not manager:
            return None
        self.package_manager = manager

        if manager == "dpkg":
            rc, stdout, _ = self.run_command(
                f"dpkg-query -W -f='${{Status}}' {package}"
            )
            if rc == 0:
                return "install ok installed" in stdout.lower()
            if rc > 0:
                return False
            return None

        if manager == "rpm":
            rc, _, _ = self.run_command(f"rpm -q {package}")
            if rc == 0:
                return True
            if rc > 0:
                return False
            return None

        if manager == "pacman":
            rc, _, _ = self.run_command(f"pacman -Qi {package}")
            if rc == 0:
                return True
            if rc > 0:
                return False
            return None

        if manager == "apk":
            rc, stdout, _ = self.run_command(f"apk info -e {package}")
            if rc == 0:
                return package in stdout.split()
            if rc > 0:
                return False
            return None

        return None

    @staticmethod
    def read_file(path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except (FileNotFoundError, PermissionError, OSError):
            return None

    @staticmethod
    def run_command(command: str, timeout: int = 15) -> Tuple[int, str, str]:
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except Exception as exc:  # pylint: disable=broad-except
            return -1, "", str(exc)

    @staticmethod
    def command_has_placeholder(command: str) -> bool:
        """Check whether a suggested command contains obvious placeholders."""

        return any(token in command for token in ("<", "…", "..."))

    @staticmethod
    def normalise_service_candidate(name: str) -> str:
        cleaned = name.strip().strip('"')
        if not cleaned:
            return ""
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[-1]
        cleaned = cleaned.split("@", 1)[0]
        cleaned = cleaned.split(":", 1)[0]
        cleaned = cleaned.split()[0]
        if cleaned.endswith(".service"):
            cleaned = cleaned[: -len(".service")]
        return cleaned

    def collect_listening_processes(self) -> Dict[int, Set[str]]:
        listeners: Dict[int, Set[str]] = {}
        for command in ("ss -tulnp", "netstat -tulnp"):
            rc, stdout, _ = self.run_command(command)
            if rc != 0 or not stdout:
                continue
            for line in stdout.splitlines():
                parts = line.split()
                if command.startswith("ss"):
                    if len(parts) < 5:
                        continue
                    local_field = parts[4]
                else:
                    if len(parts) < 4:
                        continue
                    local_field = parts[3]
                port_match = re.search(r"(\d+)$", local_field)
                if not port_match:
                    continue
                port = int(port_match.group(1))
                process_names: Set[str] = set()
                for match in re.findall(r'"([^"]+)"', line):
                    candidate = self.normalise_service_candidate(match)
                    if candidate:
                        process_names.add(candidate)
                if not process_names and parts:
                    last_field = parts[-1]
                    if "/" in last_field:
                        candidate = self.normalise_service_candidate(last_field)
                        if candidate:
                            process_names.add(candidate)
                if process_names:
                    listeners.setdefault(port, set()).update(process_names)
                else:
                    listeners.setdefault(port, set())
        return listeners

    @staticmethod
    def extract_ports_from_subitem(subitem: Dict[str, object]) -> Set[int]:
        ports: Set[int] = set()
        for container in (
            subitem.get("details", []),
            subitem.get("recommendation", []),
        ):
            for entry in container:
                for match in re.findall(r"端口(\d+)", entry):
                    ports.add(int(match))
                for match in re.findall(r"\b(\d{2,5})\b", entry):
                    try:
                        value = int(match)
                    except ValueError:
                        continue
                    if value in HIGH_RISK_PORTS:
                        ports.add(value)
        return ports

    @staticmethod
    def get_login_users() -> Dict[str, pwd.struct_passwd]:
        users: Dict[str, pwd.struct_passwd] = {}
        for entry in pwd.getpwall():
            if entry.pw_shell and entry.pw_shell in INTERACTIVE_SHELLS:
                users[entry.pw_name] = entry
        return users

    @staticmethod
    def parse_key_values(lines: List[str]) -> Dict[str, str]:
        settings: Dict[str, str] = {}
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                key, value = stripped.split("=", 1)
                settings[key.strip()] = value.strip()
        return settings

    @staticmethod
    def days_since_epoch() -> int:
        epoch = datetime(1970, 1, 1)
        return (datetime.now() - epoch).days

    @staticmethod
    def make_subitem(description: str) -> Dict[str, object]:
        return {
            "description": description,
            "status": "PASS",
            "details": [],
            "recommendation": [],
        }

    def finalize_item(self, item: str, subitems: List[Dict[str, object]]) -> None:
        overall_status = "PASS"
        aggregated_details: List[str] = []
        aggregated_recommendations: List[str] = []

        for sub in subitems:
            status = sub.get("status", "PASS")
            if status == "FAIL":
                overall_status = "FAIL"
            elif status == "ERROR" and overall_status != "FAIL":
                overall_status = "ERROR"

            aggregated_details.append(f"[{status}] {sub['description']}")
            for detail in sub.get("details", []):
                aggregated_details.append(f"  - {detail}")
            if status != "PASS":
                aggregated_recommendations.extend(sub.get("recommendation", []))

        unique_recommendations: List[str] = []
        for reco in aggregated_recommendations:
            if reco and reco not in unique_recommendations:
                unique_recommendations.append(reco)

        self.results[item] = {
            "status": overall_status,
            "details": aggregated_details,
            "recommendation": "\n".join(unique_recommendations),
            "subitems": subitems,
        }

    def collect_remediation_targets(self) -> List[Dict[str, object]]:
        """Gather all failing subitems that require remediation."""

        targets: List[Dict[str, object]] = []
        for category in CHECK_ITEMS.values():
            title = category.get("title", "")
            for item_id, metadata in category.get("items", {}).items():
                result = self.results.get(
                    item_id,
                    {"status": "UNKNOWN", "subitems": [], "details": []},
                )
                subitems = result.get("subitems", [])
                if subitems:
                    for index, subitem in enumerate(subitems):
                        status = subitem.get("status", "PASS")
                        if status not in {"FAIL", "ERROR"}:
                            continue
                        implementation = ""
                        implementation_list = metadata.get("implementation")
                        if (
                            isinstance(implementation_list, list)
                            and index < len(implementation_list)
                        ):
                            implementation = implementation_list[index]
                        targets.append(
                            {
                                "item_id": item_id,
                                "category": title,
                                "indicator": metadata.get("indicator", ""),
                                "subitem_index": index,
                                "subitem": subitem,
                                "implementation_text": implementation,
                                "result_status": status,
                            }
                        )
                elif result.get("status") in {"FAIL", "ERROR"}:
                    recommendation_value = result.get("recommendation")
                    if isinstance(recommendation_value, list):
                        record_recommendations = recommendation_value
                    elif recommendation_value:
                        record_recommendations = [recommendation_value]
                    else:
                        record_recommendations = []
                    targets.append(
                        {
                            "item_id": item_id,
                            "category": title,
                            "indicator": metadata.get("indicator", ""),
                            "subitem_index": None,
                            "subitem": {
                                "description": metadata.get("indicator", item_id),
                                "status": result.get("status"),
                                "details": result.get("details", []),
                                "recommendation": record_recommendations,
                            },
                            "implementation_text": "",
                            "result_status": result.get("status"),
                        }
                    )
        return targets

    def run_remediation(self) -> None:
        """Automatically remediate failing checks where possible."""

        targets = self.collect_remediation_targets()
        if not targets:
            print(f"\n{Colors.GREEN}所有检查项均符合要求，无需整改。{Colors.END}")
            return

        self.remediation_records = []

        print(f"\n{Colors.CYAN}=== 开始整改流程 ==={Colors.END}")
        print("以下测评子项存在不符合或错误，需要整改:")
        for index, target in enumerate(targets, 1):
            description = target["subitem"].get("description", "")
            status = target["result_status"]
            print(
                f" {index}. {target['item_id']} - {description} (当前状态: {status})"
            )

        print()
        for index, target in enumerate(targets, 1):
            subitem = target["subitem"]
            description = subitem.get("description", "")
            print(
                f"{Colors.BLUE}整改项 {index}: {target['item_id']} - {description}{Colors.END}"
            )
            if target.get("indicator"):
                print(f"   测评指标: {target['indicator']}")
            if target.get("implementation_text"):
                print(f"   对应实施要点: {target['implementation_text']}")
            details = subitem.get("details", [])
            if details:
                print("   当前问题:")
                for detail in details:
                    print(f"     - {detail}")
            recommendations = subitem.get("recommendation", [])
            if recommendations:
                print("   推荐整改措施:")
                for rec in recommendations:
                    print(f"     * {rec}")

            record = {
                "item_id": target["item_id"],
                "category": target.get("category", ""),
                "indicator": target.get("indicator", ""),
                "subitem_description": description,
                "implementation": target.get("implementation_text", ""),
                "initial_status": target.get("result_status", ""),
                "recommendations": recommendations[:],
            }

            proceed = self.prompt_user_confirmation(
                "   是否执行该项整改？(y/n，直接回车表示否): "
            )
            if proceed:
                status, notes = self.apply_remediation(target)
            else:
                status = "SKIPPED"
                notes = ["用户选择暂不整改该项。"]
            record["status"] = status
            record["notes"] = notes
            self.remediation_records.append(record)
            print(
                f"   -> 整改结果: {self.format_status_label(status)}"
            )
            for note in notes:
                print(f"      {note}")

        self.generate_remediation_report()

    def apply_remediation(self, target: Dict[str, object]) -> Tuple[str, List[str]]:
        """Dispatch remediation to an automated or manual handler."""

        handler = self.remediation_handlers.get(
            (target["item_id"], target.get("subitem_index"))
        )
        try:
            if handler:
                status, notes = handler(target)
            else:
                status, notes = self.handle_manual_remediation(target)
        except Exception as exc:  # pylint: disable=broad-except
            status = "FAILED"
            notes = [f"执行整改时发生异常: {exc}"]

        if not isinstance(notes, list):
            notes = [str(notes)]
        return status, notes

    def handle_manual_remediation(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """Interactive fallback when only manual/semi-automatic remediation is possible."""

        item_id = target.get("item_id")
        sub_index = target.get("subitem_index")
        subitem = target.get("subitem", {})
        implementation_text = target.get("implementation_text", "")
        recommendations = subitem.get("recommendation", []) or []
        details = subitem.get("details", []) or []

        steps = MANUAL_REMEDIATION_GUIDES.get((item_id, sub_index))
        has_custom_steps = False
        if steps is None:
            steps = MANUAL_REMEDIATION_GUIDES.get((item_id, None))
            has_custom_steps = steps is not None
        else:
            has_custom_steps = True

        if not steps:
            has_custom_steps = False
            fallback = target.get("indicator") or implementation_text
            if fallback:
                steps = [
                    "1. 根据测评实施要点检查相关配置，并在当前终端完成必要的修改。",
                    f"2. 重点核查: {fallback}",
                ]
            else:
                steps = [
                    "1. 根据单位安全策略核查配置，并在当前终端完成整改。",
                ]

        print(
            f"   {Colors.YELLOW}该项暂无法完全自动整改，将通过交互式步骤协助完成。{Colors.END}"
        )

        step_notes: List[str] = ["已启动交互式手动整改流程。"]
        for index, step in enumerate(steps, 1):
            print(f"   步骤{index}: {step}")
            step_notes.append(f"步骤{index}: {step}")
            commands = re.findall(r"`([^`]+)`", step)
            if not commands:
                try:
                    response = input(
                        "     完成上述操作后按回车继续，或输入 skip 跳过: "
                    )
                except EOFError:
                    response = "skip"

                if response.strip().lower() in {"skip", "s"}:
                    step_notes.append("用户暂未执行该步骤，需后续复核。")
                else:
                    step_notes.append("用户确认已处理该步骤。")
                continue

            step_skipped = False
            executed_any_command = False
            for command in commands:
                suggested = command.strip()
                has_placeholder = self.command_has_placeholder(suggested)
                if has_placeholder:
                    print(
                        "     建议命令包含占位符，请根据实际情况提供具体命令。"
                    )
                else:
                    print(f"     建议执行命令: {suggested}")

                while True:
                    try:
                        if has_placeholder:
                            prompt = (
                                "     请输入要执行的命令（输入 skip 跳过该命令）: "
                            )
                        else:
                            prompt = (
                                "     按回车执行上述命令，输入自定义命令替换，"
                                "或输入 skip 跳过: "
                            )
                        user_input = input(prompt)
                    except EOFError:
                        user_input = "skip"

                    if user_input is None:
                        user_input = ""
                    chosen = user_input.strip()

                    if not chosen and has_placeholder:
                        print("     该命令需要具体参数，请输入命令或输入 skip 跳过。")
                        continue

                    if chosen.lower() in {"skip", "s"}:
                        step_notes.append(
                            f"命令 `{suggested}` 被用户选择跳过。"
                        )
                        step_skipped = True
                        break

                    actual_command = chosen or suggested
                    rc, stdout, stderr = self.run_command(actual_command)
                    step_notes.append(
                        f"命令 `{actual_command}` 执行返回码 {rc}。"
                    )
                    executed_any_command = True

                    print(f"     -> 返回码: {rc}")
                    if stdout:
                        print("        STDOUT:")
                        for line in stdout.splitlines():
                            print(f"          {line}")
                    if stderr:
                        print("        STDERR:")
                        for line in stderr.splitlines():
                            print(f"          {line}")

                    if rc != 0:
                        if self.prompt_user_confirmation(
                            "     命令执行失败，是否重试？(y/n，回车表示否): "
                        ):
                            continue
                    break

                if step_skipped:
                    step_notes.append(
                        "该步骤包含的命令暂未执行，需在维护窗口内补充完成。"
                    )
                    break

            if step_skipped:
                continue

            if executed_any_command:
                if self.prompt_user_confirmation(
                    "     命令执行完毕，结果是否符合预期？(y/n，回车表示否): "
                ):
                    step_notes.append("用户确认命令执行结果符合预期。")
                else:
                    step_notes.append("用户提示该步骤仍需人工复核。")
            else:
                step_notes.append("该步骤未执行任何命令，请在后续计划中补充。")

        if not has_custom_steps:
            if implementation_text:
                step_notes.append(f"• 测评实施要点: {implementation_text}")

            if details:
                step_notes.append("• 当前检测发现：")
                step_notes.extend(f"  - {detail}" for detail in details)

            if recommendations:
                step_notes.append("• 完成整改后请确认：")
                step_notes.extend(f"  - {text}" for text in recommendations)

        completed = self.prompt_user_confirmation(
            "   是否已完成上述步骤并确认整改符合要求？(y/n，回车表示否): "
        )
        if completed:
            step_notes.append("用户确认该项整改已完成。")
            status = "APPLIED"
        else:
            step_notes.append("用户尚未确认整改完成，请后续复核。")
            status = "PARTIAL"

        return status, step_notes

    @staticmethod
    def prompt_user_confirmation(message: str) -> bool:
        """Prompt the operator before executing a remediation step."""

        while True:
            try:
                response = input(message).strip().lower()
            except EOFError:
                return False
            if response in {"y", "yes", "是"}:
                return True
            if response in {"", "n", "no", "否"}:
                return False
            print("请输入 y/n 或者 按回车取消。")

    @staticmethod
    def password_meets_recommended_policy(password: str) -> bool:
        """Check whether the password meets the recommended complexity guidance."""

        if len(password) < 10:
            return False
        categories = 0
        if re.search(r"[A-Z]", password):
            categories += 1
        if re.search(r"[a-z]", password):
            categories += 1
        if re.search(r"\d", password):
            categories += 1
        if re.search(r"[^A-Za-z0-9]", password):
            categories += 1
        return categories >= 3

    def prompt_new_password(self, username: str) -> Optional[str]:
        """Interactively request a new password for the specified account."""

        print(f"      用户 {username} 当前存在空口令，需要设置符合策略的新密码。")
        print(
            "      建议密码至少10位，包含大写/小写字母、数字和特殊字符，并在90天内完成轮换。"
        )

        attempts = 0
        while attempts < 3:
            try:
                new_password = getpass(
                    f"      请输入用户 {username} 新密码 (直接回车跳过): "
                )
            except (EOFError, KeyboardInterrupt):
                print("      输入被取消，已跳过该用户的自动修改。")
                return None

            if not new_password:
                print("      未输入密码，将跳过该用户的自动修改。")
                return None

            try:
                confirmation = getpass("      请再次输入新密码以确认: ")
            except (EOFError, KeyboardInterrupt):
                print("      输入被取消，已跳过该用户的自动修改。")
                return None

            if new_password != confirmation:
                print("      两次输入不一致，请重新输入。")
                attempts += 1
                continue

            if not self.password_meets_recommended_policy(new_password):
                print("      新密码未满足建议的复杂度要求。")
                if not self.prompt_user_confirmation(
                    "      是否仍然继续使用该密码？(y/n，回车表示否): "
                ):
                    attempts += 1
                    continue

            return new_password

        print("      已多次尝试失败，跳过该用户的自动修改。")
        return None

    @staticmethod
    def change_password_with_chpasswd(
        chpasswd_path: str, username: str, new_password: str
    ) -> Tuple[bool, str]:
        """Use chpasswd to update a user's password without echoing secrets."""

        try:
            result = subprocess.run(
                [chpasswd_path],
                input=f"{username}:{new_password}\n",
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except Exception as exc:  # pylint: disable=broad-except
            return False, f"调用chpasswd为用户 {username} 设置密码失败: {exc}"

        if result.returncode == 0:
            return True, f"已为用户 {username} 设置新密码"

        detail = result.stderr.strip() or result.stdout.strip() or "chpasswd命令执行失败"
        return False, f"使用chpasswd设置用户 {username} 密码失败: {detail}"

    @staticmethod
    def format_status_label(status: str) -> str:
        """Translate remediation状态标签 to Chinese for display."""

        return STATUS_LABELS.get(status, status)

    @staticmethod
    def create_backup(path: str) -> Optional[str]:
        """Create a timestamped backup of the specified file."""

        if not os.path.exists(path):
            return None
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{path}.bak_{timestamp}"
        try:
            shutil.copy2(path, backup_path)
        except OSError:
            return None
        return backup_path

    def maybe_restart_service(
        self, service: str, notes: List[str], manual_message: str
    ) -> None:
        """Offer to restart a service immediately if systemctl is available."""

        if shutil.which("systemctl") is None:
            notes.append(manual_message)
            return

        prompt = (
            f"   是否立即执行 'systemctl restart {service}' 以使配置立即生效？"
            "(y/n，直接回车表示否): "
        )
        if self.prompt_user_confirmation(prompt):
            rc, stdout, stderr = self.run_command(f"systemctl restart {service}")
            if rc == 0:
                notes.append(f"已自动执行: systemctl restart {service}")
            else:
                detail = stderr or stdout or "systemctl 执行失败"
                notes.append(
                    f"自动执行 systemctl restart {service} 失败: {detail}"
                )
                notes.append(manual_message)
        else:
            notes.append(manual_message)

    def update_or_append_line(
        self,
        path: str,
        pattern: str,
        new_line: str,
        comment: Optional[str] = None,
        case_insensitive: bool = False,
    ) -> Tuple[bool, str]:
        """Ensure a configuration line exists, updating or appending as needed."""

        if not os.path.exists(path):
            return False, f"{path} 不存在，无法自动整改"
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as src:
                lines = src.readlines()
        except OSError as exc:
            return False, f"读取{path}失败: {exc}"

        flags = re.IGNORECASE if case_insensitive else 0
        regex = re.compile(pattern, flags)
        changed = False
        found = False
        for idx, line in enumerate(lines):
            if regex.match(line.strip()):
                found = True
                if line.strip() != new_line:
                    lines[idx] = new_line + "\n"
                    changed = True
        if not found:
            if comment:
                comment_line = comment if comment.endswith("\n") else comment + "\n"
                lines.append(comment_line)
            lines.append(new_line + "\n")
            changed = True

        if not changed:
            return True, f"{path} 已包含所需配置"

        backup = self.create_backup(path)
        try:
            with open(path, "w", encoding="utf-8") as dest:
                dest.writelines(lines)
        except OSError as exc:
            return False, f"写入{path}失败: {exc}"

        if backup:
            return True, f"已更新{path}，备份文件: {backup}"
        return True, f"已更新{path}"

    def install_package(self, package: str) -> Tuple[bool, str]:
        """Attempt to install a package using the detected package manager."""

        manager = self.package_manager or self.detect_package_manager()
        if not manager:
            return False, "无法确定包管理器，无法安装软件包"
        self.package_manager = manager

        if manager == "dpkg":
            installer = "apt-get" if shutil.which("apt-get") else "apt"
            if not installer or not shutil.which(installer):
                return False, "未找到apt或apt-get命令"
            update_msg = ""
            if not self.apt_cache_refreshed:
                update_cmd = f"{installer} update"
                rc, _, err = self.run_command(update_cmd, timeout=300)
                if rc == 0:
                    self.apt_cache_refreshed = True
                else:
                    update_msg = f"执行{update_cmd}失败: {err or '请检查网络连接'}"
            install_cmd = f"{installer} install -y {package}"
            rc, stdout, stderr = self.run_command(install_cmd, timeout=300)
            if rc == 0:
                message = f"已安装软件包 {package}"
                if update_msg:
                    message = update_msg + "；" + message
                return True, message
            failure_msg = f"安装{package}失败: {stderr or stdout or '未知错误'}"
            if update_msg:
                failure_msg = update_msg + "；" + failure_msg
            return False, failure_msg

        if manager == "rpm":
            installer = None
            for candidate in ("dnf", "yum"):
                if shutil.which(candidate):
                    installer = candidate
                    break
            if not installer:
                return False, "未找到dnf或yum命令"
            install_cmd = f"{installer} install -y {package}"
            rc, stdout, stderr = self.run_command(install_cmd, timeout=300)
            if rc == 0:
                return True, f"已安装软件包 {package}"
            return False, f"安装{package}失败: {stderr or stdout or '未知错误'}"

        if manager == "pacman":
            install_cmd = f"pacman -Sy --noconfirm {package}"
            rc, stdout, stderr = self.run_command(install_cmd, timeout=300)
            if rc == 0:
                return True, f"已安装软件包 {package}"
            return False, f"安装{package}失败: {stderr or stdout or '未知错误'}"

        if manager == "apk":
            install_cmd = f"apk add {package}"
            rc, stdout, stderr = self.run_command(install_cmd, timeout=300)
            if rc == 0:
                return True, f"已安装软件包 {package}"
            return False, f"安装{package}失败: {stderr or stdout or '未知错误'}"

        return False, "暂不支持当前包管理器的自动安装"

    def detect_pam_lock_module(self) -> Optional[str]:
        """Detect which PAM module (pam_faillock/pam_tally2) is available."""

        pam_files = [
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/sshd",
        ]
        for pam_file in pam_files:
            content = self.read_file(pam_file)
            if not content:
                continue
            if "pam_faillock.so" in content:
                return "pam_faillock.so"
            if "pam_tally2.so" in content:
                return "pam_tally2.so"

        module_paths = {
            "pam_faillock.so": [
                "/usr/lib64/security/pam_faillock.so",
                "/usr/lib/security/pam_faillock.so",
                "/lib64/security/pam_faillock.so",
                "/lib/security/pam_faillock.so",
            ],
            "pam_tally2.so": [
                "/usr/lib64/security/pam_tally2.so",
                "/usr/lib/security/pam_tally2.so",
                "/lib64/security/pam_tally2.so",
                "/lib/security/pam_tally2.so",
            ],
        }
        for module, paths in module_paths.items():
            for path in paths:
                if os.path.exists(path):
                    return module
        return None

    def remediate_empty_passwords(self, target: Dict[str, object]) -> Tuple[str, List[str]]:
        """Lock accounts that still use an empty password."""

        login_users = self.get_login_users()
        empty_users: List[str] = []
        try:
            with open("/etc/shadow", "r", encoding="utf-8", errors="ignore") as shadow_file:
                for line in shadow_file:
                    if not line.strip() or ":" not in line:
                        continue
                    username, password_hash, *_ = line.split(":", 3)
                    if username in login_users and password_hash == "":
                        empty_users.append(username)
        except PermissionError as exc:
            return "FAILED", [f"无法读取/etc/shadow: {exc}"]
        except OSError as exc:
            return "FAILED", [f"读取/etc/shadow失败: {exc}"]

        if not empty_users:
            return "APPLIED", ["未再检测到空口令账户"]

        chpasswd_cmd = shutil.which("chpasswd")
        passwd_cmd = shutil.which("passwd")
        usermod_cmd = shutil.which("usermod")
        if not chpasswd_cmd and not passwd_cmd and not usermod_cmd:
            return (
                "PENDING",
                [
                    "未找到chpasswd/passwd/usermod命令，无法自动修复空口令账户，请手动为相关用户设置密码",
                ],
            )

        nologin_shell = next(
            (shell for shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false") if os.path.exists(shell)),
            "/sbin/nologin",
        )

        success = True
        notes: List[str] = []
        any_changed = False
        any_locked = False
        any_failed = False

        if not chpasswd_cmd:
            notes.append(
                "未找到chpasswd命令，将尝试锁定空口令账户，请在整改后手动为相关用户设置强密码"
            )

        for user in sorted(empty_users):
            changed = False
            locked = False

            if chpasswd_cmd:
                new_password = self.prompt_new_password(user)
                if new_password:
                    change_ok, message = self.change_password_with_chpasswd(
                        chpasswd_cmd, user, new_password
                    )
                    notes.append(message)
                    if change_ok:
                        changed = True
                        any_changed = True
                    else:
                        success = False
                else:
                    notes.append(
                        f"用户 {user} 未提供新密码，将继续尝试锁定该账户防止空口令登录"
                    )

            if not changed:
                lock_result = None
                if passwd_cmd:
                    rc, _, stderr = self.run_command(f"passwd -l {user}")
                    if rc == 0:
                        notes.append(f"已锁定用户 {user} 的密码，等待管理员设置新密码")
                        lock_result = True
                        locked = True
                        any_locked = True
                    else:
                        lock_result = False
                        success = False
                        error_text = stderr or "passwd命令执行失败"
                        notes.append(f"passwd -l {user} 失败: {error_text}")
                if lock_result is False and usermod_cmd:
                    rc, _, stderr = self.run_command(
                        f"usermod -s {nologin_shell} {user}"
                    )
                    if rc == 0:
                        notes.append(
                            f"已将用户 {user} 的登录shell设置为 {nologin_shell} 以阻止空口令登录"
                        )
                        locked = True
                        any_locked = True
                    else:
                        success = False
                        error_text = stderr or "usermod命令执行失败"
                        notes.append(
                            f"usermod -s {nologin_shell} {user} 失败: {error_text}"
                        )

            if not changed and not locked:
                any_failed = True
                if user == "root":
                    notes.append("请立即为root账户设置强密码，避免使用空口令")

        if any_failed and not any_changed and not any_locked:
            return "FAILED", notes
        if any_failed or any_locked:
            return "PARTIAL", notes
        if not success:
            return "PARTIAL", notes
        return "APPLIED", notes

    def remediate_password_complexity(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """Harden pwquality and PAM settings to enforce password complexity."""

        notes: List[str] = []
        success = True
        pwquality_path = "/etc/security/pwquality.conf"
        if not os.path.exists(pwquality_path):
            try:
                with open(pwquality_path, "w", encoding="utf-8") as conf:
                    conf.write("# Created by LinuxComplianceChecker to enforce password complexity\n")
                notes.append(f"已创建{pwquality_path} 并写入初始配置")
            except OSError as exc:
                return "FAILED", [f"创建{pwquality_path}失败: {exc}"]

        settings = [
            (r"minlen\s*=", "minlen = 10"),
            (r"dcredit\s*=", "dcredit = -1"),
            (r"ucredit\s*=", "ucredit = -1"),
            (r"lcredit\s*=", "lcredit = -1"),
            (r"ocredit\s*=", "ocredit = -1"),
        ]
        for pattern, line in settings:
            ok, msg = self.update_or_append_line(
                pwquality_path,
                pattern,
                line,
                "# LinuxComplianceChecker: enforce password complexity",
            )
            notes.append(msg)
            if not ok:
                success = False

        pam_line = (
            "password    requisite     pam_pwquality.so try_first_pass local_users_only "
            "retry=3 minlen=10 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1"
        )
        pam_files = [
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
            "/etc/pam.d/common-password",
        ]
        pam_success = False
        for pam_file in pam_files:
            if not os.path.exists(pam_file):
                continue
            ok, msg = self.update_or_append_line(
                pam_file,
                r".*pam_pwquality\.so.*",
                pam_line,
                "# LinuxComplianceChecker: ensure pam_pwquality启用",
            )
            notes.append(msg)
            if ok:
                pam_success = True
            else:
                success = False

        if not pam_success:
            notes.append("未能在常见PAM配置文件中写入pam_pwquality，请确认系统PAM策略")
            success = False

        return ("APPLIED" if success else "PARTIAL", notes)

    def remediate_password_rotation(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """Configure login.defs and per-user settings for password rotation."""

        notes: List[str] = []
        success = True
        login_defs = "/etc/login.defs"
        if not os.path.exists(login_defs):
            try:
                with open(login_defs, "w", encoding="utf-8") as defs:
                    defs.write("# Created by LinuxComplianceChecker for password policy\n")
                notes.append(f"已创建{login_defs} 并写入初始策略")
            except OSError as exc:
                return "FAILED", [f"创建{login_defs}失败: {exc}"]

        policy_lines = [
            (r"PASS_MAX_DAYS\s+", "PASS_MAX_DAYS   90"),
            (r"PASS_MIN_DAYS\s+", "PASS_MIN_DAYS   7"),
            (r"PASS_WARN_AGE\s+", "PASS_WARN_AGE   7"),
        ]
        for pattern, line in policy_lines:
            ok, msg = self.update_or_append_line(
                login_defs,
                pattern,
                line,
                "# LinuxComplianceChecker: enforce password rotation policy",
            )
            notes.append(msg)
            if not ok:
                success = False

        chage_cmd = shutil.which("chage")
        if not chage_cmd:
            notes.append("未找到chage命令，无法自动调整现有账户的密码有效期")
            return ("PARTIAL" if success else "FAILED", notes)

        login_users = self.get_login_users()
        if not login_users:
            notes.append("未检测到需要更新策略的交互式用户")
            return ("APPLIED" if success else "PARTIAL", notes)

        for username in sorted(login_users):
            rc, _, stderr = self.run_command(f"chage -M 90 -m 7 -W 7 {username}")
            if rc == 0:
                notes.append(f"已为用户 {username} 设置密码有效期策略 (90/7/7)")
            else:
                success = False
                error_text = stderr or "chage命令执行失败"
                notes.append(f"调整用户 {username} 密码策略失败: {error_text}")

        return ("APPLIED" if success else "PARTIAL", notes)

    def remediate_login_failure_module(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """Ensure PAM login failure modules enforce deny/unlock limits."""

        module = self.detect_pam_lock_module()
        if not module:
            return (
                "PENDING",
                ["未检测到pam_faillock或pam_tally2模块，请先安装相关PAM模块后再执行整改"],
            )

        pam_files = [
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/sshd",
        ]

        lines_to_ensure: List[Tuple[str, str]]
        if module == "pam_faillock.so":
            lines_to_ensure = [
                (
                    r"auth\s+required\s+pam_faillock\.so\s+preauth.*",
                    "auth        required      pam_faillock.so preauth silent deny=5 unlock_time=600 fail_interval=600 even_deny_root",
                ),
                (
                    r"auth\s+required\s+pam_faillock\.so\s+authfail.*",
                    "auth        required      pam_faillock.so authfail deny=5 unlock_time=600 fail_interval=600 even_deny_root",
                ),
                (
                    r"account\s+required\s+pam_faillock\.so.*",
                    "account     required      pam_faillock.so",
                ),
            ]
        else:
            lines_to_ensure = [
                (
                    r"auth\s+required\s+pam_tally2\.so.*",
                    "auth        required      pam_tally2.so onerr=fail audit silent deny=5 unlock_time=600 even_deny_root",
                ),
                (
                    r"account\s+required\s+pam_tally2\.so.*",
                    "account     required      pam_tally2.so",
                ),
            ]

        notes: List[str] = []
        success = False
        for pam_file in pam_files:
            if not os.path.exists(pam_file):
                continue
            file_success = True
            for pattern, line in lines_to_ensure:
                ok, msg = self.update_or_append_line(
                    pam_file,
                    pattern,
                    line,
                    "# LinuxComplianceChecker: enforce login failure策略",
                    case_insensitive=True,
                )
                notes.append(msg)
                if not ok:
                    file_success = False
            if file_success:
                success = True

        if not success:
            notes.append("未能在任何PAM配置文件写入登录失败处理策略，请手动核查PAM配置")
            return "FAILED", notes

        return "APPLIED", notes

    def remediate_audit_services(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """Enable auditd和rsyslog服务，如缺失则尝试安装后启动。"""

        systemctl_path = shutil.which("systemctl")
        service_cmd = shutil.which("service")
        if not systemctl_path and not service_cmd:
            return (
                "PENDING",
                [
                    "未检测到systemctl或service命令，无法自动启用auditd/rsyslog，请按以下步骤手动处理：",
                    "1. 使用 `/etc/init.d/auditd start`、`/etc/init.d/rsyslog start` 或发行版等效脚本启动服务。",
                    "2. 通过 `chkconfig auditd on`、`update-rc.d rsyslog defaults` 等命令设置开机自启。",
                    "3. 执行 `ps -ef | grep -E 'auditd|rsyslog'` 确认服务已运行。",
                ],
            )

        service_packages = {
            "auditd": ["auditd", "audit"],
            "rsyslog": ["rsyslog", "syslog-ng"],
        }

        def ensure_service(service: str) -> Tuple[bool, List[str]]:
            service_notes: List[str] = []
            if systemctl_path:
                rc, stdout, stderr = self.run_command(
                    f"systemctl enable --now {service}", timeout=120
                )
                if rc == 0:
                    service_notes.append(f"已启用并启动 {service} 服务")
                    return True, service_notes
                error_text = stderr or stdout
                if error_text and "not found" in error_text.lower():
                    for package in service_packages.get(service, [service]):
                        ok, msg = self.install_package(package)
                        service_notes.append(msg)
                        if ok:
                            rc, stdout, stderr = self.run_command(
                                f"systemctl enable --now {service}", timeout=120
                            )
                            if rc == 0:
                                service_notes.append(f"已在安装{package}后启动 {service} 服务")
                                return True, service_notes
                            error_text = stderr or stdout
                    service_notes.append(
                        f"无法通过systemctl启动 {service}: {error_text or '未知错误'}"
                    )
                    return False, service_notes
                service_notes.append(
                    f"systemctl 启动{service}失败: {error_text or '未知错误'}"
                )
                return False, service_notes

            # fallback to service command
            rc, stdout, stderr = self.run_command(f"service {service} start", timeout=60)
            if rc == 0:
                service_notes.append(f"已通过service命令启动 {service}")
                return True, service_notes
            service_notes.append(
                f"无法通过service命令启动 {service}: {stderr or stdout or '未知错误'}"
            )
            return False, service_notes

        overall_success = True
        notes: List[str] = []
        for service in ("auditd", "rsyslog"):
            ok, service_notes = ensure_service(service)
            notes.extend(service_notes)
            if not ok:
                overall_success = False

        return ("APPLIED" if overall_success else "PARTIAL", notes)

    def remediate_audit_log_permissions(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """Tighten permissions on critical audit log files."""

        log_files = [
            "/var/log/audit/audit.log",
            "/var/log/secure",
            "/var/log/auth.log",
            "/var/log/messages",
            "/var/log/syslog",
        ]

        notes: List[str] = []
        success = True
        for log in log_files:
            if not os.path.exists(log):
                continue
            try:
                current_mode = stat.S_IMODE(os.stat(log).st_mode)
                desired_mode = current_mode & ~0o007  # 移除其他用户权限
                desired_mode &= ~0o020  # 移除组写
                desired_mode &= ~0o010  # 移除组执行
                desired_mode |= 0o600   # 确保属主读写
                if desired_mode != current_mode:
                    os.chmod(log, desired_mode)
                    notes.append(f"已将 {log} 权限调整为{oct(desired_mode)[-3:]}")
                else:
                    notes.append(f"{log} 权限已符合要求 ({oct(current_mode)[-3:]})")
            except OSError as exc:
                success = False
                notes.append(f"调整{log}权限失败: {exc}")

        if not notes:
            notes.append("未找到需要调整的日志文件")

        return ("APPLIED" if success else "PARTIAL", notes)

    def remediate_logrotate_policy(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """Configure logrotate to retain and compress audit logs."""

        config_path = "/etc/logrotate.conf"
        if not os.path.exists(config_path):
            try:
                with open(config_path, "w", encoding="utf-8") as conf:
                    conf.write("# Created by LinuxComplianceChecker to enforce log rotation\n")
                created_msg = f"已创建{config_path} 并写入初始配置"
            except OSError as exc:
                return "FAILED", [f"创建{config_path}失败: {exc}"]
        else:
            created_msg = ""

        notes: List[str] = []
        if created_msg:
            notes.append(created_msg)

        settings = [
            (r"rotate\s+\d+", "rotate 30"),
            (r"maxsize\s+", "maxsize 100M"),
            (r"compress", "compress"),
        ]
        success = True
        for pattern, line in settings:
            ok, msg = self.update_or_append_line(
                config_path,
                pattern,
                line,
                "# LinuxComplianceChecker: enforce log rotation policy",
            )
            notes.append(msg)
            if not ok:
                success = False

        if success:
            notes.append("请执行 logrotate -f /etc/logrotate.conf 或等待下次计划任务生效")
        return ("APPLIED" if success else "PARTIAL", notes)

    def remediate_session_timeout(self, target: Dict[str, object]) -> Tuple[str, List[str]]:
        """Enforce shell和SSH会话超时。"""

        notes: List[str] = []
        success = True

        ok, msg = self.update_or_append_line(
            "/etc/profile",
            r"TMOUT\s*=",
            "TMOUT=900",
            "# Added by LinuxComplianceChecker: enforce 15 minute shell timeout",
        )
        notes.append(msg)
        if not ok:
            success = False

        ok, msg = self.update_or_append_line(
            "/etc/ssh/sshd_config",
            r"ClientAliveInterval\s+",
            "ClientAliveInterval 300",
            "# Added by LinuxComplianceChecker: enforce SSH idle timeout",
            case_insensitive=True,
        )
        notes.append(msg)
        if not ok:
            success = False

        ok, msg = self.update_or_append_line(
            "/etc/ssh/sshd_config",
            r"ClientAliveCountMax\s+",
            "ClientAliveCountMax 0",
            case_insensitive=True,
        )
        notes.append(msg)
        if not ok:
            success = False

        if shutil.which("systemctl"):
            self.maybe_restart_service(
                "sshd",
                notes,
                "请在维护窗口内执行: systemctl restart sshd 以使配置生效",
            )
        else:
            notes.append("请重启SSH服务使配置生效")

        return ("APPLIED" if success else "PARTIAL", notes)

    def remediate_ssh_protocol_security(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """强制SSHv2并尝试禁用明文远程服务。"""

        notes: List[str] = []
        success = True

        ok, msg = self.update_or_append_line(
            "/etc/ssh/sshd_config",
            r"Protocol\s+",
            "Protocol 2",
            "# Added by LinuxComplianceChecker: enforce SSH protocol 2",
            case_insensitive=True,
        )
        notes.append(msg)
        if not ok:
            success = False

        systemctl_available = shutil.which("systemctl") is not None
        if not systemctl_available:
            notes.extend(
                [
                    "未检测到systemctl，无法自动禁用Telnet/rlogin等明文远程服务，请按以下步骤处理：",
                    "1. 执行 `ss -tulnp | grep -E ':(23|513|514)'` 或 `netstat -tulnp` 查找仍在运行的服务。",
                    "2. 使用 `service <服务名> stop`、`chkconfig <服务名> off` 等命令停止并禁止开机自启。",
                    "3. 重新编辑 `/etc/inetd.conf`/`/etc/xinetd.d/`（如适用）并注释相关条目，确认 SSH `Protocol 2` 已生效。",
                ]
            )
            success = False
        else:
            for service in INSECURE_REMOTE_SERVICES:
                rc, stdout, stderr = self.run_command(f"systemctl is-active {service}")
                if rc == 0 and stdout.strip() == "active":
                    disable_rc, _, disable_err = self.run_command(
                        f"systemctl disable --now {service}"
                    )
                    if disable_rc == 0:
                        notes.append(f"已禁用服务 {service}")
                    else:
                        success = False
                        error_detail = disable_err or "systemctl执行失败"
                        notes.append(
                            f"禁用服务 {service} 失败: {error_detail}"
                        )
                elif rc == -1 and "not found" in stderr.lower():
                    continue

        if systemctl_available:
            self.maybe_restart_service(
                "sshd",
                notes,
                "如有必要，请执行 systemctl restart sshd 以应用配置",
            )

        return ("APPLIED" if success else "PARTIAL", notes)

    def remediate_disable_unnecessary_services(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """尝试自动停用常见高危服务。"""

        if shutil.which("systemctl") is None:
            return (
                "PENDING",
                [
                    "未检测到systemctl，无法自动禁用服务，请按以下步骤手工处理：",
                    "1. 使用 `service <服务名> stop`、`rc-service <服务名> stop` 等命令停止对应守护进程。",
                    "2. 通过 `chkconfig <服务名> off`、`update-rc.d <服务名> disable` 或 `rc-update del <服务名>` 取消开机自启。",
                    "3. 执行 `ss -tulnp | grep <服务名>` 或 `netstat -tulnp` 验证监听端口已关闭。",
                ],
            )

        notes: List[str] = []
        success = True
        for service in UNNECESSARY_SERVICES:
            rc, stdout, stderr = self.run_command(f"systemctl is-active {service}")
            if rc == 0 and stdout.strip() == "active":
                disable_rc, _, disable_err = self.run_command(
                    f"systemctl disable --now {service}"
                )
                if disable_rc == 0:
                    notes.append(f"已禁用服务 {service}")
                else:
                    success = False
                    error_detail = disable_err or "systemctl执行失败"
                    notes.append(
                        f"禁用服务 {service} 失败: {error_detail}"
                    )
            elif rc == -1 and "not found" in stderr.lower():
                continue

        if not notes:
            notes.append("未检测到正在运行的常见高危服务")

        return ("APPLIED" if success else "PARTIAL", notes)

    def remediate_high_risk_ports(
        self, target: Dict[str, object]
    ) -> Tuple[str, List[str]]:
        """尝试自动关闭检测到的高危监听端口。"""

        ports = sorted(self.extract_ports_from_subitem(target.get("subitem", {})))
        if not ports:
            return (
                "PENDING",
                [
                    "未能解析待关闭的端口，请根据检测详情执行 `ss -tulnp` 手动核查并处置。",
                ],
            )

        if shutil.which("systemctl") is None:
            notes = [
                "当前系统缺少systemctl，无法自动关闭端口，请按以下步骤手动处理：",
            ]
            for port in ports:
                notes.append(
                    f"- 端口{port}: 执行 `ss -tulnp | grep ':{port}'` 查找进程，使用 `service <服务名> stop` 或 `fuser -k {port}/tcp` 停止后，"
                    "配合发行版工具禁用自启。"
                )
            return "PENDING", notes

        notes: List[str] = []
        closed_ports: List[int] = []
        pending_ports: List[int] = []
        listeners = self.collect_listening_processes()

        for port in ports:
            current_processes = listeners.get(port, set())
            candidate_services: Set[str] = set()
            candidate_services.update(PORT_SERVICE_HINTS.get(port, []))
            candidate_services.update(current_processes)
            normalised_candidates: Set[str] = set()
            for name in candidate_services:
                normalised = self.normalise_service_candidate(name)
                if normalised:
                    normalised_candidates.add(normalised)
            candidate_services = normalised_candidates

            port_closed = False
            attempted = False
            for candidate in sorted(candidate_services):
                attempted = True
                rc, stdout, stderr = self.run_command(
                    f"systemctl is-active {candidate}"
                )
                if rc == 0 and stdout.strip() == "active":
                    disable_rc, _, disable_err = self.run_command(
                        f"systemctl disable --now {candidate}"
                    )
                    if disable_rc == 0:
                        notes.append(
                            f"已禁用服务 {candidate} 以关闭端口{port}"
                        )
                        port_closed = True
                        break
                    notes.append(
                        f"禁用服务 {candidate} 失败: {disable_err or 'systemctl执行失败'}"
                    )
                elif rc == 0:
                    continue
                elif rc == 3 and stdout.strip() == "inactive":
                    continue
                elif stderr:
                    notes.append(
                        f"无法检测服务 {candidate} 状态: {stderr}"
                    )

            if port_closed:
                listeners = self.collect_listening_processes()
                if port not in listeners or not listeners.get(port):
                    closed_ports.append(port)
                    continue
                notes.append(
                    f"服务已停用但端口{port}仍在监听，可能存在额外进程。"
                )
                current_processes = listeners.get(port, set())

            if not attempted:
                notes.append(
                    f"未能定位端口{port}对应的systemd服务，请人工确认运行进程。"
                )

            pending_ports.append(port)
            process_hint = (
                f"当前检测到进程: {', '.join(sorted(current_processes))}"
                if current_processes
                else "未能直接识别监听进程"
            )
            notes.append(
                f"端口{port}仍在监听，请执行 `ss -tulnp | grep ':{port}'` 定位进程，必要时使用 `systemctl disable --now <服务>` 或 `fuser -k {port}/tcp` 停止。{process_hint}。"
            )

        if pending_ports and closed_ports:
            status = "PARTIAL"
        elif pending_ports:
            status = "PENDING"
        else:
            status = "APPLIED"

        if closed_ports:
            notes.insert(0, "已成功关闭的端口: " + ", ".join(str(p) for p in closed_ports))
        if pending_ports:
            notes.insert(0, "仍需人工处理的端口: " + ", ".join(str(p) for p in pending_ports))

        return status, notes

    def check_root_privilege(self) -> bool:
        if os.geteuid() != 0:
            print(f"{Colors.RED}错误: 部分检查需要root权限{Colors.END}")
            return False
        return True


    def run_check(self) -> None:
        print(f"{Colors.CYAN}\n=== 开始三级等保合规检查 ==={Colors.END}")
        print(f"系统信息: {self.os_info['distribution']} {self.os_info['machine']}\n")

        self.check_ces1_01_identity_authentication()
        self.check_ces1_02_login_failure_handling()
        self.check_ces1_03_remote_management_security()
        self.check_ces1_04_multi_factor_auth()
        self.check_ces1_05_account_allocation()
        self.check_ces1_06_default_account_management()
        self.check_ces1_07_account_review()
        self.check_ces1_08_privilege_separation()
        self.check_ces1_11_security_labels()
        self.check_ces1_12_audit_enablement()
        self.check_ces1_13_audit_log_content()
        self.check_ces1_14_audit_log_protection()
        self.check_ces1_17_minimal_installation()
        self.check_ces1_18_service_port_control()
        self.check_ces1_19_management_access_control()
        self.check_ces1_23_malware_protection()

        self.generate_report()
        self.run_remediation()

    def check_ces1_01_identity_authentication(self) -> None:
        item = "L3-CES1-01"
        subitems = [
            self.make_subitem("1. 应核查用户在登录时是否采用了身份鉴别措施"),
            self.make_subitem("2. 应核查用户列表确认用户身份标识是否具有唯一性"),
            self.make_subitem("3. 应核查用户配置信息或测试验证是否不存在空口令用户"),
            self.make_subitem("4. 应核查用户鉴别信息是否具有复杂度要求"),
            self.make_subitem("5. 应核查用户鉴别信息是否定期更换"),
        ]

        pam_files = [
            "/etc/pam.d/system-auth",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/login",
            "/etc/pam.d/sshd",
        ]
        auth_modules = {
            "pam_unix.so",
            "pam_sss.so",
            "pam_ldap.so",
            "pam_krb5.so",
            "pam_winbind.so",
        }
        missing_pam_files: List[str] = []
        auth_lines: List[str] = []
        for pam_file in pam_files:
            content = self.read_file(pam_file)
            if content is None:
                missing_pam_files.append(pam_file)
                continue
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if not stripped.lower().startswith('auth'):
                    continue
                if any(module in stripped for module in auth_modules):
                    auth_lines.append(f"{pam_file}: {stripped}")
        if auth_lines:
            subitems[0]["details"].append("已在PAM配置中检测到身份鉴别模块")
            subitems[0]["details"].extend(auth_lines)
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未在PAM配置文件中找到pam_unix/pam_sss等身份鉴别模块")
            subitems[0]["recommendation"].append(
                "请检查/etc/pam.d/目录下的认证配置，确保启用了身份鉴别模块"
            )
        if missing_pam_files:
            subitems[0]["details"].append("以下PAM配置文件未读取到: " + ", ".join(missing_pam_files))

        username_counts: Dict[str, int] = {}
        uid_to_users: Dict[str, List[str]] = {}
        interactive_users: Set[str] = set()
        passwd_data_valid = True
        try:
            with open('/etc/passwd', 'r', encoding='utf-8', errors='ignore') as passwd_file:
                for line in passwd_file:
                    if not line.strip() or ':' not in line:
                        continue
                    fields = line.split(':')
                    if len(fields) < 7:
                        continue
                    username = fields[0]
                    uid = fields[2]
                    shell = fields[6].strip()
                    username_counts[username] = username_counts.get(username, 0) + 1
                    uid_to_users.setdefault(uid, []).append(username)
                    if shell in INTERACTIVE_SHELLS:
                        interactive_users.add(username)
        except Exception as exc:  # pylint: disable=broad-except
            passwd_data_valid = False
            subitems[1]["status"] = "ERROR"
            subitems[1]["details"].append(f"无法读取/etc/passwd: {exc}")

        if passwd_data_valid:
            duplicate_users = [name for name, count in username_counts.items() if count > 1]
            duplicate_uids = {
                uid: users
                for uid, users in uid_to_users.items()
                if len(users) > 1
            }
            if duplicate_users or duplicate_uids:
                subitems[1]["status"] = "FAIL"
                if duplicate_users:
                    subitems[1]["details"].append(
                        "发现重复用户名: " + ", ".join(sorted(duplicate_users))
                    )
                if duplicate_uids:
                    formatted = ", ".join(
                        f"UID {uid}: {', '.join(sorted(users))}" for uid, users in duplicate_uids.items()
                    )
                    subitems[1]["details"].append("发现共享UID: " + formatted)
                subitems[1]["recommendation"].append(
                    "请确保/etc/passwd中的用户名与UID一一对应，避免共享账户"
                )
            else:
                subitems[1]["details"].append("用户名与UID均唯一")

        if not passwd_data_valid:
            subitems[2]["status"] = "ERROR"
            subitems[2]["details"].append("由于无法读取/etc/passwd，未能限定交互式用户范围")
        else:
            empty_password_users: List[str] = []
            try:
                with open('/etc/shadow', 'r', encoding='utf-8', errors='ignore') as shadow_file:
                    for line in shadow_file:
                        if not line.strip() or ':' not in line:
                            continue
                        fields = line.split(':')
                        if len(fields) > 1 and fields[1] == '':
                            username = fields[0]
                            if username in interactive_users:
                                empty_password_users.append(username)
            except PermissionError as exc:
                subitems[2]["status"] = "ERROR"
                subitems[2]["details"].append(f"无法读取/etc/shadow: {exc}")
            except Exception as exc:  # pylint: disable=broad-except
                subitems[2]["status"] = "ERROR"
                subitems[2]["details"].append(f"读取/etc/shadow时出现异常: {exc}")

            if subitems[2]["status"] == "PASS":
                if empty_password_users:
                    subitems[2]["status"] = "FAIL"
                    subitems[2]["details"].append(
                        "检测到空口令账户: " + ", ".join(sorted(empty_password_users))
                    )
                    subitems[2]["recommendation"].append("请为相关用户设置强密码或禁用账户")
                else:
                    subitems[2]["details"].append("未检测到空口令账户")

        pwquality_conf = self.read_file('/etc/security/pwquality.conf')
        pwquality_settings: Dict[str, str] = {}
        if pwquality_conf:
            pwquality_settings = self.parse_key_values(pwquality_conf.splitlines())

        pam_complexity_lines: List[str] = []
        for pam_file in pam_files:
            content = self.read_file(pam_file)
            if not content:
                continue
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if 'pam_pwquality.so' in stripped or 'pam_cracklib.so' in stripped:
                    pam_complexity_lines.append(f"{pam_file}: {stripped}")

        minlen = None
        credit_requirements = 0
        for key, value in pwquality_settings.items():
            if key == 'minlen':
                try:
                    minlen = int(value)
                except ValueError:
                    continue
            if key in {'dcredit', 'ucredit', 'lcredit', 'ocredit'}:
                try:
                    if int(value) <= -1:
                        credit_requirements += 1
                except ValueError:
                    continue

        if minlen is None:
            for line in pam_complexity_lines:
                for key, value in re.findall(r'(\w+)=(-?\d+)', line):
                    if key == 'minlen' and minlen is None:
                        try:
                            minlen = int(value)
                        except ValueError:
                            continue
                    if key in {'dcredit', 'ucredit', 'lcredit', 'ocredit'}:
                        try:
                            if int(value) <= -1:
                                credit_requirements += 1
                        except ValueError:
                            continue

        if minlen is not None and minlen >= 8 and credit_requirements >= 2:
            subitems[3]["details"].append("密码复杂度策略已启用")
            subitems[3]["details"].extend(pam_complexity_lines)
        else:
            subitems[3]["status"] = "FAIL"
            subitems[3]["details"].append("未满足minlen>=8且至少包含两类字符限制的密码复杂度策略")
            if pam_complexity_lines:
                subitems[3]["details"].extend(pam_complexity_lines)
            subitems[3]["recommendation"].append(
                "请在PAM或/etc/security/pwquality.conf中启用pam_pwquality并设置minlen>=8及字符复杂度要求"
            )

        rotation_policy_ok = True
        login_defs = self.read_file('/etc/login.defs')
        if not login_defs:
            rotation_policy_ok = False
            subitems[4]["status"] = "FAIL"
            subitems[4]["details"].append("未找到/etc/login.defs，无法核查密码有效期策略")
            subitems[4]["recommendation"].append("请配置/etc/login.defs以定义密码最小/最大有效期")
        else:
            pass_max = re.search(r'PASS_MAX_DAYS\s+(\d+)', login_defs)
            pass_min = re.search(r'PASS_MIN_DAYS\s+(\d+)', login_defs)
            pass_warn = re.search(r'PASS_WARN_AGE\s+(\d+)', login_defs)
            issues = []
            if not pass_max or int(pass_max.group(1)) > 90:
                issues.append("PASS_MAX_DAYS 应配置为不大于90")
            if not pass_min or int(pass_min.group(1)) < 7:
                issues.append("PASS_MIN_DAYS 应配置为不小于7")
            if not pass_warn or int(pass_warn.group(1)) < 7:
                issues.append("PASS_WARN_AGE 应配置为不小于7")
            if issues:
                rotation_policy_ok = False
                subitems[4]["status"] = "FAIL"
                subitems[4]["details"].extend(issues)
                subitems[4]["recommendation"].append(
                    "请在/etc/login.defs中设置 PASS_MAX_DAYS 90、PASS_MIN_DAYS 7、PASS_WARN_AGE 7"
                )
            else:
                subitems[4]["details"].append("密码有效期策略配置满足90/7/7要求")

        if rotation_policy_ok:
            shadow_content = self.read_file('/etc/shadow')
            if shadow_content:
                now_days = self.days_since_epoch()
                overdue_users: List[str] = []
                missing_limit_users: List[str] = []
                login_users = self.get_login_users()
                for line in shadow_content.splitlines():
                    if not line or ':' not in line:
                        continue
                    fields = line.split(':')
                    username = fields[0]
                    if username not in login_users:
                        continue
                    max_days = fields[4] if len(fields) > 4 else ''
                    last_change = fields[2] if len(fields) > 2 else ''
                    if not max_days or max_days in {'', '-1', '99999'}:
                        missing_limit_users.append(username)
                        continue
                    try:
                        max_days_int = int(max_days)
                    except ValueError:
                        missing_limit_users.append(username)
                        continue
                    if max_days_int > 90:
                        missing_limit_users.append(username)
                        continue
                    try:
                        last_change_int = int(last_change)
                    except ValueError:
                        continue
                    if last_change_int > 0 and max_days_int > 0:
                        if now_days - last_change_int > max_days_int:
                            overdue_users.append(username)
                if missing_limit_users:
                    subitems[4]["status"] = "FAIL"
                    subitems[4]["details"].append(
                        "以下用户未设置合理的密码有效期: "
                        + ", ".join(sorted(set(missing_limit_users)))
                    )
                    subitems[4]["recommendation"].append(
                        "请使用chage命令为上述账户配置密码有效期"
                    )
                if overdue_users:
                    subitems[4]["status"] = "FAIL"
                    subitems[4]["details"].append(
                        "以下用户密码已超过允许的有效期: "
                        + ", ".join(sorted(set(overdue_users)))
                    )
                    subitems[4]["recommendation"].append("请立即通知相关用户修改密码")
            else:
                subitems[4]["status"] = "ERROR"
                subitems[4]["details"].append("无法读取/etc/shadow，无法核查密码有效期执行情况")

        self.finalize_item(item, subitems)
    def check_ces1_02_login_failure_handling(self) -> None:
        item = "L3-CES1-02"
        subitems = [
            self.make_subitem("1. 应核查是否配置并启用了登录失败处理功能"),
            self.make_subitem("2. 应核查是否配置并启用了限制非法登录次数的策略"),
            self.make_subitem("3. 应核查是否配置登录连接超时及自动退出功能"),
        ]

        pam_files = [
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/sshd",
        ]
        faillock_lines: List[str] = []
        faillock_with_policy = False
        for pam_file in pam_files:
            content = self.read_file(pam_file)
            if not content:
                continue
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if "pam_faillock.so" in stripped or "pam_tally2.so" in stripped:
                    faillock_lines.append(f"{pam_file}: {stripped}")
                    if re.search(r"deny=\d+", stripped) and (
                        re.search(r"unlock_time=\d+", stripped) or "even_deny_root" in stripped
                    ):
                        faillock_with_policy = True
        if faillock_lines:
            subitems[0]["details"].append("检测到登录失败处理模块")
            subitems[0]["details"].extend(faillock_lines)
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未在PAM配置中找到pam_faillock或pam_tally2模块")
            subitems[0]["recommendation"].append("请在/etc/pam.d/system-auth等文件中启用登录失败处理功能")

        if faillock_lines and faillock_with_policy:
            subitems[1]["details"].append("pam_faillock/pam_tally2已配置限制参数")
        elif faillock_lines:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("检测到pam_faillock/pam_tally2但缺少deny或unlock_time参数")
            subitems[1]["recommendation"].append("建议设置deny=5 unlock_time=600等参数以限制非法登录")
        else:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("未配置限制非法登录次数的PAM模块")
            subitems[1]["recommendation"].append("请部署pam_faillock或pam_tally2并设置限制策略")

        tmout_value: Optional[int] = None
        tmout_sources: List[str] = []
        profile_files = [
            "/etc/profile",
            "/etc/bash.bashrc",
            "/etc/bashrc",
            "/etc/csh.cshrc",
            "/etc/csh.login",
        ]
        for profile in profile_files:
            content = self.read_file(profile)
            if not content:
                continue
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if stripped.startswith('TMOUT'):
                    parts = stripped.split('=', 1)
                    if len(parts) == 2:
                        try:
                            value = int(parts[1].strip())
                            if value > 0 and (tmout_value is None or value < tmout_value):
                                tmout_value = value
                                tmout_sources = [f"{profile}: {stripped}"]
                            elif tmout_value is not None and value == tmout_value:
                                tmout_sources.append(f"{profile}: {stripped}")
                        except ValueError:
                            continue

        tmout_ok = tmout_value is not None and tmout_value <= 900
        if tmout_value is None:
            subitems[2]["status"] = "FAIL"
            subitems[2]["details"].append("未在全局shell配置中设置TMOUT环境变量")
            subitems[2]["recommendation"].append("请在/etc/profile中添加TMOUT=900以启用会话超时")
        else:
            subitems[2]["details"].append(f"检测到TMOUT={tmout_value}")
            subitems[2]["details"].extend(tmout_sources)
            if tmout_value > 900:
                tmout_ok = False
                subitems[2]["status"] = "FAIL"
                subitems[2]["details"].append("TMOUT值超过15分钟限制")
                subitems[2]["recommendation"].append("建议将TMOUT调整为不大于900秒")

        ssh_ok = False
        ssh_config = self.read_file('/etc/ssh/sshd_config')
        if not ssh_config:
            subitems[2]["status"] = "FAIL"
            subitems[2]["details"].append("未找到/etc/ssh/sshd_config，无法核查SSH超时配置")
            subitems[2]["recommendation"].append("请配置SSH的ClientAliveInterval与ClientAliveCountMax")
        else:
            interval = None
            count = None
            for line in ssh_config.splitlines():
                cleaned = line.split('#', 1)[0].strip()
                if not cleaned:
                    continue
                if cleaned.lower().startswith('clientaliveinterval'):
                    try:
                        interval = int(cleaned.split()[1])
                    except (IndexError, ValueError):
                        continue
                if cleaned.lower().startswith('clientalivecountmax'):
                    try:
                        count = int(cleaned.split()[1])
                    except (IndexError, ValueError):
                        continue
            if interval is not None:
                effective_count = count if count is not None else 3
                total = interval * effective_count
                subitems[2]["details"].append(
                    f"SSH保持设置: ClientAliveInterval={interval}, ClientAliveCountMax={effective_count}"
                )
                if total <= 900:
                    ssh_ok = True
                else:
                    subitems[2]["status"] = "FAIL"
                    subitems[2]["details"].append("SSH会话保持时间超过15分钟")
                    subitems[2]["recommendation"].append(
                        "请将ClientAliveInterval与ClientAliveCountMax组合控制在15分钟以内"
                    )
            else:
                subitems[2]["status"] = "FAIL"
                subitems[2]["details"].append("sshd_config缺少ClientAliveInterval配置")
                subitems[2]["recommendation"].append(
                    "请在/etc/ssh/sshd_config中设置ClientAliveInterval和ClientAliveCountMax"
                )

        if subitems[2]["status"] == "PASS" and (not tmout_ok or not ssh_ok):
            subitems[2]["status"] = "FAIL"
            if not tmout_ok:
                subitems[2]["recommendation"].append("请确保交互式shell的TMOUT值不大于900秒")
            if not ssh_ok:
                subitems[2]["recommendation"].append("请限制SSH会话保持时间，防止长期空闲连接")

        self.finalize_item(item, subitems)
    def check_ces1_03_remote_management_security(self) -> None:
        item = "L3-CES1-03"
        subitems = [
            self.make_subitem("应核查是否采用加密等安全方式进行远程管理，防止鉴别信息被窃听"),
        ]

        ssh_config = self.read_file('/etc/ssh/sshd_config')
        protocol_secure = False
        if not ssh_config:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未找到SSH配置文件/etc/ssh/sshd_config")
            subitems[0]["recommendation"].append("请安装并配置SSH服务，确保使用加密协议")
        else:
            protocol_lines = []
            for line in ssh_config.splitlines():
                cleaned = line.split('#', 1)[0].strip()
                if not cleaned:
                    continue
                if cleaned.lower().startswith('protocol'):
                    protocol_lines.append(cleaned)
                    tokens = cleaned.split()
                    if '2' in tokens and '1' not in tokens:
                        protocol_secure = True
                    if '1' in tokens:
                        subitems[0]["status"] = "FAIL"
                        subitems[0]["details"].append("检测到SSH配置允许协议版本1")
                        subitems[0]["recommendation"].append("请在/etc/ssh/sshd_config中仅保留Protocol 2")
            if not protocol_lines:
                subitems[0]["status"] = "FAIL"
                subitems[0]["details"].append("SSH配置未显式指定Protocol参数")
                subitems[0]["recommendation"].append("请在sshd_config中设置Protocol 2")
            elif subitems[0]["status"] == "PASS" and protocol_secure:
                subitems[0]["details"].append("SSH已配置仅使用Protocol 2")
            elif subitems[0]["status"] == "PASS":
                subitems[0]["status"] = "FAIL"
                subitems[0]["details"].append("SSH配置未明确限制为Protocol 2")
                subitems[0]["recommendation"].append("请在sshd_config中声明Protocol 2以禁用SSHv1")

        running_insecure: List[str] = []
        for service in INSECURE_REMOTE_SERVICES:
            rc, stdout, _ = self.run_command(f"systemctl is-active {service}")
            if rc == 0 and stdout.strip() == 'active':
                running_insecure.append(service)
        if running_insecure:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("检测到明文远程管理服务运行: " + ", ".join(running_insecure))
            subitems[0]["recommendation"].append("请禁用telnet/rsh等明文协议，仅保留SSH等加密方式")
        elif subitems[0]["status"] == "PASS":
            subitems[0]["details"].append("未检测到telnet/rlogin等不安全远程服务运行")

        self.finalize_item(item, subitems)
    def check_ces1_04_multi_factor_auth(self) -> None:
        item = "L3-CES1-04"
        subitems = [
            self.make_subitem("1. 应核查是否采用两种或两种以上组合的鉴别技术"),
            self.make_subitem("2. 应核查其中一种鉴别技术是否使用密码技术实现"),
        ]

        password_modules = {
            "pam_unix.so",
            "pam_sss.so",
            "pam_ldap.so",
            "pam_krb5.so",
            "pam_winbind.so",
        }
        second_factor_modules = {
            "pam_google_authenticator.so",
            "pam_oath.so",
            "pam_radius_auth.so",
            "pam_tacplus.so",
            "pam_pkcs11.so",
            "pam_yubico.so",
            "pam_fprintd.so",
            "pam_opie.so",
            "pam_duo.so",
        }

        pam_files = [
            "/etc/pam.d/sshd",
            "/etc/pam.d/login",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/common-auth",
        ]

        has_password_module = False
        has_second_factor = False
        second_factor_evidence: List[str] = []

        for pam_file in pam_files:
            content = self.read_file(pam_file)
            if not content:
                continue
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or not stripped.lower().startswith('auth'):
                    continue
                if any(module in stripped for module in password_modules):
                    has_password_module = True
                if any(module in stripped for module in second_factor_modules):
                    has_second_factor = True
                    second_factor_evidence.append(f"{pam_file}: {stripped}")

        if has_second_factor:
            subitems[0]["details"].append("检测到多因素鉴别模块配置")
            subitems[0]["details"].extend(second_factor_evidence)
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未检测到动态口令、证书或其他第二因子模块配置")
            subitems[0]["recommendation"].append(
                "请在PAM配置中集成动态口令/证书/指纹等第二因子，实现双重鉴别"
            )

        if has_password_module:
            subitems[1]["details"].append("已检测到pam_unix/pam_sss等密码认证模块")
        else:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("未检测到密码技术相关的PAM模块")
            subitems[1]["recommendation"].append("请确保至少保留pam_unix或其他密码技术作为第一鉴别因子")

        self.finalize_item(item, subitems)
    def check_ces1_05_account_allocation(self) -> None:
        item = "L3-CES1-05"
        subitems = [
            self.make_subitem("1. 应核查是否为用户分配了账户和权限及相关设置情况"),
            self.make_subitem("2. 应核查是否已禁用或限制匿名、默认账户的访问权限"),
        ]

        login_users = self.get_login_users()
        if login_users:
            subitems[0]["details"].append(f"已发现{len(login_users)}个具备交互登录权限的账户")
        else:
            subitems[0]["details"].append("未发现具备交互登录权限的账户")

        groups = {g.gr_gid: g.gr_name for g in grp.getgrall()}
        missing_groups: List[str] = []
        for user, entry in login_users.items():
            if entry.pw_gid not in groups:
                missing_groups.append(user)
        if missing_groups:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("以下账户的主组不存在: " + ", ".join(sorted(missing_groups)))
            subitems[0]["recommendation"].append("请为相关账户重新分配有效的用户组")
        else:
            subitems[0]["details"].append("所有交互式账户均映射到有效的主组")

        suspicious_accounts: List[str] = []
        for entry in pwd.getpwall():
            if entry.pw_uid < 1000 and entry.pw_name != 'root':
                if entry.pw_shell in INTERACTIVE_SHELLS:
                    suspicious_accounts.append(f"{entry.pw_name}({entry.pw_shell})")
        if suspicious_accounts:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("系统默认账户未禁用交互登录: " + ", ".join(suspicious_accounts))
            subitems[1]["recommendation"].append(
                "请将系统服务账户的shell设置为/sbin/nologin或/bin/false，限制匿名访问"
            )
        else:
            subitems[1]["details"].append("系统默认账户均已限制交互登录")

        self.finalize_item(item, subitems)
    def check_ces1_06_default_account_management(self) -> None:
        item = "L3-CES1-06"
        subitems = [
            self.make_subitem("1. 应核查是否已经重命名默认账户或删除默认账户"),
            self.make_subitem("2. 应核查是否已修改默认账户的默认口令"),
        ]

        uid_zero_accounts = [entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == 0]
        if len(uid_zero_accounts) > 1:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("检测到多个UID为0的账户: " + ", ".join(sorted(uid_zero_accounts)))
            subitems[0]["recommendation"].append("请确认仅保留root账户或重命名/删除多余的UID0账户")
        else:
            subitems[0]["details"].append("仅存在一个UID为0的账户")

        default_candidates = [
            'admin',
            'user',
            'test',
            'guest',
            'oracle',
            'mysql',
            'ubuntu',
            'pi',
        ]
        insecure_defaults: List[str] = []
        locked_defaults: List[str] = []
        unknown_defaults: List[str] = []

        for candidate in default_candidates:
            try:
                entry = pwd.getpwnam(candidate)
            except KeyError:
                continue
            shell = entry.pw_shell
            try:
                shadow = spwd.getspnam(candidate)
                password_field = shadow.sp_pwd
            except PermissionError as exc:
                unknown_defaults.append(f"{candidate}(无法读取shadow: {exc})")
                continue
            except KeyError:
                unknown_defaults.append(f"{candidate}(shadow记录缺失)")
                continue

            locked = password_field in ('', '!', '*', '!!')
            if shell in NOLOGIN_SHELLS or locked:
                locked_defaults.append(candidate)
            else:
                insecure_defaults.append(candidate)

        if insecure_defaults:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("以下默认账户仍启用且口令未锁定: " + ", ".join(sorted(insecure_defaults)))
            subitems[1]["recommendation"].append("请删除、重命名或锁定上述默认账户，并修改初始口令")
        if locked_defaults:
            subitems[1]["details"].append("已锁定或禁用的默认账户: " + ", ".join(sorted(locked_defaults)))
        if unknown_defaults:
            subitems[1]["status"] = "ERROR"
            subitems[1]["details"].extend(unknown_defaults)
            subitems[1]["recommendation"].append("请人工核查默认账户口令状态")
        if not insecure_defaults and not locked_defaults and not unknown_defaults:
            subitems[1]["details"].append("未发现启用状态的常见默认账户")

        self.finalize_item(item, subitems)
    def check_ces1_07_account_review(self) -> None:
        item = "L3-CES1-07"
        subitems = [
            self.make_subitem("1. 应核查是否不存在多余或过期账户，管理员账户是否一人一号"),
            self.make_subitem("2. 应测试验证多余的、过期的账户是否被删除或停用"),
        ]

        login_users = self.get_login_users()
        uid_map: Dict[int, List[str]] = {}
        for entry in login_users.values():
            uid_map.setdefault(entry.pw_uid, []).append(entry.pw_name)
        shared_accounts = {uid: names for uid, names in uid_map.items() if len(names) > 1}
        if shared_accounts:
            details = ", ".join(f"UID {uid}: {', '.join(sorted(names))}" for uid, names in shared_accounts.items())
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("检测到共享账户: " + details)
            subitems[0]["recommendation"].append("请确保管理员账户实行一人一号，避免共享UID")
        else:
            subitems[0]["details"].append("未检测到共享UID的账户")

        shadow_content = self.read_file('/etc/shadow')
        if shadow_content:
            now_days = self.days_since_epoch()
            expired_accounts: List[str] = []
            stale_accounts: List[str] = []
            locked_accounts: List[str] = []
            for line in shadow_content.splitlines():
                if not line or ':' not in line:
                    continue
                fields = line.split(':')
                username = fields[0]
                if username not in login_users:
                    continue
                expire_field = fields[7] if len(fields) > 7 else ''
                last_change = fields[2] if len(fields) > 2 else ''
                password_hash = fields[1] if len(fields) > 1 else ''
                try:
                    if expire_field:
                        expire_value = int(expire_field)
                        if 0 < expire_value < now_days:
                            expired_accounts.append(username)
                except ValueError:
                    expired_accounts.append(username)
                try:
                    if last_change:
                        last_change_value = int(last_change)
                        if 0 < last_change_value and now_days - last_change_value > 365:
                            stale_accounts.append(username)
                except ValueError:
                    continue
                if password_hash in ('!', '*', '!!'):
                    locked_accounts.append(username)
            if expired_accounts:
                subitems[0]["status"] = "FAIL"
                subitems[0]["details"].append("以下账户已过期: " + ", ".join(sorted(set(expired_accounts))))
                subitems[0]["recommendation"].append("请清理或禁用上述过期账户")
            if stale_accounts:
                subitems[1]["status"] = "FAIL"
                subitems[1]["details"].append(
                    "以下账户超过一年未更改口令，需确认是否仍在使用: " + ", ".join(sorted(set(stale_accounts)))
                )
                subitems[1]["recommendation"].append("请核实并停用长期未使用的账户")
            if locked_accounts:
                subitems[1]["details"].append("已锁定的账户: " + ", ".join(sorted(set(locked_accounts))))
            if not expired_accounts and not stale_accounts:
                subitems[1]["details"].append("未发现过期或长期未使用的账户")
        else:
            subitems[0]["status"] = "ERROR"
            subitems[0]["details"].append("无法读取/etc/shadow，无法评估账户有效期")
            subitems[1]["status"] = "ERROR"
            subitems[1]["details"].append("无法读取/etc/shadow，无法验证过期账户是否停用")

        self.finalize_item(item, subitems)
    def check_ces1_08_privilege_separation(self) -> None:
        item = "L3-CES1-08"
        subitems = [
            self.make_subitem("1. 应核查是否进行角色划分"),
            self.make_subitem("2. 应核查管理用户的权限是否已进行分离"),
            self.make_subitem("3. 应核查管理用户权限是否为其工作任务所需的最小权限"),
        ]

        sudoers_files = ["/etc/sudoers"]
        sudoers_dir = "/etc/sudoers.d"
        if os.path.isdir(sudoers_dir):
            for entry in os.listdir(sudoers_dir):
                if entry.endswith("~") or entry.startswith('.'):
                    continue
                sudoers_files.append(os.path.join(sudoers_dir, entry))

        role_evidence: List[str] = []
        broad_rules: List[str] = []
        for path in sudoers_files:
            content = self.read_file(path)
            if not content:
                continue
            for line in content.splitlines():
                cleaned = line.split('#', 1)[0].strip()
                if not cleaned:
                    continue
                if cleaned.startswith(('User_Alias', 'Runas_Alias', 'Cmnd_Alias', 'Host_Alias')):
                    role_evidence.append(f"{path}: {cleaned}")
                elif cleaned.startswith('%'):
                    role_evidence.append(f"{path}: {cleaned}")
                if "NOPASSWD: ALL" in cleaned:
                    broad_rules.append(f"{path}: {cleaned}")
                elif re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL", cleaned):
                    identity = cleaned.split()[0]
                    if identity in {"ALL", "%wheel"}:
                        broad_rules.append(f"{path}: {cleaned}")

        if role_evidence:
            subitems[0]["details"].append("检测到sudo角色/组划分配置")
            subitems[0]["details"].extend(role_evidence[:5])
            if len(role_evidence) > 5:
                subitems[0]["details"].append(f"...共发现{len(role_evidence)}条角色配置")
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未在sudoers中发现角色别名或组级授权配置")
            subitems[0]["recommendation"].append("请使用User_Alias/Cmnd_Alias等机制对管理角色进行划分")

        if broad_rules:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("检测到授予过度权限的sudo规则:")
            subitems[1]["details"].extend(broad_rules)
            subitems[1]["recommendation"].append(
                "请避免使用NOPASSWD: ALL或ALL=(ALL) ALL的全权授权，按角色拆分最小权限"
            )
        else:
            subitems[1]["details"].append("未发现全权或免密sudo授权规则")

        try:
            sudoers_stat = os.stat('/etc/sudoers')
            permissions = oct(sudoers_stat.st_mode)[-3:]
            if permissions != '440':
                subitems[2]["status"] = "FAIL"
                subitems[2]["details"].append(f"/etc/sudoers权限为{permissions}")
                subitems[2]["recommendation"].append("请将/etc/sudoers权限设置为440以防止未授权修改")
            else:
                subitems[2]["details"].append("/etc/sudoers权限符合440要求")
        except FileNotFoundError:
            subitems[2]["status"] = "FAIL"
            subitems[2]["details"].append("未找到/etc/sudoers文件")
            subitems[2]["recommendation"].append("请确认sudo已安装并配置最小权限策略")

        self.finalize_item(item, subitems)
    def check_ces1_11_security_labels(self) -> None:
        item = "L3-CES1-11"
        subitems = [
            self.make_subitem("1. 应核查是否对主体、客体设置了安全标记"),
            self.make_subitem("2. 应测试验证是否依据安全标记实施强制访问控制策略"),
        ]

        selinux_enabled = False
        selinux_enforcing = False
        rc, stdout, stderr = self.run_command('sestatus')
        if rc == 0:
            if 'SELinux status: enabled' in stdout:
                selinux_enabled = True
                subitems[0]["details"].append("检测到SELinux已启用")
                mode_match = re.search(r"Current mode:\s+(\w+)", stdout)
                if mode_match and mode_match.group(1).lower() == 'enforcing':
                    selinux_enforcing = True
                    subitems[1]["details"].append("SELinux处于Enforcing模式")
                else:
                    subitems[1]["status"] = "FAIL"
                    subitems[1]["details"].append("SELinux未处于Enforcing模式")
                    subitems[1]["recommendation"].append("请启用SELinux enforcing模式以落实强制访问控制")
            else:
                subitems[0]["status"] = "FAIL"
                subitems[0]["details"].append("SELinux未启用")
                subitems[0]["recommendation"].append("请启用SELinux并配置安全标记")
        else:
            if rc == -1 and stderr and 'not found' in stderr.lower():
                subitems[0]["details"].append("未检测到sestatus命令，可能未安装SELinux组件")
            else:
                subitems[0]["details"].append("sestatus命令执行失败，无法确认SELinux状态")

        apparmor_available = False
        apparmor_enforcing = False
        rc, stdout, stderr = self.run_command('aa-status')
        if rc == 0:
            apparmor_available = True
            subitems[0]["details"].append("检测到AppArmor配置")
            if 'profiles are in enforce mode' in stdout:
                apparmor_enforcing = True
                subitems[1]["details"].append("AppArmor处于enforce模式")
            else:
                subitems[0]["status"] = "FAIL"
                subitems[0]["details"].append("AppArmor未处于强制模式")
                subitems[0]["recommendation"].append("请将AppArmor配置为enforce模式以提供安全标记")
        else:
            if rc == -1 and stderr and 'not found' in stderr.lower():
                subitems[0]["details"].append("未检测到aa-status命令，系统可能未启用AppArmor")
            else:
                subitems[0]["details"].append("aa-status命令执行失败，无法确认AppArmor状态")

        if not selinux_enabled and not apparmor_available:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未检测到SELinux或AppArmor安全标记机制")
            subitems[0]["recommendation"].append("请启用SELinux或AppArmor以实现安全标记控制")

        if not selinux_enforcing and not apparmor_enforcing:
            subitems[1]["status"] = "FAIL"
            if not subitems[1]["details"]:
                subitems[1]["details"].append("未发现强制访问控制策略处于执行状态")
            subitems[1]["recommendation"].append("请启用SELinux或AppArmor的强制模式以落实安全标记访问控制")

        self.finalize_item(item, subitems)
    def check_ces1_12_audit_enablement(self) -> None:
        item = "L3-CES1-12"
        subitems = [
            self.make_subitem("1. 应核查是否开启了安全审计功能"),
            self.make_subitem("2. 应核查安全审计范围是否覆盖到每个用户"),
            self.make_subitem("3. 应核查是否对重要的用户行为和重要安全事件进行审计"),
        ]

        rc, stdout, _ = self.run_command('systemctl is-active auditd')
        auditd_active = rc == 0 and stdout.strip() == 'active'
        rc, stdout, _ = self.run_command('systemctl is-active rsyslog')
        rsyslog_active = rc == 0 and stdout.strip() == 'active'
        if auditd_active:
            subitems[0]["details"].append("auditd服务正在运行")
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("auditd服务未运行")
            subitems[0]["recommendation"].append("请安装并启用auditd服务: systemctl enable --now auditd")
        if rsyslog_active:
            subitems[0]["details"].append("rsyslog服务正在运行")
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("rsyslog服务未运行")
            subitems[0]["recommendation"].append("请启用系统日志服务(rsyslog或syslog-ng)")

        rc, stdout, _ = self.run_command('auditctl -l')
        if rc == 0 and stdout:
            rules = stdout.splitlines()
            subitems[1]["details"].append("检测到已加载的审计规则")
            subitems[1]["details"].append(rules[0])
            if len(rules) > 1:
                subitems[1]["details"].append(f"...共{len(rules)}条规则")
        else:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("未发现已加载的审计规则")
            subitems[1]["recommendation"].append("请配置/etc/audit/rules.d/*.rules确保覆盖所有用户活动")

        audit_log_paths = [
            '/var/log/audit/audit.log',
            '/var/log/secure',
            '/var/log/auth.log',
        ]
        log_evidence = False
        for log_path in audit_log_paths:
            if not os.path.exists(log_path):
                continue
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as log_file:
                    for _ in range(200):
                        line = log_file.readline()
                        if not line:
                            break
                        if 'type=' in line and 'uid=' in line:
                            log_evidence = True
                            subitems[2]["details"].append(f"日志{log_path}记录包含用户及事件字段: {line.strip()[:120]}")
                            break
            except OSError as exc:
                subitems[2]["details"].append(f"无法读取{log_path}: {exc}")
        if not log_evidence:
            subitems[2]["status"] = "FAIL"
            subitems[2]["details"].append("未在审计日志中发现包含关键字段的记录")
            subitems[2]["recommendation"].append("请确认auditd规则覆盖重要事件并检查日志采集")

        self.finalize_item(item, subitems)
    def check_ces1_13_audit_log_content(self) -> None:
        item = "L3-CES1-13"
        subitems = [
            self.make_subitem("应核查审计记录信息是否包括时间、用户、事件类型、成功状态等字段"),
        ]

        audit_log_paths = [
            '/var/log/audit/audit.log',
            '/var/log/secure',
            '/var/log/auth.log',
        ]
        log_checked = False
        for log_path in audit_log_paths:
            if not os.path.exists(log_path):
                continue
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as log_file:
                    lines = log_file.readlines()
            except OSError as exc:
                subitems[0]["details"].append(f"无法读取{log_path}: {exc}")
                continue
            for line in lines[-200:]:
                if re.search(r"type=.*audit\(\d+\.\d+:\d+\).*uid=\d+", line):
                    log_checked = True
                    subitems[0]["details"].append(f"日志{log_path}包含审计字段: {line.strip()[:120]}")
                    break
            if log_checked:
                break
        if not log_checked:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未在审计日志中找到包含时间/用户/事件等字段的记录")
            subitems[0]["recommendation"].append("请检查auditd配置，确保日志记录字段完整")

        audit_conf = self.read_file('/etc/audit/auditd.conf')
        if audit_conf:
            subitems[0]["details"].append("已读取/etc/audit/auditd.conf配置")
        else:
            subitems[0]["details"].append("未找到/etc/audit/auditd.conf配置文件")

        self.finalize_item(item, subitems)
    def check_ces1_14_audit_log_protection(self) -> None:
        item = "L3-CES1-14"
        subitems = [
            self.make_subitem("1. 应核查是否采取了保护措施对审计记录进行保护"),
            self.make_subitem("2. 应核查是否采取技术措施对审计记录进行定期备份")
        ]

        log_files = [
            '/var/log/audit/audit.log',
            '/var/log/secure',
            '/var/log/auth.log',
            '/var/log/messages',
            '/var/log/syslog',
        ]
        permission_issues: List[str] = []
        for log in log_files:
            if not os.path.exists(log):
                continue
            try:
                mode = oct(os.stat(log).st_mode)[-3:]
                if int(mode, 8) & 0o007:
                    permission_issues.append(f"{log} 权限为{mode}")
            except OSError as exc:
                permission_issues.append(f"无法获取{log}权限: {exc}")
        if permission_issues:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("以下日志权限过于宽松:")
            subitems[0]["details"].extend(permission_issues)
            subitems[0]["recommendation"].append("请将重要日志权限设置为640或更严格，并限制其他用户访问")
        else:
            subitems[0]["details"].append("审计日志权限设置符合要求")

        logrotate_conf = self.read_file('/etc/logrotate.conf')
        if logrotate_conf and re.search(r"rotate\s+\d+", logrotate_conf):
            subitems[1]["details"].append("已检测到日志轮转配置")
            if 'compress' not in logrotate_conf:
                subitems[1]["status"] = "FAIL"
                subitems[1]["details"].append("日志轮转未启用压缩")
                subitems[1]["recommendation"].append("建议启用日志压缩并结合离线备份")
        else:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("未找到日志轮转配置")
            subitems[1]["recommendation"].append("请配置/etc/logrotate.conf或/etc/logrotate.d/确保日志定期归档")

        self.finalize_item(item, subitems)
    def check_ces1_17_minimal_installation(self) -> None:
        item = "L3-CES1-17"
        subitems = [
            self.make_subitem("1. 应核查是否遵循最小安装原则"),
            self.make_subitem("2. 应核查是否未安装非必要的组件和应用程序"),
        ]

        unwanted_packages = [
            'telnet',
            'telnetd',
            'rsh',
            'rsh-server',
            'ypbind',
            'ypserv',
            'xinetd',
            'tftp',
            'vsftpd',
            'samba',
            'cifs-utils',
            'xorg-x11-server-Xorg',
        ]

        package_manager_detected = False
        detected_packages: List[str] = []
        for package in unwanted_packages:
            installed = self.is_package_installed(package)
            if installed is not None:
                package_manager_detected = True
            if installed:
                detected_packages.append(package)
        if package_manager_detected:
            subitems[0]["details"].append("已通过包管理器核查最小化安装状态")
        else:
            subitems[0]["status"] = "ERROR"
            subitems[0]["details"].append("无法确定包管理器状态，请人工确认最小安装原则执行情况")

        if detected_packages:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("检测到可能非必要的组件: " + ", ".join(sorted(detected_packages)))
            subitems[1]["recommendation"].append("请根据系统角色评估并卸载非必要组件")
        elif package_manager_detected:
            subitems[1]["details"].append("未检测到常见的非必要组件，符合最小化安装原则")
        else:
            subitems[1]["details"].append("未能识别包管理器，需人工核查已安装组件")

        self.finalize_item(item, subitems)
    def check_ces1_18_service_port_control(self) -> None:
        item = "L3-CES1-18"
        subitems = [
            self.make_subitem("1. 应核查是否关闭了非必要的系统服务和默认共享"),
            self.make_subitem("2. 应核查是否不存在非必要的高危端口"),
        ]

        running_services: List[str] = []
        rc, stdout, _ = self.run_command(
            'systemctl list-units --type=service --state=running --no-legend'
        )
        if rc == 0:
            for line in stdout.splitlines():
                service_name = line.split()[0]
                if service_name.endswith('.service'):
                    base = service_name[:-8]
                    if base in UNNECESSARY_SERVICES:
                        running_services.append(base)
        if running_services:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("发现运行中的不必要服务: " + ", ".join(sorted(set(running_services))))
            subitems[0]["recommendation"].append("请使用systemctl disable --now <service>停用相关服务")
        else:
            subitems[0]["details"].append("未检测到运行中的高危服务")

        listening_ports: List[str] = []
        rc, stdout, _ = self.run_command('ss -tuln')
        if rc != 0 or not stdout:
            rc, stdout, _ = self.run_command('netstat -tuln')
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                local = parts[4]
                if ':' not in local:
                    continue
                try:
                    port = int(local.rsplit(':', 1)[1])
                except ValueError:
                    continue
                if port in HIGH_RISK_PORTS:
                    listening_ports.append(f"端口{port}({HIGH_RISK_PORTS[port]})")
        if listening_ports:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("检测到高危监听端口: " + ", ".join(sorted(set(listening_ports))))
            subitems[1]["recommendation"].append("请关闭检测到的高危端口")
        else:
            subitems[1]["details"].append("未发现高危监听端口")

        self.finalize_item(item, subitems)
    def check_ces1_19_management_access_control(self) -> None:
        item = "L3-CES1-19"
        subitems = [
            self.make_subitem("应核查配置是否限制管理终端接入方式或来源地址"),
        ]

        ssh_config = self.read_file('/etc/ssh/sshd_config')
        restrictions_found = []
        if ssh_config:
            for line in ssh_config.splitlines():
                cleaned = line.split('#', 1)[0].strip()
                if not cleaned:
                    continue
                lower = cleaned.lower()
                if lower.startswith('allowusers') or lower.startswith('allowgroups'):
                    restrictions_found.append(cleaned)
                if lower.startswith('denyusers') or lower.startswith('denygroups'):
                    restrictions_found.append(cleaned)
                if lower.startswith('match') and 'address' in lower:
                    restrictions_found.append(cleaned)
                if lower.startswith('listenaddress') and '0.0.0.0' not in lower and '::' not in lower:
                    restrictions_found.append(cleaned)
        if restrictions_found:
            subitems[0]["details"].append("SSH配置已对管理源进行限制")
            subitems[0]["details"].extend(restrictions_found)
        else:
            subitems[0]["details"].append("未在SSH配置中发现管理源限制")

        firewall_evidence: List[str] = []
        rc, stdout, _ = self.run_command('firewall-cmd --list-sources')
        if rc == 0 and stdout:
            firewall_evidence.append("firewalld允许的源: " + stdout)
        else:
            rc, stdout, _ = self.run_command('iptables -S INPUT')
            if rc == 0 and stdout:
                restricted_rules = [line for line in stdout.splitlines() if '-s' in line]
                if restricted_rules:
                    firewall_evidence.append("iptables源地址限制规则:")
                    firewall_evidence.extend(restricted_rules[:5])
        if firewall_evidence:
            subitems[0]["details"].extend(firewall_evidence)
        if not restrictions_found and not firewall_evidence:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未检测到SSH或防火墙对管理终端来源的限制")
            subitems[0]["recommendation"].append("请使用AllowUsers/防火墙策略限制可访问的管理终端")

        self.finalize_item(item, subitems)
    def check_ces1_23_malware_protection(self) -> None:
        item = "L3-CES1-23"
        subitems = [
            self.make_subitem("1. 应核查是否安装并定期更新防恶意代码软件"),
            self.make_subitem("2. 应核查是否采用主动免疫可信验证技术及时识别入侵"),
            self.make_subitem("3. 应核查识别恶意行为时是否能够有效阻断"),
        ]

        antivirus_tools = {
            'clamscan': 'ClamAV病毒扫描器',
            'freshclam': 'ClamAV病毒库更新',
            'maldet': 'Maldet恶意代码检测',
            'chkrootkit': 'Chkrootkit根kit检测',
            'rkhunter': 'Rootkit Hunter检测',
        }
        available_tools = [desc for cmd, desc in antivirus_tools.items() if shutil.which(cmd)]
        if available_tools:
            subitems[0]["details"].append("检测到防恶意代码工具: " + ", ".join(available_tools))
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未检测到常见的恶意代码防护工具")
            subitems[0]["recommendation"].append("请部署ClamAV、商业杀毒或可信验证机制，并定期更新病毒库")

        integrity_tools = {
            'aide': 'AIDE完整性检查',
            'tripwire': 'Tripwire完整性监控',
            'samhain': 'Samhain完整性监控',
        }
        active_immunity = [desc for cmd, desc in integrity_tools.items() if shutil.which(cmd)]
        if active_immunity:
            subitems[1]["details"].append("检测到主动免疫/可信验证工具: " + ", ".join(active_immunity))
        else:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("未检测到AIDE/Tripwire等可信验证技术")
            subitems[1]["recommendation"].append("建议部署AIDE、Tripwire等完整性监控以提升主动免疫能力")

        service_names = [
            'clamd',
            'clamav-daemon',
            'freshclam',
            'maldet',
            'rkhunter',
            'chkrootkit',
        ]
        active_services: List[str] = []
        for service in service_names:
            rc, stdout, _ = self.run_command(f'systemctl is-active {service}')
            if rc == 0 and stdout.strip() == 'active':
                active_services.append(service)
        if active_services:
            subitems[2]["details"].append("恶意代码防护服务正在运行: " + ", ".join(active_services))
        else:
            subitems[2]["status"] = "FAIL"
            subitems[2]["details"].append("未检测到活跃的恶意代码防护服务")
            subitems[2]["recommendation"].append("请启动病毒查杀服务或配置实时监控以便及时阻断恶意行为")

        self.finalize_item(item, subitems)
    def generate_report(self) -> None:
        print(f"\n{Colors.CYAN}=== 三级等保合规检查报告 ==={Colors.END}")
        print(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"系统信息: {self.os_info['distribution']} {self.os_info['machine']}\n")

        pass_count = fail_count = error_count = 0
        for category, data in CHECK_ITEMS.items():
            print(f"\n{Colors.BLUE}【{data['title']}】{Colors.END}")
            for item_id, metadata in data['items'].items():
                result = self.results.get(item_id, {"status": "UNKNOWN", "details": [], "recommendation": "", "subitems": []})
                status = result['status']
                if status == 'PASS':
                    colour = Colors.GREEN
                    pass_count += 1
                elif status == 'FAIL':
                    colour = Colors.RED
                    fail_count += 1
                else:
                    colour = Colors.YELLOW
                    error_count += 1
                print(f"\n{colour}[{status}]{Colors.END} {item_id}")
                indicator = metadata.get('indicator')
                if indicator:
                    print(f"   - 测评指标: {indicator}")
                implementation = metadata.get('implementation', [])
                if implementation:
                    print("   - 测评实施包括以下内容:")
                    for step in implementation:
                        print(f"     * {step}")

                subitems = result.get('subitems', [])
                if subitems:
                    print("   - 子项检查结果:")
                    for sub in subitems:
                        sub_status = sub.get('status', 'PASS')
                        if sub_status == 'PASS':
                            sub_colour = Colors.GREEN
                        elif sub_status == 'FAIL':
                            sub_colour = Colors.RED
                        else:
                            sub_colour = Colors.YELLOW
                        print(f"     {sub_colour}[{sub_status}]{Colors.END} {sub['description']}")
                        for detail in sub.get('details', []):
                            print(f"       - {detail}")
                        recommendations = sub.get('recommendation', [])
                        if recommendations and sub_status != 'PASS':
                            for rec in recommendations:
                                print(f"       {Colors.YELLOW}整改建议:{Colors.END} {rec}")
                else:
                    details = result.get('details', [])
                    if details:
                        print("   - 检查详情:")
                        for detail in details:
                            print(f"     * {detail}")
                    recommendation = result.get('recommendation')
                    if recommendation and status != 'PASS':
                        print(f"   - {Colors.YELLOW}整改建议:{Colors.END} {recommendation}")

        total = pass_count + fail_count + error_count
        print(f"\n{Colors.CYAN}=== 检查结果汇总 ==={Colors.END}")
        print(f"{Colors.GREEN}符合项: {pass_count}/{total}{Colors.END}")
        print(f"{Colors.RED}不符合项: {fail_count}/{total}{Colors.END}")
        print(f"{Colors.YELLOW}检查错误: {error_count}/{total}{Colors.END}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"compliance_report_{timestamp}.txt"
        with open(report_file, "w", encoding="utf-8") as report:
            report.write("=== 三级等保合规检查报告 ===\n")
            report.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report.write(f"系统信息: {self.os_info['distribution']} {self.os_info['machine']}\n\n")
            for category, data in CHECK_ITEMS.items():
                report.write(f"\n【{data['title']}】\n")
                for item_id, metadata in data['items'].items():
                    result = self.results.get(item_id, {"status": "UNKNOWN", "details": [], "recommendation": "", "subitems": []})
                    report.write(f"\n[{result['status']}] {item_id}\n")
                    indicator = metadata.get('indicator')
                    if indicator:
                        report.write(f"   - 测评指标: {indicator}\n")
                    implementation = metadata.get('implementation', [])
                    if implementation:
                        report.write("   - 测评实施包括以下内容:\n")
                        for step in implementation:
                            report.write(f"     * {step}\n")
                    subitems = result.get('subitems', [])
                    if subitems:
                        report.write("   - 子项检查结果:\n")
                        for sub in subitems:
                            report.write(f"     [{sub.get('status', 'PASS')}] {sub['description']}\n")
                            for detail in sub.get('details', []):
                                report.write(f"       - {detail}\n")
                            recommendations = sub.get('recommendation', [])
                            if recommendations and sub.get('status') != 'PASS':
                                for rec in recommendations:
                                    report.write(f"       整改建议: {rec}\n")
                    else:
                        details = result.get('details', [])
                        if details:
                            report.write("   - 检查详情:\n")
                            for detail in details:
                                report.write(f"     * {detail}\n")
                        recommendation = result.get('recommendation')
                        if recommendation and result['status'] != 'PASS':
                            report.write(f"   - 整改建议: {recommendation}\n")
            report.write("\n=== 检查结果汇总 ===\n")
            report.write(f"符合项: {pass_count}/{total}\n")
            report.write(f"不符合项: {fail_count}/{total}\n")
            report.write(f"检查错误: {error_count}/{total}\n")
        print(f"\n{Colors.GREEN}报告已保存到: {report_file}{Colors.END}")

    def generate_remediation_report(self) -> None:
        """Persist remediation decisions and actions into a report file."""

        if not self.remediation_records:
            print(f"\n{Colors.YELLOW}未执行任何整改操作，未生成整改报告。{Colors.END}")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"remediation_report_{timestamp}.txt"
        status_counts: Dict[str, int] = {}

        with open(report_path, "w", encoding="utf-8") as report:
            report.write("=== 三级等保整改报告 ===\n")
            report.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for record in self.remediation_records:
                status = record.get("status", "UNKNOWN")
                status_counts[status] = status_counts.get(status, 0) + 1
                status_label = self.format_status_label(status)
                report.write(
                    f"[{status_label}] {record.get('item_id', '')} - "
                    f"{record.get('subitem_description', '')}\n"
                )
                if record.get("category"):
                    report.write(f"   所属分类: {record['category']}\n")
                if record.get("indicator"):
                    report.write(f"   测评指标: {record['indicator']}\n")
                if record.get("implementation"):
                    report.write(f"   测评实施要点: {record['implementation']}\n")
                report.write(
                    f"   检查初始状态: {record.get('initial_status', '')}\n"
                )
                recommendations = record.get("recommendations", []) or []
                if recommendations:
                    report.write("   原始整改建议:\n")
                    for rec in recommendations:
                        report.write(f"     - {rec}\n")
                notes = record.get("notes", []) or []
                if notes:
                    report.write("   整改执行情况:\n")
                    for note in notes:
                        report.write(f"     - {note}\n")
                report.write("\n")

            report.write("=== 整改结果汇总 ===\n")
            for status, count in sorted(status_counts.items()):
                label = self.format_status_label(status)
                report.write(f"{label}: {count}\n")

        self.remediation_report_path = report_path

        print(f"\n{Colors.CYAN}=== 整改结果汇总 ==={Colors.END}")
        for status, count in sorted(status_counts.items()):
            label = self.format_status_label(status)
            print(f" {label}: {count}")
        print(f"{Colors.GREEN}整改报告已保存到: {report_path}{Colors.END}")
if __name__ == "__main__":
    checker = LinuxComplianceChecker()
    if checker.check_root_privilege():
        checker.run_check()