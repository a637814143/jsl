#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
* 列出可用模块::
      python3 Linux.py --list-modules
* 仅运行身份鉴别与安全审计::
      python3 Linux.py --include-module identity,audit
* 跳过入侵防范模块::
      python3 Linux.py --exclude-module intrusion_prevention,malware_protection
"""
import argparse
import sys
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Set, TextIO, Tuple
# 供 CLI 使用的模块索引，键名称与之前被注释掉的 CHECK_ITEMS 结构保持一致。
CHECK_MODULES: Dict[str, Dict[str, str]] = {
    "identity": {"title": "8.1.4.1 身份鉴别"},
    "access_control": {"title": "8.1.4.2 访问控制"},
    "audit": {"title": "8.1.4.3 安全审计"},
    "intrusion_prevention": {"title": "8.1.4.4 入侵防范"},
    "malware_protection": {"title": "8.1.4.5 恶意代码防范"},
    "trusted_verification": {"title": "8.1.4.6 可信验证"},
    "data_integrity": {"title": "8.1.4.7 数据完整性"},
    "data_confidentiality": {"title": "8.1.4.8 数据保密性"},
    "data_backup_recovery": {"title": "8.1.4.9 数据备份恢复"},
    "residual_information": {"title": "8.1.4.10 剩余信息保护"},
    "personal_information": {"title": "8.1.4.11 个人信息保护"},
}
# 每个模块对应的检查函数，名称与 LinuxComplianceChecker 中的方法一致。
MODULE_METHODS: Dict[str, List[str]] = {
    "identity": [
        "check_ces1_01_identity_authentication",
        "check_ces1_02_login_failure_handling",
        "check_ces1_03_remote_management_security",
        "check_ces1_04_multi_factor_auth",
    ],
    "access_control": [
        "check_ces1_05_account_allocation",
        "check_ces1_06_default_account_management",
        "check_ces1_07_account_review",
        "check_ces1_08_privilege_separation",
        "check_ces1_09_policy_configuration",
        "check_ces1_10_access_control_granularity",
        "check_ces1_11_security_labels",
    ],
    "audit": [
        "check_ces1_12_audit_enablement",
        "check_ces1_13_audit_log_content",
        "check_ces1_14_audit_log_protection",
        "check_ces1_15_audit_process_protection",
    ],
    "intrusion_prevention": [
        "check_ces1_17_minimal_installation",
        "check_ces1_18_service_port_control",
        "check_ces1_19_management_access_control",
        "check_ces1_20_input_validation",
        "check_ces1_21_vulnerability_management",
        "check_ces1_22_intrusion_detection_alerts",
    ],
    "malware_protection": [
        "check_ces1_23_malware_protection",
    ],
    "trusted_verification": [
        "check_ces1_24_trusted_verification",
    ],
    "data_integrity": [
        "check_ces1_25_integrity_transmission",
        "check_ces1_26_integrity_storage",
    ],
    "data_confidentiality": [
        "check_ces1_27_confidentiality_transmission",
        "check_ces1_28_confidentiality_storage",
    ],
    "data_backup_recovery": [
        "check_ces1_29_local_backup_recovery",
        "check_ces1_30_remote_backup",
        "check_ces1_31_hot_redundancy",
    ],
    "residual_information": [
        "check_ces1_32_residual_authentication_clearing",
        "check_ces1_33_residual_sensitive_clearing",
    ],
    "personal_information": [
        "check_ces1_34_personal_info_minimization",
        "check_ces1_35_personal_info_protection",
    ],
}
def _normalise(raw_values: Iterable[str]) -> List[str]:
    """Split comma-separated inputs and strip whitespace."""
    values: List[str] = []
    for value in raw_values:
        if not value:
            continue
        values.extend(chunk.strip() for chunk in value.split(",") if chunk.strip())
    return values
def _validate_modules(modules: Iterable[str]) -> List[str]:
    """Ensure requested模块存在并保持调用顺序。"""
    normalised = _normalise(modules)
    if not normalised:
        return []
    unknown = set(normalised) - CHECK_MODULES.keys()
    if unknown:
        available = ", ".join(CHECK_MODULES.keys())
        names = ", ".join(sorted(unknown))
        raise ValueError(
            f"未知模块: {names}。可用模块包括: {available}."
        )
    seen: Set[str] = set()
    ordered: List[str] = []
    for module in normalised:
        if module in seen:
            continue
        seen.add(module)
        ordered.append(module)
    return ordered
def _determine_selection(include: Iterable[str], exclude: Iterable[str]) -> List[str]:
    """Return最终需要执行的模块列表。"""
    include_list = _validate_modules(include) if include else []
    exclude_list = _validate_modules(exclude) if exclude else []
    exclude_set = set(exclude_list)
    if include_list:
        selection = [module for module in include_list if module not in exclude_set]
    else:
        selection = [
            module for module in CHECK_MODULES.keys() if module not in exclude_set
        ]
    if not selection:
        raise ValueError("根据 include/exclude 参数过滤后没有剩余模块可供检查。")
    return selection
def run_selected_modules(selected_modules: List[str]) -> int:
    """执行指定模块的检查及整改流程。"""
    checker = LinuxComplianceChecker()
    if not checker.check_root_privilege():
        return 1
    checker.run_check(selected_modules)
    return 0
def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="等保2.0 三级安全计算环境合规检查与整改工具（Linux 版本）",
    )
    parser.add_argument(
        "--include-module",
        action="append",
        default=[],
        help="仅执行指定模块，使用逗号分隔多个模块",
    )
    parser.add_argument(
        "--exclude-module",
        action="append",
        default=[],
        help="跳过指定模块，使用逗号分隔多个模块",
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="列出支持的模块后退出",
    )
    return parser.parse_args(argv)
def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.list_modules:
        print("支持的模块如下：")
        for key, meta in CHECK_MODULES.items():
            emphasised_title = (
                LinuxComplianceChecker.emphasise_primary_text(meta.get('title', ''))
                or meta.get('title', '')
            )
            print(f"  - {key}: {emphasised_title}")
        return 0
    try:
        selected_modules = _determine_selection(args.include_module, args.exclude_module)
    except ValueError as exc:  # pragma: no cover - CLI 参数错误时提示并退出
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    return run_selected_modules(selected_modules)
# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
import os
import re
import pwd
import grp
import spwd
import shutil
import stat
import socket
import struct
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
    BOLD = "\033[1m"
    BOLD_BLUE = "\033[1;34m"
    BOLD_CYAN = "\033[1;36m"
    BOLD_MAGENTA = "\033[1;35m"
    BOLD_GREEN = "\033[1;32m"
    BOLD_RED = "\033[1;31m"
    BOLD_YELLOW = "\033[1;33m"
    END = "\033[0m"

CHECK_ITEMS: Dict[str, Dict[str, object]] = {
    "identity": {
        "title": "8.1.4.1 身份鉴别",
        "items": {
            "L3-CES1-01": {
                "indicator": "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换。",
                "implementation": [
                    "应核查用户在登录时是否采用了身份鉴别措施；",
                    "应核查用户列表确认用户身份标识是否具有唯一性；",
                    "应核查用户配置信息或测试验证是否不存在空口令用户；",
                    "应核查用户鉴别信息是否具有复杂度要求并定期更换。",
                ],
            },
            "L3-CES1-02": {
                "indicator": "应具有登录失败处理功能，应配置并启用结束会话、限制非法登录次数和当登录连接超时自动退出等相关措施。",
                "implementation": [
                    "应核查是否配置并启用了登录失败处理功能；",
                    "应核查是否配置并启用了限制非法登录功能，非法登录达到一定次数后采取特定动作，如账户锁定等；",
                    "应核查是否配置并启用了登录连接超时及自动退出功能。",
                ],
            },
            "L3-CES1-03": {
                "indicator": "当进行远程管理时，应采取必要措施防止鉴别信息在网络传输过程中被窃听。",
                "implementation": [
                    "应核查是否采用加密等安全方式对系统进行远程管理，防止鉴别信息在网络传输过程中被窃听。",
                ],
            },
            "L3-CES1-04": {
                "indicator": "应采用口令、密码技术、生物技术等两种或两种以上组合的鉴别技术对用户进行身份鉴别，且其中一种鉴别技术至少应使用密码技术来实现。",
                "implementation": [
                    "应核查是否采用动态口令、数字证书、生物技术和设备指纹等两种或两种以上组合的鉴别技术对用户身份进行鉴别；",
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
                    "应核查是否为用户分配了账户和权限及相关设置情况；",
                    "应核查是否已禁用或限制匿名、默认账户的访问权限。",
                ],
            },
            "L3-CES1-06": {
                "indicator": "应重命名或删除默认账户，修改默认账户的默认口令。",
                "implementation": [
                    "应核查是否已经重命名默认账户或默认账户已被删除；",
                    "应核查是否已修改默认账户的默认口令。",
                ],
            },
            "L3-CES1-07": {
                "indicator": "应及时删除或停用多余的、过期的账户，避免共享账户的存在。",
                "implementation": [
                    "应核查是否不存在多余或过期账户，管理员用户与账户之间是否一一对应；",
                    "应测试验证多余的、过期的账户是否被删除或停用。",
                ],
            },
            "L3-CES1-08": {
                "indicator": "应授予管理用户所需的最小权限，实现管理用户的权限分离。",
                "implementation": [
                    "应核查是否进行角色划分；",
                    "应核查管理用户的权限是否已进行分离；",
                    "应核查管理用户权限是否为其工作任务所需的最小权限。",
                ],
            },
            "L3-CES1-09": {
                "indicator": "应由授权主体配置访问控制策略，访问控制策略规定主体对客体的访问规则。",
                "implementation": [
                    "应核查是否由授权主体（如管理用户）负责配置访问控制策略；",
                    "应核查授权主体是否依据安全策略配置了主体对客体的访问规则；",
                    "应测试验证用户是否有可越权访问情形。",
                ],
            },
            "L3-CES1-10": {
                "indicator": "访问控制的粒度应达到主体为用户级或进程级，客体为文件、数据库表级。",
                "implementation": [
                    "应核查访问控制策略的控制粒度是否达到主体为用户级或进程级，客体为文件、数据库表、记录或字段级。",
                ],
            },
            "L3-CES1-11": {
                "indicator": "应对重要主体和客体设置安全标记，并控制主体对有安全标记信息资源的访问。",
                "implementation": [
                    "应核查是否对主体、客体设置了安全标记；",
                    "应测试验证是否依据主体、客体安全标记控制主体对客体访问的强制访问控制策略。",
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
                    "应核查是否开启了安全审计功能；",
                    "应核查安全审计范围是否覆盖到每个用户；",
                    "应核查是否对重要的用户行为和重要安全事件进行审计。",
                ],
            },
            "L3-CES1-13": {
                "indicator": "审计记录应包括事件的日期和时间、用户、事件类型、事件是否成功及其他与审计相关的信息。",
                "implementation": [
                    "应核查审计记录信息是否包括事件的日期和时间、用户、事件类型、事件是否成功及其他与审计相关的信息。",
                ],
            },
            "L3-CES1-14": {
                "indicator": "应对审计记录进行保护，定期备份，避免受到未预期的删除、修改或覆盖等。",
                "implementation": [
                    "应核查是否采取了保护措施对审计记录进行保护；",
                    "应核查是否采取技术措施对审计记录进行定期备份，并核查其备份策略。",
                ],
            },
            "L3-CES1-15": {
                "indicator": "应对审计进程进行保护，防止未经授权的中断。",
                "implementation": [
                    "应测试验证通过非审计管理员的其他账户来中断审计进程，验证审计进程是否受到保护。",
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
                    "应核查是否遵循最小安装原则；",
                    "应核查是否未安装非必要的组件和应用程序。",
                ],
            },
            "L3-CES1-18": {
                "indicator": "应关闭不需要的系统服务、默认共享和高危端口。",
                "implementation": [
                    "应核查是否关闭了非必要的系统服务和默认共享；",
                    "应核查是否不存在非必要的高危端口。",
                ],
            },
            "L3-CES1-19": {
                "indicator": "应通过设定终端接入方式或网络地址范围对通过网络进行管理的管理终端进行限制。",
                "implementation": [
                    "应核查配置文件或参数是否对终端接入范围进行限制。",
                ],
            },
            "L3-CES1-20": {
                "indicator": "应提供数据有效性检验功能，保证通过人机接口输入或通过通信接口输入的内容符合系统设定要求。",
                "implementation": [
                    "应核查系统设计文档的内容是否包括数据有效性检验功能的内容或模块；",
                    "应测试验证是否对人机接口或通信接口输入的内容进行有效性检验。",
                ],
            },
            "L3-CES1-21": {
                "indicator": "应能发现可能存在的已知漏洞，并在经过充分测试评估后，及时修补漏洞。",
                "implementation": [
                    "应通过漏洞扫描、渗透测试等方式核查是否不存在高风险漏洞；",
                    "应核查是否在经过充分测试评估后及时修补漏洞。",
                ],
            },
            "L3-CES1-22": {
                "indicator": "应能够检测到对重要节点进行入侵的行为，并在发生严重入侵事件时提供报警。",
                "implementation": [
                    "应访谈并核查是否有入侵检测的措施；",
                    "应核查在发生严重入侵事件时是否提供报警。",
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
                    "应核查是否安装了防恶意代码软件或相应功能的软件，定期进行升级和更新防恶意代码库；",
                    "应核查是否采用主动免疫可信验证技术及时识别入侵和病毒行为；",
                    "应核查当识别入侵和病毒行为时是否将其有效阻断。",
                ],
            },
        },
    },
    "trusted_verification": {
        "title": "8.1.4.6 可信验证",
        "items": {
            "L3-CES1-24": {
                "indicator": "可基于可信根对计算设备的系统引导程序、系统程序、重要配置参数和应用程序等进行可信验证，并在应用程序的关键执行环节进行动态可信验证，在检测到其可信性受到破坏后进行报警，并将验证结果形成审计记录送至安全管理中心。",
                "implementation": [
                    "应核查是否基于可信根对计算设备的系统引导程序、系统程序、重要配置参数和应用程序等进行可信验证；",
                    "应核查是否在应用程序的关键执行环节进行动态可信验证；",
                    "应测试验证当检测到计算设备的可信性受到破坏后是否进行报警；",
                    "应测试验证结果是否以审计记录的形式送至安全管理中心。",
                ],
            },
        },
    },
    "data_integrity": {
        "title": "8.1.4.7 数据完整性",
        "items": {
            "L3-CES1-25": {
                "indicator": "应采用校验技术或密码技术保证重要数据在传输过程中的完整性，包括但不限于鉴别数据、重要业务数据、重要审计数据、重要配置数据、重要视频数据和重要个人信息等。",
                "implementation": [
                    "应核查系统设计文档，鉴别数据、重要业务数据、重要审计数据、重要配置数据、重要视频数据和重要个人信息等在传输过程中是否采用了校验技术或密码技术保证完整性；",
                    "应测试验证在传输过程中对鉴别数据、重要业务数据、重要审计数据、重要配置数据、重要视频数据和重要个人信息等进行篡改，是否能够检测到数据在传输过程中的完整性受到破坏并能够及时恢复。",
                ],
            },
            "L3-CES1-26": {
                "indicator": "应采用校验技术或密码技术保证重要数据在存储过程中的完整性，包括但不限于鉴别数据、重要业务数据、重要审计数据、重要配置数据、重要视频数据和重要个人信息等。",
                "implementation": [
                    "应核查设计文档，是否采用了校验技术或密码技术保证鉴别数据、重要业务数据、重要审计数据、重要配置数据、重要视频数据和重要个人信息等在存储过程中的完整性；",
                    "应核查是否采用技术措施（如数据安全保护系统等）保证鉴别数据、重要业务数据、重要审计数据、重要配置数据、重要视频数据和重要个人信息等在存储过程中的完整性；",
                    "应测试验证在存储过程中对鉴别数据、重要业务数据、重要审计数据、重要配置数据、重要视频数据和重要个人信息等进行篡改，是否能够检测到数据在存储过程中的完整性受到破坏并能够及时恢复。",
                ],
            },
        },
    },
    "data_confidentiality": {
        "title": "8.1.4.8 数据保密性",
        "items": {
            "L3-CES1-27": {
                "indicator": "应采用密码技术保证重要数据在传输过程中的保密性，包括但不限于鉴别数据、重要业务数据和重要个人信息等。",
                "implementation": [
                    "应核查系统设计文档，鉴别数据、重要业务数据和重要个人信息等在传输过程中是否采用密码技术保证保密性；",
                    "应通过嗅探等方式抓取传输过程中的数据包，鉴别数据、重要业务数据和重要个人信息等在传输过程中是否进行了加密处理。",
                ],
            },
            "L3-CES1-28": {
                "indicator": "应采用密码技术保证重要数据在存储过程中的保密性，包括但不限于鉴别数据、重要业务数据和重要个人信息等。",
                "implementation": [
                    "应核查是否采用密码技术保证鉴别数据、重要业务数据和重要个人信息等在存储过程中的保密性；",
                    "应核查是否采用技术措施（如数据安全保护系统等）保证鉴别数据、重要业务数据和重要个人信息等在存储过程中的保密性；",
                    "应测试验证是否对指定的数据进行加密处理。",
                ],
            },
        },
    },
    "data_backup_recovery": {
        "title": "8.1.4.9 数据备份恢复",
        "items": {
            "L3-CES1-29": {
                "indicator": "应提供重要数据的本地数据备份与恢复功能。",
                "implementation": [
                    "应核查是否按照备份策略进行本地备份；",
                    "应核查备份策略设置是否合理、配置是否正确；",
                    "应核查备份结果是否与备份策略一致；",
                    "应核查近期恢复测试记录是否能够进行正常的数据恢复。",
                ],
            },
            "L3-CES1-30": {
                "indicator": "应提供异地实时备份功能，利用通信网络将重要数据实时备份至备份场地。",
                "implementation": [
                    "应核查是否提供异地实时备份功能，并通过网络将重要配置数据、重要业务数据实时备份至备份场地。",
                ],
            },
            "L3-CES1-31": {
                "indicator": "应提供重要数据处理系统的热冗余，保证系统的高可用性。",
                "implementation": [
                    "应核查重要数据处理系统（包括边界路由器、边界防火墙、核心交换机、应用服务器和数据库服务器等）是否采用热冗余方式部署。",
                ],
            },
        },
    },
    "residual_information": {
        "title": "8.1.4.10 剩余信息保护",
        "items": {
            "L3-CES1-32": {
                "indicator": "应保证鉴别信息所在的存储空间被释放或重新分配前得到完全清除。",
                "implementation": [
                    "应核查相关配置信息或系统设计文档，用户的鉴别信息所在的存储空间被释放或重新分配前是否得到完全清除。",
                ],
            },
            "L3-CES1-33": {
                "indicator": "应保证存有敏感数据的存储空间被释放或重新分配前得到完全清除。",
                "implementation": [
                    "应核查相关配置信息或系统设计文档，敏感数据所在的存储空间被释放或重新分配给其他用户前是否得到完全清除。",
                ],
            },
        },
    },
    "personal_information": {
        "title": "8.1.4.11 个人信息保护",
        "items": {
            "L3-CES1-34": {
                "indicator": "应仅采集和保存业务必需的用户个人信息。",
                "implementation": [
                    "应核查采集的用户个人信息是否是业务应用必需的；",
                    "应核查是否制定了有关用户个人信息保护的管理制度和流程。",
                ],
            },
            "L3-CES1-35": {
                "indicator": "应禁止未授权访问和非法使用用户个人信息。",
                "implementation": [
                    "应核查是否采用技术措施限制对用户个人信息的访问和使用；",
                    "应核查是否制定了有关用户个人信息保护的管理制度和流程。",
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

COMPLIANCE_STATUS_LABELS = {
    "PASS": "符合",
    "FAIL": "不符合",
    "ERROR": "检查错误",
    "UNKNOWN": "未知",
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
    ("L3-CES1-09", None): [
        "1. 访谈系统授权管理员，确认由哪些主体负责制定与发布访问控制策略，并记录授权凭据。",
        "2. 对照安全策略检查 ACL、文件权限或数据库授权配置，确保主体对客体的访问规则均已受控并可追溯。",
        "3. 选取敏感资源进行越权访问尝试，验证策略是否有效拦截并记录结果。",
    ],
    ("L3-CES1-10", None): [
        "1. 抽查应用与数据库权限模型，确认控制粒度已经细化到用户/进程与文件、表、记录或字段级。",
        "2. 对比需求文档与实际权限，记录是否存在仅目录级或库级授权的粗粒度情形。",
        "3. 针对发现的粗粒度授权，制定细化方案并安排变更窗口实施。",
    ],
    ("L3-CES1-15", None): [
        "1. 列出审计服务（如 auditd/rsyslog）对应的进程与 systemd 单元，确认已启用保护策略。",
        "2. 使用非审计管理员账户尝试停止或卸载审计服务，验证是否被权限或安全策略阻止。",
        "3. 如可被中断，请收紧系统权限或添加 service 硬ening（如 `RefuseManualStop=yes`），并记录验证结果。",
    ],
    ("L3-CES1-20", None): [
        "1. 查阅设计/接口文档，识别输入校验模块或中间件配置（如 WAF、参数校验库）。",
        "2. 通过手工或自动化测试提交超长、非法格式、注入类输入，确认系统能够拦截或返回校验错误。",
        "3. 对缺失校验的接口，补充后端验证或前置网关规则，并补充回归测试用例。",
    ],
    ("L3-CES1-21", None): [
        "1. 使用漏洞扫描/渗透工具对目标进行评估，收集高危漏洞列表与风险等级。",
        "2. 针对发现的漏洞制定修补计划并在测试环境验证补丁或配置变更的兼容性。",
        "3. 在生产实施修复后复扫确认漏洞已关闭，并记录审批与回归结果。",
    ],
    ("L3-CES1-22", None): [
        "1. 核查入侵检测/防御系统或主机安全代理的部署情况，确认告警通道可用。",
        "2. 通过模拟入侵事件（如端口扫描、暴力破解尝试）验证是否生成告警并能及时通知。",
        "3. 若缺失检测或告警，请部署 IDS/EDR 并配置升级与告警接收人。",
    ],
    ("L3-CES1-24", None): [
        "1. 审阅可信计算或安全启动方案，确认 BIOS/BootLoader/系统文件已纳入可信根校验范围。",
        "2. 检查是否启用运行时完整性/白名单机制，并对关键执行环节进行动态验证。",
        "3. 模拟篡改后验证能否触发告警并生成审计记录上报安全管理中心。",
    ],
    ("L3-CES1-25", None): [
        "1. 检查传输层是否启用 TLS/IPsec/消息签名，确认覆盖鉴别、业务、审计等重要数据。",
        "2. 通过抓包或篡改测试验证数据被修改后能被校验/加密机制检测并拒绝。",
        "3. 对未加密或未校验链路，补充传输加密或报文完整性校验配置。",
    ],
    ("L3-CES1-26", None): [
        "1. 核查数据库、存储或配置库是否启用校验或防篡改机制（如校验和、HMAC、AIDE）。",
        "2. 模拟修改关键数据文件，验证完整性监测是否告警并能恢复。",
        "3. 对缺失保护的数据存储启用校验/签名或部署完整性监测工具。",
    ],
    ("L3-CES1-27", None): [
        "1. 确认重要数据传输已使用加密隧道（HTTPS/SSH/VPN）或应用层加密。",
        "2. 抓包检查是否仍存在明文鉴别数据或个人信息，必要时启用强制加密。",
        "3. 更新设计文档及配置，确保传输加密范围覆盖所有敏感链路。",
    ],
    ("L3-CES1-28", None): [
        "1. 核实数据库、文件系统或备份介质对重要数据是否启用加密存储。",
        "2. 检查密钥管理方案与访问控制，避免未授权解密。",
        "3. 对未加密的敏感数据启用加密或调整访问策略，并记录验证结果。",
    ],
    ("L3-CES1-29", None): [
        "1. 评估当前备份策略与计划任务，确认本地备份周期、保留期与内容符合要求。",
        "2. 抽查备份产物的完整性与可用性，执行恢复演练并记录成功率。",
        "3. 如未覆盖关键数据或恢复失败，调整备份工具与策略并复测。",
    ],
    ("L3-CES1-30", None): [
        "1. 核查是否存在异地实时备份链路/服务，确认同步范围与带宽。",
        "2. 验证数据在备份站点的可用性与一致性，评估延迟与故障切换流程。",
        "3. 若缺失该能力，规划备份链路或云端复制方案并评估安全加固措施。",
    ],
    ("L3-CES1-31", None): [
        "1. 盘点边界设备、核心交换、应用与数据库节点的冗余部署情况。",
        "2. 检查负载均衡/双机热备配置并执行切换演练，确认服务不中断。",
        "3. 对单点风险组件制定热备方案并提交变更实施。",
    ],
    ("L3-CES1-32", None): [
        "1. 审核身份鉴别信息的存储与销毁流程，确认介质/内存释放前有清除机制。",
        "2. 通过测试账户删除或密码重置流程，验证敏感残留是否被彻底清理。",
        "3. 对发现的残留风险补充擦除命令或安全清除策略。",
    ],
    ("L3-CES1-33", None): [
        "1. 审核敏感数据存储位置与释放流程，确认重分配前执行了覆写或加密擦除。",
        "2. 抽样验证卷/对象删除后的残留情况，必要时使用安全擦除工具。",
        "3. 补充清除策略与审计记录，确保敏感空间在分配前已净化。",
    ],
    ("L3-CES1-34", None): [
        "1. 对照业务清单审查采集字段，确认仅保留业务必需的个人信息。",
        "2. 检查并完善个人信息保护制度、告知与同意流程。",
        "3. 删除或匿名化非必要字段，并记录变更审批。",
    ],
    ("L3-CES1-35", None): [
        "1. 检查访问控制、脱敏/最小化展示与审计策略是否覆盖个人信息数据。",
        "2. 核查相关管理制度与操作流程，确保未授权访问可被阻止并追责。",
        "3. 对发现的未授权访问路径进行封堵或细化权限，并完善日志审计。",
    ],

}

class LinuxComplianceChecker:
    """Implements the third-level compliance checks defined in section 8.1.4."""

    REPORT_EXTENSION = ".md"

    def __init__(self) -> None:
        self.results: Dict[str, Dict[str, object]] = {}
        self.os_info = self.get_os_info()
        self.current_user = os.getenv("USER")
        self.package_manager: Optional[str] = self.detect_package_manager()
        self.remediation_records: List[Dict[str, object]] = []
        self.remediation_report_path: Optional[str] = None
        self.apt_cache_refreshed = False
        self.selected_modules: List[str] = list(MODULE_METHODS.keys())

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

    def build_markdown_report_path(
        self, prefix: str, timestamp: Optional[str] = None
    ) -> str:
        """Return a Markdown report filename with a consistent extension."""

        resolved_timestamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
        extension = (
            self.REPORT_EXTENSION
            if self.REPORT_EXTENSION.startswith(".")
            else f".{self.REPORT_EXTENSION}"
        )
        return f"{prefix}{resolved_timestamp}{extension}"

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

    def describe_package_installation(self, package: str) -> Optional[str]:
        """Return a human-readable summary for an installed package."""

        manager = self.package_manager or self.detect_package_manager()
        if not manager:
            return None

        self.package_manager = manager

        if manager == "dpkg":
            rc, stdout, _ = self.run_command(
                f"dpkg-query -W -f='${{Version}} ${{Architecture}}' {package}"
            )
            if rc == 0:
                summary = stdout.strip()
                if summary:
                    return f"{package} {summary}"
                return package
            return None

        if manager == "rpm":
            rc, stdout, _ = self.run_command(
                f"rpm -q --qf '%{{NAME}} %{{VERSION}}-%{{RELEASE}} %{{ARCH}}' {package}"
            )
            if rc == 0:
                return stdout.strip()
            return None

        if manager == "pacman":
            rc, stdout, _ = self.run_command(f"pacman -Qi {package}")
            if rc == 0:
                version = ""
                arch = ""
                for line in stdout.splitlines():
                    if line.startswith("Version"):
                        version = line.split(" : ", 1)[-1].strip()
                    if line.startswith("Architecture"):
                        arch = line.split(" : ", 1)[-1].strip()
                details = f"{package} {version}".strip()
                if arch:
                    details = f"{details} {arch}".strip()
                return details or package
            return None

        if manager == "apk":
            rc, stdout, _ = self.run_command(f"apk info -e {package}")
            if rc == 0:
                for line in stdout.splitlines():
                    if line.startswith(package):
                        return line.strip()
                return package
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
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except Exception as exc:  # pylint: disable=broad-except
            return -1, "", str(exc)

    @staticmethod
    def message_indicates_missing_service(message: str) -> bool:
        if not message:
            return False

        lowered = message.lower()
        keywords = [
            "no such file or directory",
            "could not be found",
            "not found",
            "unrecognized service",
            "unknown service",
            "loaded: not-found",
        ]
        return any(keyword in lowered for keyword in keywords)

    @staticmethod
    def message_indicates_systemd_unavailable(message: str) -> bool:
        if not message:
            return False

        lowered = message.lower()
        return "system has not been booted with systemd" in lowered or "failed to connect to bus" in lowered

    @staticmethod
    def command_has_placeholder(command: str) -> bool:
        """Check whether a suggested command contains obvious placeholders."""

        return any(token in command for token in ("<", "…", "..."))

    @staticmethod
    def summarise_command_output(
        output: str, max_lines: int = 3, max_chars: int = 200
    ) -> str:
        """Condense command output so it can be embedded into remediation笔记."""

        if not output:
            return ""

        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return ""

        truncated = False
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            truncated = True

        summary = "; ".join(lines)
        if len(summary) > max_chars:
            summary = summary[:max_chars].rstrip()
            truncated = True

        if truncated:
            summary += " …"

        return summary

    @staticmethod
    def extract_pam_policy_tokens(line: str) -> List[str]:
        """Return significant option tokens from a PAM faillock/tally2配置行."""

        if not line:
            return []

        match = re.search(r"pam_(?:faillock|tally2)\.so(.*)", line)
        if not match:
            return []

        trailing = match.group(1)
        if not trailing:
            return []

        tokens: List[str] = []
        for raw_token in trailing.split():
            cleaned = raw_token.strip().strip(",")
            if not cleaned:
                continue
            if "=" in cleaned:
                tokens.append(cleaned)
                continue
            if cleaned in {"even_deny_root", "even_deny_non_root", "silent", "audit"}:
                tokens.append(cleaned)

        return tokens

    @staticmethod
    def safe_getpwuid(uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)
        except Exception:  # pylint: disable=broad-except
            return str(uid)

    @staticmethod
    def safe_getgrgid(gid: int) -> str:
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return str(gid)
        except Exception:  # pylint: disable=broad-except
            return str(gid)

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
    def parse_colon_key_values(text: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            fields[key] = value
        return fields

    @staticmethod
    def days_since_epoch() -> int:
        epoch = datetime(1970, 1, 1)
        return (datetime.now() - epoch).days

    @staticmethod
    def describe_password_hash(hash_field: str) -> str:
        if hash_field is None:
            return "未提供口令字段"

        field = hash_field.strip()
        if field == "":
            return "空口令"

        locked = False
        while field.startswith("!") or field.startswith("*"):
            locked = True
            field = field[1:]
        if field == "":
            return "账户已锁定/禁用"

        algorithm_map = {
            "1": "MD5",
            "2a": "Blowfish",
            "5": "SHA-256",
            "6": "SHA-512",
            "y": "yescrypt",
            "gy": "gost-yescrypt",
            "apr1": "Apache MD5",
            "bcrypt": "bcrypt",
        }

        algorithm = "传统DES散列"
        if field.startswith("$"):
            parts = field.split("$")
            if len(parts) > 2:
                alg_id = parts[1]
                algorithm = algorithm_map.get(alg_id, f"算法ID {alg_id}")
        preview = field[:16] + ("..." if len(field) > 16 else "")
        status_parts = [algorithm, f"哈希前缀: {preview}"]
        if locked:
            status_parts.append("账户已锁定/禁用")
        return ", ".join(status_parts)

    @staticmethod
    def describe_shadow_change(last_change_int: Optional[int], now_days: int) -> str:
        if last_change_int is None or last_change_int <= 0:
            return "最后改密时间未知"
        change_date = datetime(1970, 1, 1) + timedelta(days=last_change_int)
        days_ago = max(0, now_days - last_change_int)
        return f"最后改密 {change_date.strftime('%Y-%m-%d')} ({days_ago} 天前)"

    @staticmethod
    def describe_shadow_expiry(expire_int: Optional[int], now_days: int) -> str:
        if expire_int is None or expire_int <= 0:
            return "未设置到期日"
        expire_date = datetime(1970, 1, 1) + timedelta(days=expire_int)
        delta = expire_int - now_days
        if delta >= 0:
            return f"预计到期 {expire_date.strftime('%Y-%m-%d')} (剩余 {delta} 天)"
        return f"已于 {expire_date.strftime('%Y-%m-%d')} 到期 ({-delta} 天前)"

    @staticmethod
    def resolve_group_name(gid: int) -> str:
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return f"GID {gid}"

    def describe_account_overview(
        self,
        username: str,
        entry: Optional[pwd.struct_passwd],
        info: Dict[str, object],
        now_days: int,
    ) -> str:
        parts: List[str] = []

        if entry is not None:
            group_name = self.resolve_group_name(entry.pw_gid)
            parts.append(f"UID {entry.pw_uid}")
            parts.append(f"主组 {group_name} (GID {entry.pw_gid})")
            parts.append(f"家目录 {entry.pw_dir}")
            parts.append(f"Shell {entry.pw_shell}")
        else:
            parts.append("未在/etc/passwd中找到对应账户信息")

        password_summary = info.get("password_summary")
        if isinstance(password_summary, str) and password_summary:
            parts.append(password_summary)
        elif entry is not None:
            parts.append("未在/etc/shadow找到口令摘要")

        last_change_desc = info.get("last_change_desc")
        last_change_int = info.get("last_change_int")
        if not last_change_desc and isinstance(last_change_int, int):
            last_change_desc = self.describe_shadow_change(last_change_int, now_days)
        if isinstance(last_change_desc, str) and last_change_desc:
            parts.append(last_change_desc)
        else:
            parts.append("最后改密时间未知")

        expire_desc = info.get("expire_desc")
        expire_int = info.get("expire_int")
        if not expire_desc and isinstance(expire_int, int):
            expire_desc = self.describe_shadow_expiry(expire_int, now_days)
        if isinstance(expire_desc, str) and expire_desc:
            parts.append(expire_desc)
        else:
            parts.append("未设置到期日")

        flags = info.get("flags")
        if isinstance(flags, list):
            for flag in flags:
                if flag:
                    parts.append(flag)

        return f"{username}: " + "; ".join(parts)

    @staticmethod
    def summarize_rotation(username: str, info: Dict[str, object]) -> str:
        parts: List[str] = []
        last_change_desc = info.get("last_change_desc")
        if isinstance(last_change_desc, str) and last_change_desc:
            parts.append(last_change_desc)
        else:
            parts.append("最后改密时间未知")

        max_days_int = info.get("max_days_int")
        if isinstance(max_days_int, int):
            parts.append(f"有效期 {max_days_int} 天")
        else:
            raw = info.get("max_days_raw")
            if raw:
                parts.append(f"有效期字段={raw}")
            else:
                parts.append("未配置有效期字段")

        days_remaining = info.get("days_remaining")
        if isinstance(days_remaining, int):
            if days_remaining >= 0:
                parts.append(f"剩余 {days_remaining} 天")
            else:
                parts.append(f"已超期 {-days_remaining} 天")

        issues = info.get("flags")
        if isinstance(issues, list) and issues:
            parts.extend(issues)

        return f"{username}: {', '.join(parts)}"

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
            elif status not in {"PASS", "FAIL", "ERROR"} and overall_status == "PASS":
                overall_status = status

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
        active_modules = self.selected_modules or list(MODULE_METHODS.keys())
        for module in active_modules:
            category = CHECK_ITEMS.get(module, {})
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
            emphasised_desc = (
                self.emphasise_primary_text(description) or description
            )
            print(
                f" {index}. {target['item_id']} - {emphasised_desc} (当前状态: {status})"
            )

        print()
        for index, target in enumerate(targets, 1):
            subitem = target["subitem"]
            description = subitem.get("description", "")
            heading_text = f"整改项 {index}: {target['item_id']}"
            initial_status = target.get("result_status")
            if initial_status:
                heading_text = f"{heading_text} · {initial_status}"
            print(
                self.render_heading(
                    heading_text,
                    level=2,
                    colour=Colors.BOLD_BLUE,
                )
            )
            emphasised_desc = self.emphasise_primary_text(description) or description
            print(f"   子项描述: {emphasised_desc}")
            if target.get("indicator"):
                indicator_text = (
                    self.emphasise_primary_text(target["indicator"]) or target["indicator"]
                )
                print(f"   测评指标: {indicator_text}")
            if target.get("implementation_text"):
                implementation_text = (
                    self.emphasise_primary_text(target["implementation_text"])
                    or target["implementation_text"]
                )
                print(f"   对应实施要点: {implementation_text}")
            details = subitem.get("details", [])
            if details:
                print(f"   {Colors.BOLD}当前问题:{Colors.END}")
                for detail in details:
                    print(f"     - {detail}")
            recommendations = subitem.get("recommendation", [])
            if recommendations:
                print(f"   {Colors.BOLD}推荐整改措施:{Colors.END}")
                for rec in recommendations:
                    emphasised_rec = self.emphasise_primary_text(rec) or rec
                    print(f"     * {emphasised_rec}")

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
            print(f"   -> 整改结果: {self.format_status_label(status)}")
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
            print()
            step_heading = self.render_heading(f"步骤 {index}", level=3, indent=3)
            if step_heading:
                print(step_heading)
            emphasised_step = self.emphasise_primary_text(step) or step
            print(f"      {emphasised_step}")
            step_notes.append(f"步骤{index}: {step}")
            commands = re.findall(r"`([^`]+)`", step)
            if not commands:
                response = self.safe_input(
                    "      完成上述操作后按回车继续，或输入 skip 跳过: "
                )
                if response is None:
                    step_notes.append(
                        "终端输入被中断（可能是 Ctrl+C/Ctrl+D），该步骤暂未执行。"
                    )
                    step_notes.append("用户暂未执行该步骤，需后续复核。")
                    continue

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
                        "      建议命令包含占位符，请根据实际情况提供具体命令。"
                    )
                else:
                    emphasised_command = self.emphasise_primary_text(suggested) or suggested
                    print(f"      建议执行命令: {emphasised_command}")

                while True:
                    if has_placeholder:
                        prompt = (
                            "      请输入要执行的命令（输入 skip 跳过该命令）: "
                        )
                    else:
                        prompt = (
                            "      按回车执行上述命令，输入自定义命令替换，"
                            "或输入 skip 跳过: "
                        )
                    user_input = self.safe_input(prompt)
                    if user_input is None:
                        step_notes.append(
                            f"命令 `{suggested}` 因用户中断输入而跳过。"
                        )
                        step_skipped = True
                        break

                    chosen = user_input.strip()

                    if not chosen and has_placeholder:
                        print("      该命令需要具体参数，请输入命令或输入 skip 跳过。")
                        continue

                    if chosen.lower() in {"skip", "s"}:
                        step_notes.append(
                            f"命令 `{suggested}` 被用户选择跳过。"
                        )
                        step_skipped = True
                        break

                    actual_command = chosen or suggested
                    if actual_command != suggested:
                        step_notes.append(
                            f"命令 `{suggested}` 已替换为 `{actual_command}` 执行。"
                        )
                    rc, stdout, stderr = self.run_command(actual_command)
                    step_notes.append(
                        f"命令 `{actual_command}` 执行返回码 {rc}。"
                    )
                    executed_any_command = True

                    print(f"      -> 返回码: {rc}")
                    if stdout:
                        print("        STDOUT:")
                        for line in stdout.splitlines():
                            print(f"          {line}")
                        summary = self.summarise_command_output(stdout)
                        if summary:
                            step_notes.append(
                                f"命令 `{actual_command}` STDOUT 摘要: {summary}"
                            )
                    if stderr:
                        print("        STDERR:")
                        for line in stderr.splitlines():
                            print(f"          {line}")
                        summary = self.summarise_command_output(stderr)
                        if summary:
                            step_notes.append(
                                f"命令 `{actual_command}` STDERR 摘要: {summary}"
                            )

                    if rc != 0:
                        if self.prompt_user_confirmation(
                            "      命令执行失败，是否重试？(y/n，回车表示否): "
                        ):
                            step_notes.append(
                                f"命令 `{actual_command}` 返回码 {rc}，用户选择重试。"
                            )
                            continue
                        step_notes.append(
                            f"命令 `{actual_command}` 返回码 {rc}，用户放弃重试。"
                        )
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
                    "      命令执行完毕，结果是否符合预期？(y/n，回车表示否): "
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

        extra_note = self.prompt_optional_text(
            "   如需补充说明或记录后续计划，请输入（直接回车跳过）: "
        )
        if extra_note:
            step_notes.append(f"补充说明: {extra_note}")

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
    def safe_input(message: str) -> Optional[str]:
        """Wrapper around input() that gracefully handles EOF/KeyboardInterrupt."""

        try:
            return input(message)
        except (EOFError, KeyboardInterrupt):
            return None

    def prompt_optional_text(self, message: str) -> Optional[str]:
        """Collect optional free-form备注 when recording整改情况."""

        response = self.safe_input(message)
        if response is None:
            return None
        cleaned = response.strip()
        return cleaned or None

    def prompt_user_confirmation(self, message: str) -> bool:
        """Prompt the operator before executing a remediation step."""

        while True:
            response = self.safe_input(message)
            if response is None:
                return False
            choice = response.strip().lower()
            if choice in {"y", "yes", "是"}:
                return True
            if choice in {"", "n", "no", "否"}:
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
    def format_compliance_status(status: str) -> str:
        """Translate合规性检查状态到中文，便于在报告中直观展示。"""

        return COMPLIANCE_STATUS_LABELS.get(status, status)

    @staticmethod
    def render_heading(
        text: str,
        level: int = 1,
        indent: int = 0,
        plain: bool = False,
        colour: Optional[str] = None,
    ) -> str:
        """Render emphasised headings with simple underline gradients to suggest size."""

        sanitized = (text or "").strip()
        if not sanitized:
            return ""

        if level <= 1:
            content = sanitized.upper()
            underline_char = "="
            default_colour = Colors.BOLD_BLUE
        elif level == 2:
            content = sanitized
            underline_char = "-"
            default_colour = Colors.BOLD_CYAN
        else:
            content = sanitized
            underline_char = "~"
            default_colour = Colors.BOLD_MAGENTA

        prefix = " " * max(indent, 0)
        lines = [f"{prefix}{content}"]

        underline = underline_char * len(content)
        if underline:
            lines.append(f"{prefix}{underline}")

        heading = "\n".join(lines)

        if plain:
            return heading

        style = colour or default_colour
        return f"{style}{heading}{Colors.END}"

    @staticmethod
    def render_markdown_heading(text: str, level: int = 1) -> str:
        """Render a Markdown heading with a trailing blank line."""

        sanitized = (text or "").strip()
        if not sanitized:
            return ""

        prefix = "#" * max(level, 1)
        return f"{prefix} {sanitized}\n\n"

    @staticmethod
    def write_markdown_metadata(report: TextIO, metadata: Dict[str, str]) -> None:
        """Write a block of key-value metadata as a Markdown table."""

        if not metadata:
            return

        rows = [[key, value] for key, value in metadata.items() if value]
        report.write(
            LinuxComplianceChecker.render_markdown_table(
                ["字段", "值"], rows
            )
        )

    @staticmethod
    def render_markdown_table(headers: List[str], rows: List[List[object]]) -> str:
        """Render a Markdown table with escaped content and a trailing blank line."""

        if not headers:
            return ""

        def escape_cell(cell: object) -> str:
            if cell is None:
                return ""
            return str(cell).replace("|", "\\|").replace("\n", "<br>")

        column_count = len(headers)
        header_line = " | ".join(escape_cell(header) for header in headers)
        divider = " | ".join("---" for _ in headers)
        lines = [f"| {header_line} |", f"| {divider} |"]

        for row in rows:
            padded = list(row) + [""] * (column_count - len(row))
            cells = " | ".join(
                escape_cell(cell) for cell in padded[:column_count]
            )
            lines.append(f"| {cells} |")

        lines.append("")
        return "\n".join(lines)

    def render_markdown_cover(
        self,
        subject_placeholder: str,
        report_title: str,
        report_number: str = "XXXXXXXXXXXX-XX-XXXX-XX",
        client_label: str = "委托单位",
        assessor_label: str = "测评单位",
        report_time_label: str = "报告时间",
    ) -> str:
        """Render a cover page block for Markdown reports."""

        rows = [
            [client_label, "______________"],
            [assessor_label, "______________"],
            [report_time_label, "____年____月"],
        ]

        parts = [
            "<div align=\"center\">",
            f"**报告编号：** {report_number}",
            "",
            "# 网络安全等级保护",
            f"## {subject_placeholder}{report_title}",
            "</div>",
            "",
            self.render_markdown_table(["字段", "内容"], rows).rstrip(),
            "",
            "<div style=\"page-break-after: always;\"></div>",
            "",
        ]

        return "\n".join(parts)

    @staticmethod
    def emphasise_primary_text(text: str) -> str:
        """Format dictionary-sourced content in a visually larger (bold) style."""

        sanitized = (text or "").strip()
        if not sanitized:
            return ""
        return f"{Colors.BOLD}{sanitized}{Colors.END}"

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

    def run_check(self, modules: Optional[List[str]] = None) -> None:
        active_modules = modules or list(MODULE_METHODS.keys())
        self.selected_modules = active_modules[:]

        print(f"{Colors.CYAN}\n=== 开始三级等保合规检查 ==={Colors.END}")
        print(f"系统信息: {self.os_info['distribution']} {self.os_info['machine']}\n")

        for module in active_modules:
            method_names = MODULE_METHODS.get(module, [])
            for method_name in method_names:
                getattr(self, method_name)()

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
            matched = 0
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if not stripped.lower().startswith('auth'):
                    continue
                if any(module in stripped for module in auth_modules):
                    auth_lines.append(f"{pam_file}: {stripped}")
                    matched += 1
        if auth_lines:
            subitems[0]["details"].append("已在PAM配置中检测到身份鉴别模块")
            subitems[0]["details"].extend(auth_lines)
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未在PAM配置文件中找到pam_unix/pam_sss等身份鉴别模块")
            subitems[0]["recommendation"].append(
                "请检查/etc/pam.d/目录下的认证配置，确保启用了身份鉴别模块"
            )
        if missing_pam_files and not auth_lines:
            subitems[0]["details"].append(
                "以下PAM配置文件未读取到: " + ", ".join(missing_pam_files)
            )

        username_counts: Dict[str, int] = {}
        uid_to_users: Dict[str, List[str]] = {}
        interactive_users: Set[str] = set()
        account_entries: List[Tuple[str, str, str]] = []
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
                    account_entries.append((username, uid, shell))
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
                if account_entries:
                    subitems[1]["details"].append("账户列表(用户名: UID, Shell):")
                    for username, uid, shell in sorted(
                        account_entries,
                        key=lambda entry: (
                            int(entry[1]) if entry[1].isdigit() else float('inf'),
                            entry[0],
                        ),
                    ):
                        shell_note = (
                            f"{shell} (交互式)"
                            if shell in INTERACTIVE_SHELLS
                            else shell
                        )
                        subitems[1]["details"].append(
                            f" - {username}: {uid} ({shell_note})"
                        )
                    subitems[1]["details"].append(
                        f"共计 {len(account_entries)} 个账户参与核查"
                    )

        interactive_hash_summaries: Dict[str, str] = {}

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
                        if len(fields) < 2:
                            continue
                        username = fields[0]
                        password_field = fields[1]
                        if username in interactive_users:
                            interactive_hash_summaries[username] = self.describe_password_hash(
                                password_field
                            )
                        if password_field == '':
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
                    if interactive_users:
                        subitems[2]["details"].append(
                            "未检测到空口令账户，以下可交互用户均设置了口令:"
                        )
                        for username in sorted(interactive_users):
                            summary = interactive_hash_summaries.get(
                                username,
                                "未在/etc/shadow找到对应条目",
                            )
                            subitems[2]["details"].append(
                                f" - {username}: {summary}"
                            )
                        subitems[2]["details"].append(
                            f"共核查 {len(interactive_users)} 个可交互账户"
                        )
                    else:
                        subitems[2]["details"].append(
                            "未检测到空口令账户，系统中不存在可交互登录账户"
                        )

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
            if not pass_max:
                issues.append("未找到 PASS_MAX_DAYS 配置")
            else:
                max_value = int(pass_max.group(1))
                if max_value > 90:
                    issues.append(f"PASS_MAX_DAYS 当前值为 {max_value}，应不大于90")
            if not pass_min:
                issues.append("未找到 PASS_MIN_DAYS 配置")
            else:
                min_value = int(pass_min.group(1))
                if min_value < 7:
                    issues.append(f"PASS_MIN_DAYS 当前值为 {min_value}，应不小于7")
            if not pass_warn:
                issues.append("未找到 PASS_WARN_AGE 配置")
            else:
                warn_value = int(pass_warn.group(1))
                if warn_value < 7:
                    issues.append(f"PASS_WARN_AGE 当前值为 {warn_value}，应不小于7")
            if issues:
                rotation_policy_ok = False
                subitems[4]["status"] = "FAIL"
                subitems[4]["details"].extend(issues)
                subitems[4]["recommendation"].append(
                    "请在/etc/login.defs中设置 PASS_MAX_DAYS 90、PASS_MIN_DAYS 7、PASS_WARN_AGE 7"
                )
            else:
                subitems[4]["details"].append("密码有效期策略配置满足90/7/7要求")
                configured_values: List[str] = []
                if pass_max:
                    configured_values.append(f"PASS_MAX_DAYS={pass_max.group(1)}")
                if pass_min:
                    configured_values.append(f"PASS_MIN_DAYS={pass_min.group(1)}")
                if pass_warn:
                    configured_values.append(f"PASS_WARN_AGE={pass_warn.group(1)}")
                if configured_values:
                    subitems[4]["details"].append(
                        "检测到以下/etc/login.defs配置: "
                        + ", ".join(configured_values)
                    )

        if rotation_policy_ok:
            shadow_content = self.read_file('/etc/shadow')
            if shadow_content:
                now_days = self.days_since_epoch()
                overdue_users: List[str] = []
                missing_limit_users: List[str] = []
                login_users = self.get_login_users()
                per_user_rotation_info: Dict[str, Dict[str, object]] = {}
                for line in shadow_content.splitlines():
                    if not line or ':' not in line:
                        continue
                    fields = line.split(':')
                    username = fields[0]
                    if username not in login_users:
                        continue
                    max_days = fields[4] if len(fields) > 4 else ''
                    last_change = fields[2] if len(fields) > 2 else ''
                    info: Dict[str, object] = {
                        "max_days_raw": max_days,
                        "last_change_raw": last_change,
                        "flags": [],
                    }
                    max_days_int: Optional[int] = None
                    if max_days and max_days not in {'', '-1', '99999'}:
                        try:
                            max_days_int = int(max_days)
                        except ValueError:
                            max_days_int = None
                    info["max_days_int"] = max_days_int
                    if not max_days or max_days in {'', '-1', '99999'}:
                        missing_limit_users.append(username)
                        info.setdefault("flags", []).append("未设置有效期上限")
                    elif max_days_int is None:
                        missing_limit_users.append(username)
                        info.setdefault("flags", []).append("有效期字段无法解析")
                    elif max_days_int > 90:
                        missing_limit_users.append(username)
                        info.setdefault("flags", []).append(
                            f"有效期 {max_days_int} 天，大于90天限制"
                        )
                    try:
                        last_change_int = int(last_change)
                    except ValueError:
                        last_change_int = None
                    info["last_change_int"] = last_change_int
                    if last_change_int is not None:
                        info["last_change_desc"] = self.describe_shadow_change(
                            last_change_int, now_days
                        )
                        days_since_change = max(0, now_days - last_change_int)
                        info["days_since_change"] = days_since_change
                        if isinstance(max_days_int, int):
                            info["days_remaining"] = max_days_int - days_since_change
                            if days_since_change > max_days_int:
                                overdue_users.append(username)
                                info.setdefault("flags", []).append(
                                    f"已超期 {days_since_change - max_days_int} 天"
                                )
                    else:
                        info.setdefault("flags", []).append("缺少最后改密日期")
                    per_user_rotation_info[username] = info
                if missing_limit_users:
                    subitems[4]["status"] = "FAIL"
                    subitems[4]["details"].append("以下用户未设置合理的密码有效期:")
                    for username in sorted(set(missing_limit_users)):
                        info = per_user_rotation_info.get(username, {})
                        subitems[4]["details"].append(
                            f" - {self.summarize_rotation(username, info)}"
                        )
                    subitems[4]["recommendation"].append(
                        "请使用chage命令为上述账户配置密码有效期"
                    )
                if overdue_users:
                    subitems[4]["status"] = "FAIL"
                    subitems[4]["details"].append("以下用户密码已超过允许的有效期:")
                    for username in sorted(set(overdue_users)):
                        info = per_user_rotation_info.get(username, {})
                        subitems[4]["details"].append(
                            f" - {self.summarize_rotation(username, info)}"
                        )
                    subitems[4]["recommendation"].append("请立即通知相关用户修改密码")
                if subitems[4]["status"] == "PASS":
                    if login_users:
                        subitems[4]["details"].append(
                            "已核查以下登录账户的密码有效期:"
                        )
                        for username in sorted(login_users):
                            info = per_user_rotation_info.get(username, {})
                            subitems[4]["details"].append(
                                f" - {self.summarize_rotation(username, info)}"
                            )
                        subitems[4]["details"].append(
                            f"共核查 {len(login_users)} 个登录账户"
                        )
                    else:
                        subitems[4]["details"].append(
                            "系统未检出需要密码有效期控制的登录账户"
                        )
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
        faillock_policy_entries: List[Tuple[str, str, List[str]]] = []
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
                    module_name = (
                        "pam_faillock.so" if "pam_faillock.so" in stripped else "pam_tally2.so"
                    )
                    options = self.extract_pam_policy_tokens(stripped)
                    has_deny = any(token.startswith("deny=") for token in options)
                    has_unlock_or_flag = any(
                        token.startswith("unlock_time=") for token in options
                    ) or any(
                        token in {"even_deny_root", "even_deny_non_root"} for token in options
                    )
                    if has_deny and has_unlock_or_flag:
                        faillock_with_policy = True
                        faillock_policy_entries.append((pam_file, module_name, options))
        if faillock_lines:
            subitems[0]["details"].append("检测到登录失败处理模块")
            subitems[0]["details"].extend(faillock_lines)
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未在PAM配置中找到pam_faillock或pam_tally2模块")
            subitems[0]["recommendation"].append("请在/etc/pam.d/system-auth等文件中启用登录失败处理功能")

        if faillock_lines and faillock_with_policy:
            subitems[1]["details"].append("pam_faillock/pam_tally2已配置限制参数")
            for path, module, options in faillock_policy_entries:
                if options:
                    subitems[1]["details"].append(
                        f"{path}: {module} -> {', '.join(options)}"
                    )
                else:
                    subitems[1]["details"].append(f"{path}: {module} 已启用")
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
        observed_protocol_lines: List[str] = []
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

            if protocol_lines:
                observed_protocol_lines.extend(protocol_lines)

        running_insecure: List[str] = []
        service_observations: List[str] = []
        for service in INSECURE_REMOTE_SERVICES:
            rc, stdout, stderr = self.run_command(f"systemctl is-active {service}")
            output = stdout or stderr or f"返回码 {rc}"
            service_observations.append(f"{service}: {output}")
            if rc == 0 and stdout.strip() == 'active':
                running_insecure.append(service)
        if running_insecure:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("检测到明文远程管理服务运行: " + ", ".join(running_insecure))
            subitems[0]["recommendation"].append("请禁用telnet/rsh等明文协议，仅保留SSH等加密方式")
        elif subitems[0]["status"] == "PASS":
            subitems[0]["details"].append("未检测到telnet/rlogin等不安全远程服务运行")

        if observed_protocol_lines:
            subitems[0]["details"].append(
                "sshd_config中Protocol相关配置: " + "; ".join(observed_protocol_lines)
            )
        if service_observations:
            subitems[0]["details"].append(
                "systemctl is-active 检查结果: " + "; ".join(service_observations)
            )

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
        password_evidence: List[str] = []
        second_factor_evidence: List[str] = []

        for pam_file in pam_files:
            content = self.read_file(pam_file)
            if not content:
                continue
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or not stripped.lower().startswith('auth'):
                    continue
                matched_password = sorted(
                    {module for module in password_modules if module in stripped}
                )
                if matched_password:
                    has_password_module = True
                    password_evidence.append(
                        f"{pam_file}: {stripped} (匹配: {', '.join(matched_password)})"
                    )
                matched_second_factor = sorted(
                    {module for module in second_factor_modules if module in stripped}
                )
                if matched_second_factor:
                    has_second_factor = True
                    second_factor_evidence.append(
                        f"{pam_file}: {stripped} (匹配: {', '.join(matched_second_factor)})"
                    )

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
            subitems[1]["details"].append(
                f"已检测到{len(password_evidence)}条密码认证模块配置"
            )
            if password_evidence:
                subitems[1]["details"].append("密码认证配置明细:")
                subitems[1]["details"].extend(password_evidence)
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

        groups = {g.gr_gid: g.gr_name for g in grp.getgrall()}
        if login_users:
            subitems[0]["details"].append(
                f"已发现{len(login_users)}个具备交互登录权限的账户"
            )
        else:
            subitems[0]["details"].append("未发现具备交互登录权限的账户")
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

        if login_users:
            subitems[0]["details"].append("交互式账户详情 (/etc/passwd):")
            for user, entry in sorted(login_users.items()):
                group_name = groups.get(entry.pw_gid)
                if group_name:
                    group_display = f"{group_name} (GID={entry.pw_gid})"
                else:
                    group_display = f"GID={entry.pw_gid} (未找到组名)"
                subitems[0]["details"].append(
                    f"  - {user}: UID={entry.pw_uid}, 主组={group_display}, Shell={entry.pw_shell}, 家目录={entry.pw_dir}"
                )

        system_account_entries: List[pwd.struct_passwd] = []
        suspicious_accounts: List[str] = []
        for entry in pwd.getpwall():
            if entry.pw_uid < 1000 and entry.pw_name != 'root':
                system_account_entries.append(entry)
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

        if system_account_entries:
            subitems[1]["details"].append("默认账户Shell配置 (/etc/passwd):")
            for entry in sorted(system_account_entries, key=lambda item: (item.pw_uid, item.pw_name)):
                if entry.pw_shell in INTERACTIVE_SHELLS:
                    shell_state = "允许交互登录"
                else:
                    shell_state = "已禁用交互登录"
                subitems[1]["details"].append(
                    f"  - {entry.pw_name}: UID={entry.pw_uid}, Shell={entry.pw_shell}（{shell_state}）"
                )

        self.finalize_item(item, subitems)
    def check_ces1_06_default_account_management(self) -> None:
        item = "L3-CES1-06"
        subitems = [
            self.make_subitem("1. 应核查是否已经重命名默认账户或删除默认账户"),
            self.make_subitem("2. 应核查是否已修改默认账户的默认口令"),
        ]

        groups = {entry.gr_gid: entry.gr_name for entry in grp.getgrall()}

        uid_zero_entries = [entry for entry in pwd.getpwall() if entry.pw_uid == 0]
        uid_zero_accounts = [entry.pw_name for entry in uid_zero_entries]
        if len(uid_zero_entries) > 1:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("检测到多个UID为0的账户: " + ", ".join(sorted(uid_zero_accounts)))
            subitems[0]["recommendation"].append("请确认仅保留root账户或重命名/删除多余的UID0账户")
        else:
            subitems[0]["details"].append("仅存在一个UID为0的账户")

        if uid_zero_entries:
            subitems[0]["details"].append("UID 0 账户详情 (/etc/passwd):")
            for entry in sorted(uid_zero_entries, key=lambda item: item.pw_name):
                group_name = groups.get(entry.pw_gid)
                if group_name:
                    group_display = f"{group_name} (GID={entry.pw_gid})"
                else:
                    group_display = f"GID={entry.pw_gid}"
                subitems[0]["details"].append(
                    f"  - {entry.pw_name}: Shell={entry.pw_shell or '(未配置)'}, 主组={group_display}, 家目录={entry.pw_dir}, 描述={entry.pw_gecos or '(空)'}"
                )

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
        missing_defaults: List[str] = []
        default_account_details: List[str] = []

        for candidate in default_candidates:
            try:
                entry = pwd.getpwnam(candidate)
            except KeyError:
                missing_defaults.append(candidate)
                continue
            raw_shell = entry.pw_shell or ""
            shell = raw_shell or "(未配置)"
            group_name = groups.get(entry.pw_gid)
            if group_name:
                group_display = f"{group_name} (GID={entry.pw_gid})"
            else:
                group_display = f"GID={entry.pw_gid}"
            passwd_summary = (
                f"UID={entry.pw_uid}, 主组={group_display}, Shell={shell}, 家目录={entry.pw_dir}"
            )
            try:
                shadow = spwd.getspnam(candidate)
                password_field = shadow.sp_pwd
            except PermissionError as exc:
                unknown_defaults.append(f"{candidate}(无法读取shadow: {exc})")
                default_account_details.append(
                    f"  - {candidate}: {passwd_summary}, 口令状态=无法读取shadow: {exc}"
                )
                continue
            except KeyError:
                unknown_defaults.append(f"{candidate}(shadow记录缺失)")
                default_account_details.append(
                    f"  - {candidate}: {passwd_summary}, 口令状态=shadow记录缺失"
                )
                continue

            password_desc = self.describe_password_hash(password_field)
            default_account_details.append(
                f"  - {candidate}: {passwd_summary}, 口令状态={password_desc}"
            )
            locked = password_field in ('', '!', '*', '!!')
            if raw_shell in NOLOGIN_SHELLS or locked:
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
        if default_account_details:
            subitems[1]["details"].append("默认账户检查详情 (/etc/passwd + /etc/shadow):")
            subitems[1]["details"].extend(default_account_details)
        if missing_defaults:
            subitems[1]["details"].append("以下默认账户未在系统中找到: " + ", ".join(sorted(missing_defaults)))
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
        per_user_shadow_info: Dict[str, Dict[str, object]] = {}
        uid_map: Dict[int, List[str]] = {}
        for entry in login_users.values():
            uid_map.setdefault(entry.pw_uid, []).append(entry.pw_name)
        shared_accounts = {uid: names for uid, names in uid_map.items() if len(names) > 1}
        if shared_accounts:
            details = ", ".join(
                f"UID {uid}: {', '.join(sorted(names))}" for uid, names in shared_accounts.items()
            )
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("检测到共享账户: " + details)
            subitems[0]["recommendation"].append("请确保管理员账户实行一人一号，避免共享UID")
        else:
            subitems[0]["details"].append("未检测到共享UID的账户")

        if login_users:
            subitems[0]["details"].append("交互式账户清单及属性:")
            for username in sorted(login_users):
                entry = login_users[username]
                group_name = self.resolve_group_name(entry.pw_gid)
                subitems[0]["details"].append(
                    " - "
                    + f"{username}: UID {entry.pw_uid}, 主组 {group_name} (GID {entry.pw_gid}), 家目录 {entry.pw_dir}, Shell {entry.pw_shell}"
                )
            subitems[0]["details"].append(
                f"共计 {len(login_users)} 个交互式账户参与核查"
            )
        else:
            subitems[0]["details"].append("未检测到具备交互登录权限的账户")

        shadow_content = self.read_file('/etc/shadow')
        if shadow_content:
            now_days = self.days_since_epoch()
            expired_accounts: Set[str] = set()
            stale_accounts: Set[str] = set()
            locked_accounts: Set[str] = set()
            for line in shadow_content.splitlines():
                if not line or ':' not in line:
                    continue
                fields = line.split(':')
                username = fields[0]
                if username not in login_users:
                    continue
                info = per_user_shadow_info.setdefault(username, {})
                flags_list = info.setdefault("flags", [])
                expire_field = fields[7] if len(fields) > 7 else ''
                last_change = fields[2] if len(fields) > 2 else ''
                password_hash = fields[1] if len(fields) > 1 else ''
                info["password_summary"] = self.describe_password_hash(password_hash)
                stripped_hash = password_hash or ""
                locked_flag = False
                if stripped_hash == "" or stripped_hash in {'!', '*', '!!'} or stripped_hash.startswith('!'):
                    locked_flag = True
                    locked_accounts.add(username)
                info["locked"] = locked_flag

                last_change_value: Optional[int] = None
                if last_change:
                    try:
                        last_change_value = int(last_change)
                    except ValueError:
                        message = f"最后改密字段无法解析({last_change})"
                        if message not in flags_list:
                            flags_list.append(message)
                info["last_change_int"] = last_change_value
                if last_change_value and last_change_value > 0:
                    info["last_change_desc"] = self.describe_shadow_change(last_change_value, now_days)
                    days_since_change = max(0, now_days - last_change_value)
                    info["days_since_change"] = days_since_change
                    if days_since_change > 365:
                        stale_accounts.add(username)
                        message = f"距今 {days_since_change} 天未改密"
                        if message not in flags_list:
                            flags_list.append(message)
                else:
                    if not last_change:
                        if "缺少最后改密日期" not in flags_list:
                            flags_list.append("缺少最后改密日期")

                expire_value: Optional[int] = None
                if expire_field:
                    try:
                        expire_value = int(expire_field)
                    except ValueError:
                        message = f"口令到期字段无法解析({expire_field})"
                        if message not in flags_list:
                            flags_list.append(message)
                info["expire_int"] = expire_value
                if expire_value and expire_value > 0:
                    info["expire_desc"] = self.describe_shadow_expiry(expire_value, now_days)
                    delta = expire_value - now_days
                    info["days_until_expire"] = delta
                    if delta < 0:
                        expired_accounts.add(username)
                        message = f"口令已过期 {-delta} 天"
                        if message not in flags_list:
                            flags_list.append(message)
                elif expire_field:
                    message = f"口令到期字段值={expire_field}"
                    if message not in flags_list:
                        flags_list.append(message)

            for username in login_users:
                per_user_shadow_info.setdefault(username, {})

            if expired_accounts:
                subitems[0]["status"] = "FAIL"
                subitems[0]["details"].append("以下账户已过期:")
                for username in sorted(expired_accounts):
                    entry = login_users.get(username)
                    info = per_user_shadow_info.get(username, {})
                    subitems[0]["details"].append(
                        f" - {self.describe_account_overview(username, entry, info, now_days)}"
                    )
                subitems[0]["recommendation"].append("请清理或禁用上述过期账户")

            if stale_accounts:
                subitems[1]["status"] = "FAIL"
                subitems[1]["details"].append("以下账户超过一年未更改口令，需确认是否仍在使用:")
                for username in sorted(stale_accounts):
                    entry = login_users.get(username)
                    info = per_user_shadow_info.get(username, {})
                    subitems[1]["details"].append(
                        f" - {self.describe_account_overview(username, entry, info, now_days)}"
                    )
                subitems[1]["recommendation"].append("请核实并停用长期未使用的账户")

            if locked_accounts:
                subitems[1]["details"].append("已锁定的账户:")
                for username in sorted(locked_accounts):
                    entry = login_users.get(username)
                    info = per_user_shadow_info.get(username, {})
                    subitems[1]["details"].append(
                        f" - {self.describe_account_overview(username, entry, info, now_days)}"
                    )

            if not expired_accounts and not stale_accounts:
                if login_users:
                    subitems[1]["details"].append("未发现过期或长期未使用的账户，已核查以下口令状态:")
                    for username in sorted(login_users):
                        entry = login_users.get(username)
                        info = per_user_shadow_info.get(username, {})
                        subitems[1]["details"].append(
                            f" - {self.describe_account_overview(username, entry, info, now_days)}"
                        )
                    subitems[1]["details"].append(
                        f"共核查 {len(login_users)} 个账户"
                    )
                else:
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
            permissions = stat.S_IMODE(sudoers_stat.st_mode)
            permissions_str = format(permissions, "03o")
            if permissions_str != '440':
                subitems[2]["status"] = "FAIL"
                subitems[2]["details"].append(f"/etc/sudoers权限为{permissions_str}")
                subitems[2]["recommendation"].append("请将/etc/sudoers权限设置为440以防止未授权修改")
            else:
                owner = self.safe_getpwuid(sudoers_stat.st_uid)
                group = self.safe_getgrgid(sudoers_stat.st_gid)
                size = sudoers_stat.st_size
                mtime = datetime.fromtimestamp(sudoers_stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                subitems[2]["details"].append(
                    "/etc/sudoers权限符合440要求，具体信息: "
                    f"权限={permissions_str}, 所有者={owner}, 所属组={group}, 大小={size}字节, 修改时间={mtime}"
                )
        except FileNotFoundError:
            subitems[2]["status"] = "FAIL"
            subitems[2]["details"].append("未找到/etc/sudoers文件")
            subitems[2]["recommendation"].append("请确认sudo已安装并配置最小权限策略")

        self.finalize_item(item, subitems)
    def check_ces1_09_policy_configuration(self) -> None:
        item = "L3-CES1-09"
        subitems = [
            self.make_subitem("1. 应核查是否由授权主体负责配置访问控制策略"),
            self.make_subitem("2. 应核查授权主体是否依据安全策略配置访问规则"),
            self.make_subitem("3. 应测试验证用户是否有可越权访问情形"),
        ]

        for sub in subitems:
            sub["status"] = "UNKNOWN"
            sub["details"].append("该子项需通过访谈与人工验证完成，未自动化评估。")
        subitems[1]["details"].append("请对照安全策略与访问控制列表核查配置责任主体和审批记录。")
        subitems[2]["details"].append("建议选取敏感资源执行越权尝试，记录拦截和审计结果。")
        subitems[0]["details"].append(
            "检测步骤：1）访谈安全负责人确认授权主体名单；2）查阅变更/审批记录核实授权链路；3）截图留证形成佐证材料。"
        )
        subitems[1]["details"].append(
            "检测步骤：1）提取 ACL/策略配置，与安全策略逐条对照；2）记录发现的缺失规则；3）如有差异，标记为风险并提交整改。"
        )
        subitems[2]["details"].append(
            "检测步骤：1）选择敏感客体与高权限账号组合；2）以非授权主体尝试读/写/管理操作；3）保存日志/截图，评估是否存在越权。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_10_access_control_granularity(self) -> None:
        item = "L3-CES1-10"
        subitems = [
            self.make_subitem("应核查访问控制策略的控制粒度是否达到用户/进程-文件/表/字段级"),
        ]

        subitems[0]["status"] = "UNKNOWN"
        subitems[0]["details"].append("该子项需人工审阅权限模型与访问控制策略粒度。")
        subitems[0]["recommendation"].append(
            "请对照需求与数据分级，确认权限控制细化到用户或进程级、文件/表/字段级，并记录发现。"
        )
        subitems[0]["details"].append(
            "检测步骤：1）调阅系统/数据库权限矩阵，确认主体粒度是否到用户或进程级；2）抽查关键资源权限，核对是否细化到文件/表/字段；3）记录缺口并提出调整计划。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_11_security_labels(self) -> None:
        item = "L3-CES1-11"
        subitems = [
            self.make_subitem("1. 应核查是否对主体、客体设置了安全标记"),
            self.make_subitem("2. 应测试验证是否依据安全标记实施强制访问控制策略"),
        ]

        selinux_enabled = False
        selinux_enforcing = False
        selinux_mode_summary = ""
        selinux_fields: Dict[str, str] = {}
        rc, stdout, stderr = self.run_command('sestatus')
        if rc == 0:
            selinux_fields = self.parse_colon_key_values(stdout)
            status_value = selinux_fields.get("SELinux status", "").lower()
            current_mode = selinux_fields.get("Current mode", "")
            config_mode = selinux_fields.get("Mode from config file", "")
            if status_value == 'enabled':
                selinux_enabled = True
                subitems[0]["details"].append("检测到SELinux已启用")
            else:
                subitems[0]["status"] = "FAIL"
                subitems[0]["details"].append(
                    f"SELinux状态为: {selinux_fields.get('SELinux status', '未知')}"
                )
                subitems[0]["recommendation"].append("请启用SELinux并配置安全标记")

            relevant_keys = []
            for key in (
                "SELinux status",
                "Current mode",
                "Mode from config file",
                "Policy from config file",
            ):
                value = selinux_fields.get(key)
                if value:
                    relevant_keys.append(f"{key}: {value}")
            if relevant_keys:
                subitems[0]["details"].append(
                    "sestatus关键字段: " + "; ".join(relevant_keys)
                )

            if current_mode:
                selinux_mode_summary = f"SELinux当前模式: {current_mode}"
                if current_mode.lower() == 'enforcing':
                    selinux_enforcing = True
                    subitems[1]["details"].append("SELinux处于Enforcing模式")
                else:
                    subitems[1]["status"] = "FAIL"
                    subitems[1]["details"].append(
                        f"SELinux当前模式为{current_mode}"
                    )
                    if config_mode:
                        subitems[1]["details"].append(
                            f"配置文件中的模式为{config_mode}"
                        )
                    subitems[1]["recommendation"].append(
                        "请启用SELinux enforcing模式以落实强制访问控制"
                    )
            else:
                subitems[1]["status"] = "FAIL"
                status_label = selinux_fields.get('SELinux status') or '未知'
                subitems[1]["details"].append(
                    f"SELinux当前模式不可用（状态: {status_label})"
                )
                if config_mode:
                    subitems[1]["details"].append(
                        f"配置文件中的模式为{config_mode}"
                    )
                subitems[1]["recommendation"].append(
                    "请启用SELinux enforcing模式以落实强制访问控制"
                )
        else:
            error_text = (stderr or "").strip()
            lowered = error_text.lower()
            if rc == -1 or "not found" in lowered or "未找到" in lowered:
                subitems[0]["details"].append("未检测到sestatus命令，可能未安装SELinux组件")
            elif error_text:
                subitems[0]["details"].append(
                    f"sestatus命令返回错误: {error_text}"
                )
            else:
                subitems[0]["details"].append("sestatus命令执行未返回结果")

        selinux_config_path = '/etc/selinux/config'
        selinux_config = self.read_file(selinux_config_path)
        if selinux_config:
            config_lines: List[str] = []
            for raw_line in selinux_config.splitlines():
                stripped = raw_line.strip()
                if stripped.startswith('SELINUX='):
                    config_lines.append(stripped)
            if config_lines:
                subitems[0]["details"].append(
                    f"{selinux_config_path}设置: {', '.join(config_lines)}"
                )
        elif selinux_config is None:
            subitems[0]["details"].append(
                f"无法读取{selinux_config_path}，可能不存在或权限不足"
            )

        apparmor_available = False
        apparmor_enforcing = False
        apparmor_summary: List[str] = []
        rc, stdout, stderr = self.run_command('aa-status')
        if rc == 0:
            apparmor_available = True
            subitems[0]["details"].append("检测到AppArmor配置")
            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if 'profiles are in enforce mode' in stripped or 'profiles are in complain mode' in stripped:
                    apparmor_summary.append(stripped)
                if stripped.startswith('Enforced:') or stripped.startswith('Disabled:'):
                    apparmor_summary.append(stripped)
            if apparmor_summary:
                subitems[0]["details"].append(
                    "aa-status关键字段: " + "; ".join(apparmor_summary)
                )
            if any('profiles are in enforce mode' in entry and not entry.startswith('0') for entry in apparmor_summary):
                apparmor_enforcing = True
                subitems[1]["details"].append("AppArmor存在enforce模式的策略")
            elif 'profiles are in enforce mode' in stdout:
                match = re.search(r"(\d+) profiles are in enforce mode", stdout)
                if match and match.group(1) != '0':
                    apparmor_enforcing = True
                    subitems[1]["details"].append(
                        f"AppArmor enforce模式的策略数量: {match.group(1)}"
                    )
            if not apparmor_enforcing:
                subitems[0]["status"] = "FAIL"
                subitems[0]["details"].append("AppArmor未处于强制模式")
                subitems[0]["recommendation"].append(
                    "请将AppArmor配置为enforce模式以提供安全标记"
                )
        else:
            error_text = (stderr or "").strip()
            lowered = error_text.lower()
            if rc == -1 or "not found" in lowered or "未找到" in lowered:
                subitems[0]["details"].append("未检测到aa-status命令，系统可能未安装AppArmor")
            elif error_text:
                subitems[0]["details"].append(
                    f"aa-status返回错误信息: {error_text}"
                )
            else:
                subitems[0]["details"].append("aa-status未返回任何输出")

        if shutil.which('systemctl') is not None:
            rc, stdout, stderr = self.run_command('systemctl is-enabled apparmor')
            if rc == 0 and stdout:
                subitems[0]["details"].append(
                    f"systemctl is-enabled apparmor: {stdout.strip()}"
                )
            elif stderr:
                lowered = stderr.lower()
                if "no such file" in lowered or "not found" in lowered:
                    subitems[0]["details"].append(
                        "AppArmor systemd单元不存在（systemctl is-enabled apparmor）"
                    )
                else:
                    subitems[0]["details"].append(
                        f"systemctl is-enabled apparmor 输出: {stderr.strip()}"
                    )
            rc, stdout, stderr = self.run_command('systemctl is-active apparmor')
            if rc == 0 and stdout:
                subitems[0]["details"].append(
                    f"systemctl is-active apparmor: {stdout.strip()}"
                )
            elif stderr:
                lowered = stderr.lower()
                if "no such file" in lowered or "not found" in lowered:
                    subitems[0]["details"].append(
                        "AppArmor systemd单元不存在（systemctl is-active apparmor）"
                    )
                else:
                    subitems[0]["details"].append(
                        f"systemctl is-active apparmor 输出: {stderr.strip()}"
                    )

        if not selinux_enabled and not apparmor_available:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未检测到SELinux或AppArmor安全标记机制")
            subitems[0]["recommendation"].append("请启用SELinux或AppArmor以实现安全标记控制")

        if not selinux_enforcing and not apparmor_enforcing:
            subitems[1]["status"] = "FAIL"
            if not subitems[1]["details"]:
                subitems[1]["details"].append("未发现强制访问控制策略处于执行状态")
            else:
                enforcement_context: List[str] = []
                if selinux_mode_summary:
                    enforcement_context.append(selinux_mode_summary)
                if apparmor_summary:
                    enforcement_context.append(
                        "AppArmor摘要: " + "; ".join(apparmor_summary)
                    )
                if enforcement_context:
                    subitems[1]["details"].extend(enforcement_context)
            subitems[1]["recommendation"].append("请启用SELinux或AppArmor的强制模式以落实安全标记访问控制")

        self.finalize_item(item, subitems)
    def check_ces1_12_audit_enablement(self) -> None:
        item = "L3-CES1-12"
        subitems = [
            self.make_subitem("1. 应核查是否开启了安全审计功能"),
            self.make_subitem("2. 应核查安全审计范围是否覆盖到每个用户"),
            self.make_subitem("3. 应核查是否对重要的用户行为和重要安全事件进行审计"),
        ]

        rc, stdout, stderr = self.run_command('systemctl is-active auditd')
        auditd_status = stdout.strip()
        if auditd_status:
            subitems[0]["details"].append(
                f"systemctl is-active auditd: {auditd_status}"
            )
        elif stderr:
            subitems[0]["details"].append(
                f"systemctl is-active auditd 错误: {stderr}"
            )
        auditd_active = rc == 0 and auditd_status == 'active'

        rc, stdout, stderr = self.run_command('systemctl is-active rsyslog')
        rsyslog_status = stdout.strip()
        if rsyslog_status:
            subitems[0]["details"].append(
                f"systemctl is-active rsyslog: {rsyslog_status}"
            )
        elif stderr:
            subitems[0]["details"].append(
                f"systemctl is-active rsyslog 错误: {stderr}"
            )
        rsyslog_active = rc == 0 and rsyslog_status == 'active'

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

        if shutil.which('systemctl') is not None:
            rc, stdout, stderr = self.run_command('systemctl is-enabled auditd')
            if stdout:
                subitems[0]["details"].append(
                    f"systemctl is-enabled auditd: {stdout.strip()}"
                )
            elif stderr:
                subitems[0]["details"].append(
                    f"systemctl is-enabled auditd 错误: {stderr}"
                )

            rc, stdout, stderr = self.run_command('systemctl is-enabled rsyslog')
            if stdout:
                subitems[0]["details"].append(
                    f"systemctl is-enabled rsyslog: {stdout.strip()}"
                )
            elif stderr:
                subitems[0]["details"].append(
                    f"systemctl is-enabled rsyslog 错误: {stderr}"
                )

        rc, stdout, stderr = self.run_command('auditctl -l')
        if rc == 0:
            raw_lines = [line.strip() for line in stdout.splitlines() if line.strip()]
            meaningful_rules = [
                line for line in raw_lines if line.lower() != 'no rules'
            ]

            if meaningful_rules:
                subitems[1]["details"].append("检测到已加载的审计规则")
                for rule in meaningful_rules[:5]:
                    subitems[1]["details"].append(f"auditctl规则: {rule}")
                if len(meaningful_rules) > 5:
                    subitems[1]["details"].append(
                        f"...共{len(meaningful_rules)}条规则"
                    )
            else:
                subitems[1]["status"] = "FAIL"
                if raw_lines:
                    subitems[1]["details"].append(
                        "auditctl -l 输出: " + "; ".join(raw_lines)
                    )
                else:
                    subitems[1]["details"].append("未发现已加载的审计规则")
                subitems[1]["recommendation"].append(
                    "请配置/etc/audit/rules.d/*.rules确保覆盖所有用户活动"
                )
        else:
            subitems[1]["status"] = "FAIL"
            if stdout:
                subitems[1]["details"].append(f"auditctl -l 输出: {stdout}")
            if stderr:
                subitems[1]["details"].append(f"auditctl -l 错误: {stderr}")
            if not stdout and not stderr:
                subitems[1]["details"].append("未发现已加载的审计规则")
            subitems[1]["recommendation"].append(
                "请配置/etc/audit/rules.d/*.rules确保覆盖所有用户活动"
            )

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
        reviewed_logs: List[str] = []
        missing_logs: List[str] = []
        for log in log_files:
            if not os.path.exists(log):
                missing_logs.append(log)
                continue
            try:
                stat_result = os.stat(log)
            except OSError as exc:
                permission_issues.append(f"无法获取{log}权限: {exc}")
                continue

            mode = stat.S_IMODE(stat_result.st_mode)
            owner = self.safe_getpwuid(stat_result.st_uid)
            group = self.safe_getgrgid(stat_result.st_gid)
            size = stat_result.st_size
            mtime = datetime.fromtimestamp(stat_result.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            detail = (
                f"{log}: 权限={mode:03o}, 所有者={owner}, 组={group}, 大小={size}B, 修改时间={mtime}"
            )
            reviewed_logs.append(detail)

            if mode & 0o007:
                permission_issues.append(f"{detail} (包含other权限)")
            elif mode & 0o020:
                permission_issues.append(f"{detail} (组具有写权限)")

        if reviewed_logs:
            subitems[0]["details"].append("审计日志文件权限核查结果:")
            subitems[0]["details"].extend(reviewed_logs)
        if missing_logs:
            joined_missing = ", ".join(missing_logs)
            subitems[0]["details"].append(
                "发行版特定日志在本系统中未提供（已跳过）：" + joined_missing
            )

        if permission_issues:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("存在权限过宽的日志文件:")
            subitems[0]["details"].extend(permission_issues)
            subitems[0]["recommendation"].append("请将重要日志权限设置为640或更严格，并限制其他用户访问")
        elif reviewed_logs:
            subitems[0]["details"].append("所有已找到的审计日志文件权限均满足最小化要求")

        logrotate_sources: List[str] = ['/etc/logrotate.conf']
        logrotate_dir = '/etc/logrotate.d'
        if os.path.isdir(logrotate_dir):
            for entry in sorted(os.listdir(logrotate_dir)):
                logrotate_sources.append(os.path.join(logrotate_dir, entry))

        rotate_detected = False
        compress_detected = False
        readable_configs = False
        for config_path in logrotate_sources:
            content = self.read_file(config_path)
            if content is None:
                subitems[1]["details"].append(f"未能读取{config_path}")
                continue

            readable_configs = True
            rotate_matches = sorted(set(re.findall(r"rotate\s+\d+", content)))
            frequency_matches = sorted(
                set(re.findall(r"\b(hourly|daily|weekly|monthly|yearly)\b", content))
            )
            compress_present = bool(re.search(r"^\s*compress\b", content, re.MULTILINE))
            detail_parts: List[str] = []
            if rotate_matches:
                rotate_detected = True
                detail_parts.append("轮转保留设置=" + ", ".join(rotate_matches))
            else:
                detail_parts.append("未显式声明rotate保留设置（可能继承全局策略）")
            if frequency_matches:
                detail_parts.append("执行频率=" + "/".join(frequency_matches))
            else:
                detail_parts.append("未指定轮转频率")
            if compress_present:
                compress_detected = True
                detail_parts.append("启用compress")
            else:
                detail_parts.append("未启用compress")

            subitems[1]["details"].append(f"{config_path}: " + "; ".join(detail_parts))

        if not rotate_detected:
            subitems[1]["status"] = "FAIL"
            if readable_configs:
                subitems[1]["details"].append("未在已读取的配置中找到rotate参数")
            else:
                subitems[1]["details"].append("未读取到任何日志轮转配置文件")
            subitems[1]["recommendation"].append("请配置/etc/logrotate.conf或/etc/logrotate.d/确保日志定期归档")
        elif not compress_detected:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("已配置轮转但未启用日志压缩")
            subitems[1]["recommendation"].append("建议在日志轮转策略中启用compress并结合离线备份")
        else:
            subitems[1]["details"].append("日志轮转配置包含保留策略并已启用压缩归档")

        self.finalize_item(item, subitems)
    def check_ces1_15_audit_process_protection(self) -> None:
        item = "L3-CES1-15"
        subitems = [
            self.make_subitem("应测试验证审计进程是否受到保护，防止未经授权中断"),
        ]

        subitems[0]["status"] = "UNKNOWN"
        subitems[0]["details"].append("该检查需通过非审计管理员账户执行中断测试，暂未自动化。")
        subitems[0]["recommendation"].append(
            "请模拟停止 auditd/rsyslog 等审计服务，确认权限或保护策略能够阻止未授权中断。"
        )
        subitems[0]["details"].append(
            "检测步骤：1）列出审计进程与 systemd 单元；2）使用普通账号执行 systemctl stop/kill，观察是否被拒绝；3）查看日志确认拦截记录并截图存档。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_17_minimal_installation(self) -> None:
        item = "L3-CES1-17"
        subitems = [
            self.make_subitem("1. 应核查是否遵循最小安装原则"),
            self.make_subitem("2. 应核查是否未安装非必要的组件和应用程序"),
        ]

        unwanted_packages = [
            "telnet",
            "telnetd",
            "rsh",
            "rsh-server",
            "ypbind",
            "ypserv",
            "xinetd",
            "tftp",
            "vsftpd",
            "samba",
            "cifs-utils",
            "xorg-x11-server-Xorg",
        ]

        manager = self.package_manager or self.detect_package_manager()
        package_manager_detected = manager is not None
        if manager:
            self.package_manager = manager
            subitems[0]["details"].append(
                f"检测到包管理器: {manager}"
            )
            distribution = self.os_info.get("distribution")
            if distribution:
                subitems[0]["details"].append(
                    f"目标操作系统: {distribution}"
                )

        package_states: List[Tuple[str, bool]] = []
        detected_packages: List[str] = []
        for package in unwanted_packages:
            installed = self.is_package_installed(package)
            if installed is None:
                continue
            package_manager_detected = True
            package_states.append((package, installed))
            if installed:
                detected_packages.append(package)

        if package_states:
            formatted_states: List[str] = []
            for package, installed in package_states:
                if installed:
                    description = self.describe_package_installation(package)
                    if description and description != package:
                        formatted_states.append(f"{package}: 已安装 ({description})")
                    else:
                        formatted_states.append(f"{package}: 已安装")
                else:
                    formatted_states.append(f"{package}: 未安装")
            subitems[0]["details"].append(
                "核查组件状态: " + "; ".join(formatted_states)
            )

        if package_manager_detected:
            subitems[0]["details"].append("已通过包管理器核查最小化安装状态")
        else:
            subitems[0]["status"] = "ERROR"
            subitems[0]["details"].append(
                "无法确定包管理器状态，请人工确认最小安装原则执行情况"
            )

        if detected_packages:
            installed_details: List[str] = []
            for package in sorted(set(detected_packages)):
                description = self.describe_package_installation(package)
                installed_details.append(description or package)
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append(
                "检测到可能非必要的组件 (含版本信息): "
                + "; ".join(installed_details)
            )
            subitems[1]["recommendation"].append("请根据系统角色评估并卸载非必要组件")
        elif package_manager_detected and package_states:
            absent_components = [
                package for package, installed in package_states if not installed
            ]
            if absent_components:
                subitems[1]["details"].append(
                    "已确认以下常见组件未安装: "
                    + ", ".join(sorted(absent_components))
                )
            subitems[1]["details"].append(
                "未检测到常见的非必要组件，符合最小化安装原则"
            )
        elif package_manager_detected:
            subitems[1]["details"].append(
                "未检测到常见的非必要组件，符合最小化安装原则"
            )
        else:
            subitems[1]["details"].append(
                "未能识别包管理器，需人工核查已安装组件"
            )

        self.finalize_item(item, subitems)
    def check_ces1_18_service_port_control(self) -> None:
        item = "L3-CES1-18"
        subitems = [
            self.make_subitem("1. 应核查是否关闭了非必要的系统服务和默认共享"),
            self.make_subitem("2. 应核查是否不存在非必要的高危端口"),
        ]

        running_services: List[str] = []
        running_service_details: List[str] = []
        service_listing_source = ""
        service_listing_note: Optional[str] = None
        service_errors: List[str] = []

        def record_service_error(command: str, stderr_output: str) -> None:
            message = stderr_output.strip() if stderr_output else "命令无输出"
            service_errors.append(f"{command}: {message}")

        systemctl_command = (
            'systemctl list-units --type=service --state=running --no-legend'
        )
        rc, stdout, stderr = self.run_command(systemctl_command)
        if rc == 0 and stdout:
            service_listing_source = systemctl_command
            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                parts = line.split(None, 4)
                service_name = parts[0]
                description = parts[4] if len(parts) > 4 else ''
                display = service_name
                if description:
                    display = f"{service_name} - {description}"
                running_service_details.append(display)
                if service_name.endswith('.service'):
                    base = service_name[:-8]
                else:
                    base = service_name
                if base in UNNECESSARY_SERVICES:
                    running_services.append(base)
        else:
            record_service_error(systemctl_command, stderr)

        if not running_service_details:
            service_command = 'service --status-all'
            rc, stdout, stderr = self.run_command(service_command)
            if rc == 0 and stdout:
                service_listing_source = service_command
                found_running = False
                for raw_line in stdout.splitlines():
                    stripped = raw_line.strip()
                    if not stripped or not stripped.startswith('['):
                        continue
                    parts = stripped.split(']', 1)
                    if len(parts) != 2:
                        continue
                    status_token = parts[0]
                    name = parts[1].strip()
                    if not name:
                        continue
                    if '+' in status_token:
                        found_running = True
                        running_service_details.append(name)
                        base = name[:-8] if name.endswith('.service') else name
                        if base in UNNECESSARY_SERVICES:
                            running_services.append(base)
                if not found_running:
                    service_listing_note = (
                        f"{service_command} 输出未标记任何正在运行的服务"
                    )
            else:
                record_service_error(service_command, stderr)

        service_data_available = bool(running_service_details)
        if not service_data_available and service_listing_note:
            service_data_available = True

        if running_service_details:
            source_label = service_listing_source or "服务列表"
            subitems[0]["details"].append(
                f"当前运行服务清单 ({source_label} 输出):"
            )
            subitems[0]["details"].extend(
                f" - {detail}" for detail in running_service_details
            )
        elif service_listing_note:
            subitems[0]["details"].append(service_listing_note)
        else:
            for error in service_errors or ["未能获取运行服务列表"]:
                subitems[0]["details"].append(f"无法列出运行服务: {error}")

        if running_services:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append(
                "发现运行中的不必要服务: " + ", ".join(sorted(set(running_services)))
            )
            subitems[0]["recommendation"].append(
                "请使用systemctl disable --now <service>停用相关服务"
            )
        elif service_data_available:
            subitems[0]["details"].append("未检测到运行中的高危服务")

        listening_ports: List[str] = []
        listener_details: List[str] = []
        listener_command_used = ""
        port_errors: List[str] = []

        def record_port_error(command: str, stderr_output: str) -> None:
            message = stderr_output.strip() if stderr_output else "命令无输出"
            port_errors.append(f"{command}: {message}")

        def register_listener(proto: str, local: str, state: str) -> None:
            detail = f"{proto} {local}"
            if state:
                detail += f" 状态={state}"
            listener_details.append(detail)
            port_value = extract_port(local)
            if port_value is not None and port_value in HIGH_RISK_PORTS:
                listening_ports.append(
                    f"端口{port_value}({HIGH_RISK_PORTS[port_value]})"
                )

        def extract_port(local: str) -> Optional[int]:
            if ':' not in local:
                return None
            port_segment = local.rsplit(':', 1)[-1]
            try:
                return int(port_segment)
            except ValueError:
                if ']:' in local:
                    try:
                        return int(local.rsplit(']:', 1)[-1])
                    except ValueError:
                        return None
                return None

        rc, stdout, stderr = self.run_command('ss -tuln')
        if rc == 0 and stdout:
            listener_command_used = 'ss -tuln'
            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if not line or line.lower().startswith('netid'):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                proto = parts[0]
                state = parts[1]
                local = parts[4]
                register_listener(proto, local, state)
        else:
            record_port_error('ss -tuln', stderr)

        if not listener_details:
            rc, stdout, stderr = self.run_command('netstat -tuln')
            if rc == 0 and stdout:
                listener_command_used = 'netstat -tuln'
                for raw_line in stdout.splitlines():
                    line = raw_line.strip()
                    if not line or line.lower().startswith('proto'):
                        continue
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    proto = parts[0]
                    local = parts[3]
                    state = parts[5] if len(parts) > 5 else ''
                    register_listener(proto, local, state)
            else:
                record_port_error('netstat -tuln', stderr)

        if not listener_details:
            tcp_states = {
                '01': 'ESTABLISHED',
                '02': 'SYN_SENT',
                '03': 'SYN_RECV',
                '04': 'FIN_WAIT1',
                '05': 'FIN_WAIT2',
                '06': 'TIME_WAIT',
                '07': 'CLOSE',
                '08': 'CLOSE_WAIT',
                '09': 'LAST_ACK',
                '0A': 'LISTEN',
                '0B': 'CLOSING',
            }

            def parse_proc_net(protocol: str) -> List[Tuple[str, str, str]]:
                path = f"/proc/net/{protocol}"
                content = self.read_file(path)
                if not content:
                    return []
                entries: List[Tuple[str, str, str]] = []
                for raw_line in content.splitlines()[1:]:
                    parts = raw_line.split()
                    if len(parts) < 2:
                        continue
                    local_field = parts[1]
                    state_field = parts[3] if len(parts) > 3 else ''
                    if ':' not in local_field:
                        continue
                    ip_hex, port_hex = local_field.split(':', 1)
                    try:
                        port_value = int(port_hex, 16)
                    except ValueError:
                        continue
                    if port_value == 0:
                        continue
                    try:
                        if protocol.endswith('6'):
                            raw_bytes = bytes.fromhex(ip_hex)
                            if len(raw_bytes) == 16:
                                reordered = b"".join(
                                    raw_bytes[i : i + 4][::-1]
                                    for i in range(0, 16, 4)
                                )
                            else:
                                reordered = raw_bytes
                            ip_address = socket.inet_ntop(
                                socket.AF_INET6, reordered
                            )
                        else:
                            ip_address = socket.inet_ntop(
                                socket.AF_INET, struct.pack('<I', int(ip_hex, 16))
                            )
                    except Exception:  # pylint: disable=broad-except
                        ip_address = ip_hex
                    state_name = tcp_states.get(state_field.upper(), state_field.upper())
                    entries.append((protocol, f"{ip_address}:{port_value}", state_name))
                return entries

            proc_entries: List[Tuple[str, str, str]] = []
            for proto in ('tcp', 'tcp6', 'udp', 'udp6'):
                proc_entries.extend(parse_proc_net(proto))
            if proc_entries:
                listener_command_used = '/proc/net'
                for proto, local, state in proc_entries:
                    register_listener(proto, local, state)
            else:
                port_errors.append('/proc/net: 未能读取内核网络套接字信息')

        port_data_available = bool(listener_details)
        if port_data_available:
            source_label = listener_command_used or '监听端口列表'
            subitems[1]["details"].append(
                f"监听端口清单 ({source_label} 输出):"
            )
            subitems[1]["details"].extend(
                f" - {entry}" for entry in listener_details
            )
        else:
            for error in port_errors or ["未能获取监听端口信息"]:
                subitems[1]["details"].append(f"无法列出监听端口: {error}")

        if listening_ports:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append(
                "检测到高危监听端口: " + ", ".join(sorted(set(listening_ports)))
            )
            subitems[1]["recommendation"].append("请关闭检测到的高危端口")
        elif port_data_available:
            subitems[1]["details"].append("未发现高危监听端口")

        self.finalize_item(item, subitems)
    def check_ces1_19_management_access_control(self) -> None:
        item = "L3-CES1-19"
        subitems = [
            self.make_subitem("应核查配置是否限制管理终端接入方式或来源地址"),
        ]

        ssh_config = self.read_file('/etc/ssh/sshd_config')
        restrictions_found: List[str] = []
        allow_directives: List[str] = []
        deny_directives: List[str] = []
        match_directives: List[str] = []
        listen_directives: List[str] = []
        if ssh_config:
            for line in ssh_config.splitlines():
                cleaned = line.split('#', 1)[0].strip()
                if not cleaned:
                    continue
                lower = cleaned.lower()
                if lower.startswith('allowusers') or lower.startswith('allowgroups'):
                    allow_directives.append(cleaned)
                    restrictions_found.append(cleaned)
                elif lower.startswith('denyusers') or lower.startswith('denygroups'):
                    deny_directives.append(cleaned)
                    restrictions_found.append(cleaned)
                elif lower.startswith('match') and 'address' in lower:
                    match_directives.append(cleaned)
                    restrictions_found.append(cleaned)
                elif lower.startswith('listenaddress'):
                    listen_directives.append(cleaned)
                    if '0.0.0.0' not in lower and '::' not in lower:
                        restrictions_found.append(cleaned)
        else:
            subitems[0]["details"].append("无法读取/etc/ssh/sshd_config，无法确认SSH源限制配置")

        if restrictions_found:
            subitems[0]["details"].append("SSH配置已对管理源进行限制:")
            subitems[0]["details"].extend(f" - {line}" for line in restrictions_found)
        else:
            if ssh_config:
                if listen_directives:
                    subitems[0]["details"].append("sshd_config监听地址配置:")
                    subitems[0]["details"].extend(
                        f" - {line}" for line in listen_directives
                    )
                else:
                    subitems[0]["details"].append(
                        "sshd_config未显式设置ListenAddress（默认监听所有地址）"
                    )
                if not (allow_directives or deny_directives or match_directives):
                    subitems[0]["details"].append(
                        "未配置AllowUsers/AllowGroups/DenyUsers/DenyGroups/Match Address指令"
                    )

        firewall_evidence: List[str] = []
        firewall_notes: List[str] = []
        rc, stdout, stderr = self.run_command('firewall-cmd --list-sources')
        if rc == 0 and stdout:
            firewall_evidence.append("firewalld允许的源:")
            firewall_evidence.extend(
                f" - {entry.strip()}" for entry in stdout.splitlines() if entry.strip()
            )
        elif rc == 0:
            firewall_notes.append("firewalld未配置特定源地址限制（返回空列表）")
        else:
            message = stderr or stdout
            if message:
                firewall_notes.append(
                    f"firewall-cmd --list-sources 返回错误信息: {message.strip()}"
                )
            else:
                firewall_notes.append(
                    "firewall-cmd --list-sources 未能提供允许的源地址信息"
                )

        if not firewall_evidence:
            rc, stdout, stderr = self.run_command('iptables -S INPUT')
            if rc == 0 and stdout:
                restricted_rules = [line for line in stdout.splitlines() if '-s' in line]
                if restricted_rules:
                    firewall_evidence.append("iptables源地址限制规则:")
                    firewall_evidence.extend(
                        f" - {line}" for line in restricted_rules[:5]
                    )
                else:
                    firewall_notes.append(
                        "iptables INPUT 链未检测到包含-s参数的源地址限制规则"
                    )
            elif rc != 0:
                message = stderr or stdout
                if message:
                    firewall_notes.append(
                        f"iptables -S INPUT 返回错误信息: {message.strip()}"
                    )
                else:
                    firewall_notes.append(
                        "iptables -S INPUT 未能提供源地址限制规则"
                    )

        if firewall_evidence:
            subitems[0]["details"].extend(firewall_evidence)
        if firewall_notes:
            subitems[0]["details"].extend(firewall_notes)

        if not restrictions_found and not firewall_evidence:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未检测到SSH或防火墙对管理终端来源的限制")
            subitems[0]["recommendation"].append("请使用AllowUsers/防火墙策略限制可访问的管理终端")

        self.finalize_item(item, subitems)
    def check_ces1_20_input_validation(self) -> None:
        item = "L3-CES1-20"
        subitems = [
            self.make_subitem("1. 应核查设计中是否包含数据有效性检验功能"),
            self.make_subitem("2. 应测试验证接口输入是否进行有效性校验"),
        ]

        for index, message in enumerate(
            [
                "请审阅设计/需求文档，确认数据有效性校验模块覆盖人机接口与通信接口。",
                "需通过手工或自动化测试提交异常输入，验证系统是否拦截或提示错误。",
            ]
        ):
            subitems[index]["status"] = "UNKNOWN"
            subitems[index]["details"].append(message)
        subitems[0]["details"].append(
            "检测步骤：1）获取接口列表与字段校验规则；2）核查是否存在必填、长度、格式、白名单/黑名单校验；3）记录未覆盖的字段并建议补充。"
        )
        subitems[1]["details"].append(
            "检测步骤：1）准备越界、恶意字符、空值等测试用例；2）对人机界面和 API 逐项提交，观察返回码与日志；3）形成测试记录，标记未拦截的情形。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_21_vulnerability_management(self) -> None:
        item = "L3-CES1-21"
        subitems = [
            self.make_subitem("1. 应核查是否不存在高风险漏洞"),
            self.make_subitem("2. 应核查漏洞是否经过测试评估后及时修补"),
        ]

        subitems[0]["status"] = "UNKNOWN"
        subitems[0]["details"].append("需要运行漏洞扫描/渗透测试并人工确认结果，未自动化。")
        subitems[1]["status"] = "UNKNOWN"
        subitems[1]["details"].append("请检查补丁管理流程与变更记录，核实修补时效与验证。")
        subitems[0]["details"].append(
            "检测步骤：1）使用合规授权的扫描工具对目标资产执行高危漏洞扫描；2）导出报告并筛选高危/严重项；3）与资产负责人确认漏洞真实性并记录。"
        )
        subitems[1]["details"].append(
            "检测步骤：1）查阅补丁/变更工单与实施记录，核对修复时间是否满足策略；2）在测试/生产复扫验证漏洞关闭；3）记录未修复或延期原因。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_22_intrusion_detection_alerts(self) -> None:
        item = "L3-CES1-22"
        subitems = [
            self.make_subitem("1. 应核查是否有入侵检测的措施"),
            self.make_subitem("2. 应核查发生严重入侵事件时是否提供报警"),
        ]

        for sub in subitems:
            sub["status"] = "UNKNOWN"
            sub["details"].append("需要访谈与告警演练验证，暂未自动化。")
        subitems[1]["details"].append("请模拟入侵事件验证告警通道与响应流程。")
        subitems[0]["details"].append(
            "检测步骤：1）盘点现有 IDS/IPS/EDR/主机防护部署；2）核查策略更新时间与覆盖资产清单；3）截取告警面板或配置作为证据。"
        )
        subitems[1]["details"].append(
            "检测步骤：1）模拟端口扫描/暴力破解等事件；2）确认是否产生告警并能送达安全团队；3）记录告警内容、响应时间与处置结果。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_23_malware_protection(self) -> None:
        item = "L3-CES1-23"
        subitems = [
            self.make_subitem("1. 应核查是否安装并定期更新防恶意代码软件"),
            self.make_subitem("2. 应核查是否采用主动免疫可信验证技术及时识别入侵"),
            self.make_subitem("3. 应核查识别恶意行为时是否能够有效阻断"),
        ]

        antivirus_candidates = [
            {
                "command": "clamscan",
                "description": "ClamAV病毒扫描器",
                "packages": ["clamav", "clamav-base", "clamav-daemon"],
            },
            {
                "command": "freshclam",
                "description": "ClamAV病毒库更新",
                "packages": ["clamav", "clamav-freshclam"],
            },
            {
                "command": "maldet",
                "description": "Maldet恶意代码检测",
                "packages": ["maldet"],
            },
            {
                "command": "chkrootkit",
                "description": "Chkrootkit根kit检测",
                "packages": ["chkrootkit"],
            },
            {
                "command": "rkhunter",
                "description": "Rootkit Hunter检测",
                "packages": ["rkhunter"],
            },
        ]

        detected_antivirus: List[str] = []
        missing_antivirus: List[str] = []
        inspected_antivirus: List[str] = []

        for candidate in antivirus_candidates:
            command = candidate["command"]
            description = candidate["description"]
            inspected_antivirus.append(f"{description} ({command})")

            path = shutil.which(command)
            package_summaries: List[str] = []
            for package in candidate.get("packages", []):
                summary = self.describe_package_installation(package)
                if summary and summary not in package_summaries:
                    package_summaries.append(summary)

            detail_parts = [f"{description} ({command})"]
            if path:
                detail_parts.append(f"路径={path}")
            if package_summaries:
                detail_parts.append("包信息: " + "; ".join(package_summaries))

            if path or package_summaries:
                detected_antivirus.append(", ".join(detail_parts))
            else:
                missing_antivirus.append(f"{description} ({command})")

        if detected_antivirus:
            subitems[0]["details"].append("检测到防恶意代码工具清单:")
            subitems[0]["details"].extend(detected_antivirus)
        else:
            subitems[0]["status"] = "FAIL"
            subitems[0]["details"].append("未检测到常见的恶意代码防护工具")
            if inspected_antivirus:
                subitems[0]["details"].append(
                    "已检查的候选工具: " + ", ".join(inspected_antivirus)
                )
            subitems[0]["recommendation"].append(
                "请部署ClamAV、商业杀毒或可信验证机制，并定期更新病毒库"
            )

        integrity_candidates = [
            {
                "command": "aide",
                "description": "AIDE完整性检查",
                "packages": ["aide"],
            },
            {
                "command": "tripwire",
                "description": "Tripwire完整性监控",
                "packages": ["tripwire"],
            },
            {
                "command": "samhain",
                "description": "Samhain完整性监控",
                "packages": ["samhain"],
            },
        ]

        detected_integrity: List[str] = []
        missing_integrity: List[str] = []
        inspected_integrity: List[str] = []

        for candidate in integrity_candidates:
            command = candidate["command"]
            description = candidate["description"]
            inspected_integrity.append(f"{description} ({command})")

            path = shutil.which(command)
            package_summaries: List[str] = []
            for package in candidate.get("packages", []):
                summary = self.describe_package_installation(package)
                if summary and summary not in package_summaries:
                    package_summaries.append(summary)

            detail_parts = [f"{description} ({command})"]
            if path:
                detail_parts.append(f"路径={path}")
            if package_summaries:
                detail_parts.append("包信息: " + "; ".join(package_summaries))

            if path or package_summaries:
                detected_integrity.append(", ".join(detail_parts))
            else:
                missing_integrity.append(f"{description} ({command})")

        if detected_integrity:
            subitems[1]["details"].append("检测到主动免疫/可信验证工具:")
            subitems[1]["details"].extend(detected_integrity)
        else:
            subitems[1]["status"] = "FAIL"
            subitems[1]["details"].append("未检测到AIDE/Tripwire等可信验证技术")
            if inspected_integrity:
                subitems[1]["details"].append(
                    "已检查的候选工具: " + ", ".join(inspected_integrity)
                )
            subitems[1]["recommendation"].append(
                "建议部署AIDE、Tripwire等完整性监控以提升主动免疫能力"
            )

        service_names = [
            "clamd",
            "clamav-daemon",
            "freshclam",
            "maldet",
            "rkhunter",
            "chkrootkit",
        ]
        systemctl_available = shutil.which("systemctl") is not None
        service_cmd = shutil.which("service")
        active_services: List[str] = []
        service_details: List[str] = []
        missing_services: List[str] = []
        systemd_error_message: Optional[str] = None

        for service in service_names:
            status_fragments: List[str] = []
            service_missing = False
            systemd_failed = False

            if systemctl_available:
                rc_active, stdout_active, stderr_active = self.run_command(
                    f"systemctl is-active {service}"
                )
                if rc_active == 0:
                    if stdout_active:
                        status_fragments.append(
                            f"systemctl is-active={stdout_active.strip()}"
                        )
                        if stdout_active.strip() == "active":
                            active_services.append(service)
                    else:
                        status_fragments.append("systemctl is-active=无输出")
                else:
                    message = (stderr_active or stdout_active or f"返回码 {rc_active}").strip()
                    if self.message_indicates_systemd_unavailable(message):
                        systemd_error_message = systemd_error_message or message
                        systemctl_available = False
                        systemd_failed = True
                    elif self.message_indicates_missing_service(message):
                        service_missing = True
                    elif stdout_active.strip():
                        status_fragments.append(
                            f"systemctl is-active={stdout_active.strip()}"
                        )
                    else:
                        summary = self.summarise_command_output(
                            message, max_lines=2, max_chars=200
                        )
                        status_fragments.append(
                            f"systemctl is-active 输出: {summary or message}"
                        )

                if not systemd_failed and not service_missing:
                    rc_enabled, stdout_enabled, stderr_enabled = self.run_command(
                        f"systemctl is-enabled {service}"
                    )
                    if rc_enabled == 0 and stdout_enabled:
                        status_fragments.append(
                            f"systemctl is-enabled={stdout_enabled.strip()}"
                        )
                    elif rc_enabled != 0:
                        message = (stderr_enabled or stdout_enabled or f"返回码 {rc_enabled}").strip()
                        if self.message_indicates_systemd_unavailable(message):
                            systemd_error_message = systemd_error_message or message
                            systemctl_available = False
                            systemd_failed = True
                        elif self.message_indicates_missing_service(message):
                            service_missing = True
                        elif stdout_enabled.strip():
                            status_fragments.append(
                                f"systemctl is-enabled={stdout_enabled.strip()}"
                            )
                        else:
                            summary = self.summarise_command_output(
                                message, max_lines=2, max_chars=200
                            )
                            status_fragments.append(
                                f"systemctl is-enabled 输出: {summary or message}"
                            )

            if (not systemctl_available or systemd_failed) and service_cmd and not service_missing:
                rc_service, stdout_service, stderr_service = self.run_command(
                    f"service {service} status"
                )
                if rc_service == 0:
                    summary = self.summarise_command_output(stdout_service)
                    status_fragments.append(
                        f"service status 正常: {summary or '命令无输出'}"
                    )
                else:
                    message = (stderr_service or stdout_service or f"返回码 {rc_service}").strip()
                    if self.message_indicates_missing_service(message):
                        service_missing = True
                    else:
                        summary = self.summarise_command_output(
                            message, max_lines=2, max_chars=200
                        )
                        status_fragments.append(
                            f"service status 输出: {summary or message}"
                        )

            if service_missing:
                missing_services.append(service)
                continue

            if status_fragments:
                service_details.append(f"{service}: " + "; ".join(status_fragments))

        if active_services:
            subitems[2]["details"].append(
                "恶意代码防护服务正在运行: " + ", ".join(sorted(set(active_services)))
            )
        else:
            subitems[2]["status"] = "FAIL"
            subitems[2]["details"].append("未检测到活跃的恶意代码防护服务")
            subitems[2]["recommendation"].append(
                "请启动病毒查杀服务或配置实时监控以便及时阻断恶意行为"
            )

        if missing_services:
            subitems[2]["details"].append(
                "未发现以下恶意代码防护服务单元: "
                + ", ".join(sorted(set(missing_services)))
            )

        if systemd_error_message:
            summary = self.summarise_command_output(
                systemd_error_message, max_lines=2, max_chars=200
            )
            subitems[2]["details"].append(
                "systemctl 状态查询不可用: " + (summary or systemd_error_message)
            )

        if service_details:
            subitems[2]["details"].append("恶意代码防护服务状态记录:")
            subitems[2]["details"].extend(service_details)

        self.finalize_item(item, subitems)
    def check_ces1_24_trusted_verification(self) -> None:
        item = "L3-CES1-24"
        subitems = [
            self.make_subitem("1. 应核查是否基于可信根进行系统引导和关键组件可信验证"),
            self.make_subitem("2. 应核查是否在关键执行环节进行动态可信验证"),
            self.make_subitem("3. 应测试验证可信性被破坏时是否报警"),
            self.make_subitem("4. 应测试验证是否将可信验证结果形成审计记录并送至安全管理中心"),
        ]

        for sub in subitems:
            sub["status"] = "UNKNOWN"
            sub["details"].append("该检查依赖可信计算方案与演练，需人工确认。")
        subitems[2]["details"].append("请模拟篡改或验证失败场景，确认告警链路有效。")
        subitems[3]["details"].append("请检查审计日志与上报机制，验证记录是否送达安全管理中心。")

        self.finalize_item(item, subitems)
    def check_ces1_25_integrity_transmission(self) -> None:
        item = "L3-CES1-25"
        subitems = [
            self.make_subitem("1. 应核查传输过程中是否采用校验或密码技术保证完整性"),
            self.make_subitem("2. 应测试验证篡改是否能被检测并恢复"),
        ]

        subitems[0]["status"] = "UNKNOWN"
        subitems[0]["details"].append("需审阅设计文档与网络抓包，确认重要数据传输完整性保护。")
        subitems[1]["status"] = "UNKNOWN"
        subitems[1]["details"].append("请通过篡改测试验证完整性校验/加密能否发现并阻断异常。")

        self.finalize_item(item, subitems)
    def check_ces1_26_integrity_storage(self) -> None:
        item = "L3-CES1-26"
        subitems = [
            self.make_subitem("1. 应核查存储过程是否采用校验或密码技术保证完整性"),
            self.make_subitem("2. 应核查是否采用技术措施保证存储完整性"),
            self.make_subitem("3. 应测试验证存储篡改是否可检测并恢复"),
        ]

        for sub in subitems:
            sub["status"] = "UNKNOWN"
        subitems[0]["details"].append("请检查数据库/存储设计，确认敏感数据存储启用校验或签名。")
        subitems[1]["details"].append("建议核查完整性监测、WORM或数据防篡改方案是否部署。")
        subitems[2]["details"].append("需通过模拟篡改验证告警与恢复能力。")

        self.finalize_item(item, subitems)
    def check_ces1_27_confidentiality_transmission(self) -> None:
        item = "L3-CES1-27"
        subitems = [
            self.make_subitem("1. 应核查重要数据在传输过程中是否采用密码技术保证保密性"),
            self.make_subitem("2. 应验证传输数据包是否经过加密处理"),
        ]

        subitems[0]["status"] = "UNKNOWN"
        subitems[0]["details"].append("需审核设计与配置，确认敏感链路已启用传输加密。")
        subitems[1]["status"] = "UNKNOWN"
        subitems[1]["details"].append("请通过抓包或嗅探验证数据是否加密，记录验证时间与范围。")

        self.finalize_item(item, subitems)
    def check_ces1_28_confidentiality_storage(self) -> None:
        item = "L3-CES1-28"
        subitems = [
            self.make_subitem("1. 应核查存储过程是否采用密码技术保证保密性"),
            self.make_subitem("2. 应核查技术措施是否保障存储保密性"),
            self.make_subitem("3. 应测试验证指定数据是否进行了加密处理"),
        ]

        for sub in subitems:
            sub["status"] = "UNKNOWN"
        subitems[0]["details"].append("请审阅存储加密/密钥管理方案，确认覆盖鉴别数据与重要业务数据。")
        subitems[1]["details"].append("核查数据安全保护系统或磁盘/数据库加密是否到位。")
        subitems[2]["details"].append("建议抽样数据进行加密性验证，确保明文不落盘。")

        self.finalize_item(item, subitems)
    def check_ces1_29_local_backup_recovery(self) -> None:
        item = "L3-CES1-29"
        subitems = [
            self.make_subitem("1. 应核查是否按照备份策略进行本地备份"),
            self.make_subitem("2. 应核查备份策略设置是否合理、配置是否正确"),
            self.make_subitem("3. 应核查备份结果是否与备份策略一致"),
            self.make_subitem("4. 应核查近期恢复测试记录是否能够正常恢复"),
        ]

        for sub in subitems:
            sub["status"] = "UNKNOWN"
            sub["details"].append("需审核备份/恢复记录与策略配置，暂未自动化。")
        subitems[3]["details"].append("请执行恢复演练并记录结果，确保满足合规要求。")
        subitems[0]["details"].append(
            "检测步骤：1）收集备份策略与计划任务；2）核查备份时间表与成功日志；3）抽查最近一次备份文件是否存在。"
        )
        subitems[1]["details"].append(
            "检测步骤：1）审阅保留周期、加密、存储位置等配置；2）确认与业务 RTO/RPO 一致；3）记录配置截图与审批记录。"
        )
        subitems[2]["details"].append(
            "检测步骤：1）抽样比对备份内容与生产数据；2）验证校验和或文件数量匹配；3）记录差异并提出修正计划。"
        )
        subitems[3]["details"].append(
            "检测步骤：1）选择最近备份执行恢复演练；2）验证业务可用性与数据完整性；3）保存演练结果与缺陷清单。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_30_remote_backup(self) -> None:
        item = "L3-CES1-30"
        subitems = [self.make_subitem("应核查是否提供异地实时备份功能并实时同步重要数据")]

        subitems[0]["status"] = "UNKNOWN"
        subitems[0]["details"].append("请核查异地备份链路、同步范围与监控记录，未自动化检测。")
        subitems[0]["details"].append(
            "检测步骤：1）确认是否存在专线/VPN/云复制通道；2）核查同步范围、延迟与监控告警；3）在备份站点抽样验证数据可用性。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_31_hot_redundancy(self) -> None:
        item = "L3-CES1-31"
        subitems = [self.make_subitem("应核查重要数据处理系统是否采用热冗余部署")]

        subitems[0]["status"] = "UNKNOWN"
        subitems[0]["details"].append("需盘点关键节点冗余架构并通过切换演练验证，未自动化。")
        subitems[0]["details"].append(
            "检测步骤：1）梳理边界/核心/应用/数据库节点部署架构；2）确认是否存在双机/集群/负载均衡配置；3）执行或调阅切换演练记录，验证不中断。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_32_residual_authentication_clearing(self) -> None:
        item = "L3-CES1-32"
        subitems = [self.make_subitem("应核查鉴别信息存储空间释放前是否彻底清除")]

        subitems[0]["status"] = "UNKNOWN"
        subitems[0]["details"].append("请审查账户删除/重置流程，确认鉴别信息清除机制，未自动化。")
        subitems[0]["details"].append(
            "检测步骤：1）审阅账户生命周期与密码重置流程，确认包含安全清除步骤；2）抽样删除/重置测试账户后检查 shadow/缓存文件是否残留；3）如有残留，补充清除脚本并记录结果。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_33_residual_sensitive_clearing(self) -> None:
        item = "L3-CES1-33"
        subitems = [self.make_subitem("应核查敏感数据存储空间释放或分配前是否清除")]

        subitems[0]["status"] = "UNKNOWN"
        subitems[0]["details"].append("需验证敏感数据存储的擦除/覆写流程是否执行，暂未自动化。")
        subitems[0]["details"].append(
            "检测步骤：1）确认敏感数据存储位置与介质；2）模拟删除/重分配后使用恢复工具检查是否有残留；3）验证安全擦除/覆写策略生效并形成报告。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_34_personal_info_minimization(self) -> None:
        item = "L3-CES1-34"
        subitems = [
            self.make_subitem("1. 应核查采集的用户个人信息是否是业务必需"),
            self.make_subitem("2. 应核查是否制定了个人信息保护的管理制度和流程"),
        ]

        for sub in subitems:
            sub["status"] = "UNKNOWN"
        subitems[0]["details"].append("请对照业务场景审查采集字段，确认最小化原则。")
        subitems[1]["details"].append("需核查制度/流程文件，确保个人信息保护措施落实。")
        subitems[0]["details"].append(
            "检测步骤：1）列出所有采集字段与用途，对照业务必要性；2）检查是否存在超出目的的字段并标记；3）出具精简建议并确认实施记录。"
        )
        subitems[1]["details"].append(
            "检测步骤：1）收集个人信息保护制度、告知与同意模板；2）核查审批与培训记录；3）确认制度涵盖采集、使用、存储、共享、删除等全流程。"
        )

        self.finalize_item(item, subitems)
    def check_ces1_35_personal_info_protection(self) -> None:
        item = "L3-CES1-35"
        subitems = [
            self.make_subitem("1. 应核查是否采用技术措施限制对个人信息的访问和使用"),
            self.make_subitem("2. 应核查是否制定了个人信息保护的管理制度和流程"),
        ]

        for sub in subitems:
            sub["status"] = "UNKNOWN"
        subitems[0]["details"].append("请检查访问控制、脱敏与审计措施是否覆盖个人信息。")
        subitems[1]["details"].append("需审阅制度流程，确认未授权访问可追责并受控。")
        subitems[0]["details"].append(
            "检测步骤：1）审查权限、脱敏、加密和日志配置是否覆盖个人信息库/表；2）模拟未授权账号访问，验证被拒绝并有审计；3）记录测试证据与日志。"
        )
        subitems[1]["details"].append(
            "检测步骤：1）查阅个人信息访问审批、最小化授权与定期审计流程；2）核实违规访问处置记录；3）确认流程与技术控制闭环。"
        )

        self.finalize_item(item, subitems)
    def generate_report(self) -> None:
        print(f"\n{Colors.CYAN}=== 三级等保合规检查报告 ==={Colors.END}")
        print(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"系统信息: {self.os_info['distribution']} {self.os_info['machine']}\n")

        pass_count = fail_count = error_count = 0
        active_modules = self.selected_modules or list(MODULE_METHODS.keys())
        for module in active_modules:
            data = CHECK_ITEMS.get(module)
            if not data:
                continue

            print()
            category_heading = self.render_heading(data['title'], level=1)
            if category_heading:
                print(category_heading)

            for item_id, metadata in data['items'].items():
                result = self.results.get(
                    item_id,
                    {"status": "UNKNOWN", "details": [], "recommendation": "", "subitems": []},
                )
                status = result['status']
                if status == 'PASS':
                    heading_colour = Colors.BOLD_GREEN
                    pass_count += 1
                elif status == 'FAIL':
                    heading_colour = Colors.BOLD_RED
                    fail_count += 1
                else:
                    heading_colour = Colors.BOLD_YELLOW
                    error_count += 1

                item_heading = self.render_heading(
                    f"{item_id} · {status}",
                    level=2,
                    colour=heading_colour,
                )
                print()
                print(item_heading)

                indicator = metadata.get('indicator')
                if indicator:
                    emphasised_indicator = (
                        self.emphasise_primary_text(indicator) or indicator
                    )
                    print(f"   {Colors.BOLD}- 测评指标:{Colors.END} {emphasised_indicator}")

                implementation = metadata.get('implementation', [])
                if implementation:
                    print(f"   {Colors.BOLD}- 测评实施包括以下内容:{Colors.END}")
                    for step in implementation:
                        emphasised_step = self.emphasise_primary_text(step) or step
                        print(f"     * {emphasised_step}")

                subitems = result.get('subitems', [])
                if subitems:
                    print(f"   {Colors.BOLD}- 子项检查结果:{Colors.END}")
                    for sub in subitems:
                        sub_status = sub.get('status', 'PASS')
                        if sub_status == 'PASS':
                            sub_colour = Colors.GREEN
                        elif sub_status == 'FAIL':
                            sub_colour = Colors.RED
                        else:
                            sub_colour = Colors.YELLOW
                        emphasised_sub_desc = (
                            self.emphasise_primary_text(sub.get('description', ''))
                            or sub.get('description', '')
                        )
                        print(
                            f"     {sub_colour}[{sub_status}]{Colors.END} {emphasised_sub_desc}"
                        )
                        for detail in sub.get('details', []):
                            print(f"       - {detail}")
                        recommendations = sub.get('recommendation', [])
                        if recommendations and sub_status != 'PASS':
                            for rec in recommendations:
                                emphasised_rec = (
                                    self.emphasise_primary_text(rec) or rec
                                )
                                print(
                                    f"       {Colors.YELLOW}整改建议:{Colors.END} {emphasised_rec}"
                                )
                else:
                    details = result.get('details', [])
                    if details:
                        print(f"   {Colors.BOLD}- 检查详情:{Colors.END}")
                        for detail in details:
                            print(f"     * {detail}")
                    recommendation = result.get('recommendation')
                    if recommendation and status != 'PASS':
                        print(f"   {Colors.BOLD_YELLOW}整改建议:{Colors.END} {recommendation}")

        total = pass_count + fail_count + error_count
        print(f"\n{Colors.CYAN}=== 检查结果汇总 ==={Colors.END}")
        print(f"{Colors.GREEN}符合项: {pass_count}/{total}{Colors.END}")
        print(f"{Colors.RED}不符合项: {fail_count}/{total}{Colors.END}")
        print(f"{Colors.YELLOW}检查错误: {error_count}/{total}{Colors.END}")

        skipped = [module for module in CHECK_MODULES if module not in active_modules]
        if skipped:
            titles = ", ".join(
                f"{module}({CHECK_MODULES[module]['title']})" for module in skipped
            )
            print(
                f"\n{Colors.YELLOW}提示:{Colors.END} 以下模块未执行检查: {titles}"
            )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.build_markdown_report_path(
            "compliance_report_", timestamp
        )
        with open(report_file, "w", encoding="utf-8") as report:
            report.write(
                self.render_markdown_cover(
                    subject_placeholder="[被测对象名称]",
                    report_title="等级测评报告",
                )
            )
            self.write_markdown_metadata(
                report,
                {
                    "生成时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "系统信息": f"{self.os_info['distribution']} {self.os_info['machine']}",
                    "执行模块": ", ".join(
                        CHECK_MODULES[module]["title"] for module in active_modules
                    ),
                },
            )
            for module in active_modules:
                data = CHECK_ITEMS.get(module)
                if not data:
                    continue
                report.write(self.render_markdown_heading(data['title'], level=2))
                for item_id, metadata in data['items'].items():
                    result = self.results.get(item_id, {"status": "UNKNOWN", "details": [], "recommendation": "", "subitems": []})
                    status = result['status']
                    status_label = self.format_compliance_status(status)
                    report.write(
                        self.render_markdown_heading(
                            f"{item_id} · {status_label} ({status})", level=3
                        )
                    )
                    indicator = metadata.get('indicator')
                    if indicator:
                        report.write(f"- 测评指标: {indicator}\n")
                    implementation = metadata.get('implementation', [])
                    if implementation:
                        report.write("- 测评实施包括以下内容:\n")
                        for step in implementation:
                            report.write(f"  - {step}\n")
                    subitems = result.get('subitems', [])
                    if subitems:
                        rows: List[List[str]] = []
                        for sub in subitems:
                            sub_status = sub.get('status', 'PASS')
                            sub_label = self.format_compliance_status(sub_status)
                            detail_text = "<br>".join(sub.get('details', []))
                            recommendations = sub.get('recommendation', [])
                            rec_text = "<br>".join(recommendations) if recommendations else ""
                            rows.append([
                                sub_label,
                                sub.get('description', ''),
                                detail_text,
                                rec_text,
                            ])

                        report.write(
                            self.render_markdown_table(
                                ["状态", "子项", "检查详情", "整改建议"], rows
                            )
                        )
                    else:
                        details = result.get('details', [])
                        if details:
                            report.write("- 检查详情:\n")
                            for detail in details:
                                report.write(f"  - {detail}\n")
                        recommendation = result.get('recommendation')
                        if recommendation and result['status'] != 'PASS':
                            report.write(f"- 整改建议: {recommendation}\n")
                    report.write("\n")
            report.write(self.render_markdown_heading("检查结果汇总", level=2))
            summary_rows = [
                [self.format_compliance_status('PASS'), f"{pass_count}/{total}"],
                [self.format_compliance_status('FAIL'), f"{fail_count}/{total}"],
                [self.format_compliance_status('ERROR'), f"{error_count}/{total}"],
            ]
            if skipped:
                skipped_titles = ", ".join(
                    f"{module}({CHECK_MODULES[module]['title']})" for module in skipped
                )
                summary_rows.append(["未执行模块", skipped_titles])
            report.write(
                self.render_markdown_table(["类别", "统计"], summary_rows)
            )
        print(
            f"\n{Colors.GREEN}Markdown 合规报告已保存到: {report_file}{Colors.END}"
        )

    def generate_remediation_report(self) -> None:
        """Persist remediation decisions and actions into a report file."""

        if not self.remediation_records:
            print(f"\n{Colors.YELLOW}未执行任何整改操作，未生成整改报告。{Colors.END}")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.build_markdown_report_path(
            "remediation_report_", timestamp
        )
        status_counts: Dict[str, int] = {}

        with open(report_path, "w", encoding="utf-8") as report:
            report.write(
                self.render_markdown_cover(
                    subject_placeholder="[被测对象名称]",
                    report_title="等级整改报告",
                )
            )
            self.write_markdown_metadata(
                report,
                {
                    "生成时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "整改记录数": str(len(self.remediation_records)),
                },
            )
            for record in self.remediation_records:
                status = record.get("status", "UNKNOWN")
                status_counts[status] = status_counts.get(status, 0) + 1
                status_label = self.format_status_label(status)
                report.write(
                    self.render_markdown_heading(
                        f"[{status_label}] {record.get('item_id', '')} - {record.get('subitem_description', '')}",
                        level=2,
                    )
                )
                detail_rows: List[List[str]] = []
                if record.get("category"):
                    detail_rows.append(["所属分类", record["category"]])
                if record.get("indicator"):
                    detail_rows.append(["测评指标", record["indicator"]])
                if record.get("implementation"):
                    detail_rows.append(["测评实施要点", record["implementation"]])
                detail_rows.append([
                    "检查初始状态",
                    record.get("initial_status", ""),
                ])
                recommendations = record.get("recommendations", []) or []
                if recommendations:
                    detail_rows.append([
                        "原始整改建议",
                        "<br>".join(recommendations),
                    ])
                notes = record.get("notes", []) or []
                if notes:
                    detail_rows.append([
                        "整改执行情况",
                        "<br>".join(notes),
                    ])
                report.write(
                    self.render_markdown_table(["字段", "内容"], detail_rows)
                )

            report.write(self.render_markdown_heading("整改结果汇总", level=2))
            summary_rows = [
                [self.format_status_label(status), str(count)]
                for status, count in sorted(status_counts.items())
            ]
            report.write(
                self.render_markdown_table(["状态", "数量"], summary_rows)
            )

        self.remediation_report_path = report_path

        print(f"\n{Colors.CYAN}=== 整改结果汇总 ==={Colors.END}")
        for status, count in sorted(status_counts.items()):
            label = self.format_status_label(status)
            print(f" {label}: {count}")
        print(
            f"{Colors.GREEN}Markdown 整改报告已保存到: {report_path}{Colors.END}"
        )
if __name__ == "__main__": 
    sys.exit(main())

