#!/usr/bin/env python3
"""
Bash command safety guard for Claude Code.
Scans the FULL command string (including combined commands with &&, ||, ;, |)
for dangerous patterns anywhere in the string — not just at the prefix.

Location: ~/.claude/hooks/bash_guard.py
Loaded by: ~/.claude/settings.json (PreToolUse hook, Bash matcher)
"""

import sys
import json
import re

# Each entry: (regex_pattern, human_readable_reason)
# Patterns use re.IGNORECASE | re.DOTALL and re.search (matches anywhere in string)
DANGEROUS_PATTERNS = [

    # ── Filesystem Destruction ────────────────────────────────────────────────

    # rm -rf targeting /, /*, ~, $HOME, or empty-variable expansion (SC2115)
    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*/$',             '删除根目录 (rm -rf /)'),
    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*/\*',            '删除根目录所有文件 (rm -rf /*)'),
    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*~/?(\s|$)',      '删除 home 目录 (rm -rf ~)'),
    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*\$HOME/?(\s|$)', '删除 HOME 目录 (rm -rf $HOME)'),
    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*""/',            '空字符串变量展开导致根删除'),
    (r'--no-preserve-root',                                          'rm --no-preserve-root 绕过保护'),

    # Disk / partition overwrite
    (r'\bdd\b.+\bof=/dev/(sd|hd|nvme|vd|xvd)',                     '覆写磁盘设备 (dd)'),
    (r'\bshred\b.+/dev/(sd|hd|nvme)',                               '安全擦除磁盘 (shred)'),
    (r'>\s*/dev/(sd|hd|nvme)[a-z0-9]',                             '重定向写入磁盘设备节点'),
    (r'\bcat\s+/dev/(zero|urandom)\s+>\s*/dev/',                   'cat /dev/zero 覆写磁盘'),
    (r'\bmkfs\b.*/dev/',                                            '格式化磁盘分区 (mkfs)'),

    # Kernel panic / forced reboot via SysRq
    (r'echo\s+[cb]\s*>\s*/proc/sysrq-trigger',                     '触发内核崩溃/强制重启 (SysRq)'),


    # ── Fork Bombs & Resource Exhaustion ─────────────────────────────────────

    # Classic and obfuscated variants: :(){ :|:& };:  ..(){..|..&}..  bomb(){ bomb|bomb& };bomb
    (r'(\w+|\.|:)\s*\(\s*\)\s*\{[^}]*\|[^}]*&',                   'Fork bomb'),
    (r'while\s+true\s*;\s*do\s+\$0\s*&',                           '进程自繁殖循环'),


    # ── Remote Code Execution ─────────────────────────────────────────────────

    (r'\bcurl\b[^|#\n]*\|\s*-?\s*(ba?sh|sh)\b',                    '远程代码执行 (curl | bash/sh)'),
    (r'\bwget\b[^|#\n]*\|\s*-?\s*(ba?sh|sh)\b',                   '远程代码执行 (wget | bash/sh)'),
    (r'\bcurl\b[^|#\n]*\|\s*python3?\b',                           '远程代码执行 (curl | python)'),
    (r'\bwget\b[^|#\n]*\|\s*python3?\b',                           '远程代码执行 (wget | python)'),
    (r'\bcurl\b[^|#\n]*\|\s*perl\b',                               '远程代码执行 (curl | perl)'),
    (r'\bcurl\b[^|#\n]*\|\s*ruby\b',                               '远程代码执行 (curl | ruby)'),
    (r'\bcurl\b[^|#\n]*\|\s*node\b',                               '远程代码执行 (curl | node)'),
    # bash <(curl ...) and . <(curl ...)
    (r'(bash|sh)\s*<\s*\(\s*(curl|wget)',                          '下载并执行 bash <(curl...)'),
    (r'\.\s+<\s*\(\s*(curl|wget)',                                  'source 远程脚本 . <(curl...)'),
    # source <(curl ...)
    (r'\bsource\s+<\s*\(\s*(curl|wget)',                           'source 远程脚本 source <(curl...)'),
    # eval with dynamic/remote content
    (r'\beval\s+["\'\`\$\(]',                                      'eval 动态内容 (潜在代码注入)'),
    (r'\beval\s+\$\(',                                              'eval 命令替换'),


    # ── Reverse Shells ────────────────────────────────────────────────────────

    (r'/dev/tcp/',                                                   '反向 Shell (bash /dev/tcp)'),
    (r'/dev/udp/',                                                   '反向 Shell (bash /dev/udp)'),
    # bash -i >& ...
    (r'bash\s+-i\s+>&',                                             '反向 Shell (bash -i >&)'),
    # nc -e /bin/sh  or  nc -e /bin/bash
    (r'\bnc\b.+-e\s+/bin/(sh|bash)',                               '反向 Shell (nc -e)'),
    # mkfifo pipe to nc pattern
    (r'mkfifo\s+.+\|\s*(sh|bash)\s+-i.+nc\b',                     '反向 Shell (mkfifo | nc)'),
    (r'\bncat\b.+-e\s+/bin/(sh|bash)',                             '反向 Shell (ncat -e)'),


    # ── Credential & Sensitive File Access ───────────────────────────────────

    (r'\bcat\s+/etc/shadow\b',                                      '读取密码哈希 (/etc/shadow)'),
    (r'\bcat\s+/etc/sudoers\b',                                     '读取 sudoers 配置'),
    # SSH private keys
    (r'\bcat\b.+\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa)\b',     '读取 SSH 私钥'),
    # AWS credentials
    (r'\bcat\b.+\.aws/(credentials|config)\b',                      '读取 AWS 凭据'),
    # .env files (only direct cat, not find - too noisy)
    (r'\bcat\b.+/\.env\b',                                          '读取 .env 凭据文件'),
    # /proc memory of sensitive processes
    (r'\bcat\s+/proc/\d+/(mem|environ)\b',                         '读取进程内存/环境变量'),


    # ── History & Log Tampering ───────────────────────────────────────────────

    (r'HISTFILE\s*=\s*/dev/null',                                   '禁用 shell 历史 (HISTFILE=/dev/null)'),
    (r'HISTSIZE\s*=\s*0',                                           '清空历史大小 (HISTSIZE=0)'),
    (r'HISTFILESIZE\s*=\s*0',                                       '清空历史文件大小'),
    (r'\bhistory\s+-[cw]\b',                                        '清除/覆盖 shell 历史 (history -c/-w)'),
    (r'\bln\s+-sf?\s+/dev/null\s+.*bash_history',                  '将 bash_history 链接到 /dev/null'),
    # Clear auth/syslog
    (r'(cat\s+/dev/null|echo\s+""?)\s*>\s*/var/log/(auth|syslog|messages|secure)', '清空系统日志'),
    (r'\brm\s+-rf?\s+/var/log/',                                    '删除系统日志目录'),
    # Stop audit daemon
    (r'(service|systemctl)\s+(stop|disable)\s+audit',              '停止审计守护进程 (auditd)'),


    # ── Environment Variable Injection ───────────────────────────────────────

    (r'\bLD_PRELOAD\s*=',                                           '动态库劫持 (LD_PRELOAD)'),
    (r'\bLD_LIBRARY_PATH\s*=\s*/tmp',                               '劫持库搜索路径到 /tmp'),
    (r'\bLD_AUDIT\s*=',                                             '动态链接器审计劫持 (LD_AUDIT)'),
    (r'\bBASH_ENV\s*=',                                             'Shell 启动注入 (BASH_ENV)'),
    (r'\bPROMPT_COMMAND\s*=',                                       '命令提示符注入 (PROMPT_COMMAND)'),
    (r'\bPYTHONSTARTUP\s*=',                                        'Python 启动脚本注入'),
    (r'\bNODE_OPTIONS\s*=.*--require',                              'Node.js 模块注入 (NODE_OPTIONS)'),
    (r'\bJAVA_TOOL_OPTIONS\s*=.*-agent',                           'JVM Agent 注入'),


    # ── Privilege Escalation ─────────────────────────────────────────────────

    # SUID on shell binaries
    (r'\bchmod\b.+[0-9]*4[0-9]*7[0-9]*\s+.*(bash|sh|zsh|python|perl|ruby)',
                                                                     'SUID 设置在 shell/解释器上'),
    # Recursive dangerous chmod on root paths
    (r'\bchmod\b\s+(-R|--recursive)\s+[0-9]*7[0-9]*7\s+/',        '递归 777 根路径'),
    # sudo to root shell
    (r'\bsudo\s+(su|bash|sh|zsh|fish)(\s|$)',                      'sudo 提权到 root shell'),
    (r'\bsudo\s+-[si]\b',                                           'sudo -s/-i 获取 root shell'),
    # sudo + dangerous operations
    (r'\bsudo\b.+\brm\b.+-[rf].+/',                                'sudo 递归删除系统路径'),
    (r'\bsudo\b.+\bdd\b',                                           'sudo 磁盘操作'),
    (r'\bsudo\b.+\bmkfs\b',                                         'sudo 格式化磁盘'),
    (r'\bsudo\b.+\bchmod\b.+(-R|--recursive).+/',                  'sudo 递归修改系统路径权限'),
    (r'\bsudo\b.+\bchown\b.+(-R|--recursive).+/',                  'sudo 递归修改系统路径所有权'),
    # Overwrite /etc/passwd or /etc/shadow
    (r'>>\s*/etc/(passwd|shadow)',                                   '写入 /etc/passwd 或 /etc/shadow'),
    (r'echo\b.+>>\s*/etc/(passwd|shadow)',                          '追加内容到 passwd/shadow'),


    # ── Persistence Mechanisms ────────────────────────────────────────────────

    # Append reverse shell to shell startup files
    (r'>>\s*~/?\.(bashrc|bash_profile|profile|zshrc|zprofile)',    '向 shell 启动文件植入后门'),
    (r'>>\s*/etc/(bash\.bashrc|profile|bashrc)',                    '向系统 shell 启动文件植入后门'),
    # Cron persistence
    (r'>>\s*/etc/(crontab|cron\.d/)',                               '向系统 crontab 植入任务'),
    (r'\bcrontab\b[^|]*\|\s*crontab\b',                            '通过管道修改 crontab (植入持久化)'),
    # Unauthorized user creation
    (r'\buseradd\b.+-u\s+0\b',                                     '创建 UID=0 后门用户'),
    # SSH backdoor key
    (r'>>\s*~?/\.ssh/authorized_keys',                              '向 authorized_keys 写入后门公钥'),


    # ── Firewall / Security Controls Disabling ────────────────────────────────

    (r'\biptables\s+-F\b',                                          '清空 iptables 防火墙规则'),
    (r'\biptables\s+-P\s+INPUT\s+ACCEPT\b',                        '开放所有入站流量 (iptables)'),
    (r'\bufw\s+disable\b',                                          '禁用 UFW 防火墙'),
    (r'\bsystemctl\s+(stop|disable)\s+firewalld\b',                '禁用 firewalld'),
    (r'\bsetenforce\s+0\b',                                         '关闭 SELinux 强制模式'),
    (r'echo\s+0\s*>\s*/sys/fs/selinux/enforce',                    '关闭 SELinux (sysfs)'),

]


def main():
    try:
        data = json.load(sys.stdin)
        cmd = data.get('tool_input', {}).get('command', '')
        hook_event = data.get('hook_event_name', 'PreToolUse')

        for pattern, reason in DANGEROUS_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE | re.DOTALL):
                output = {
                    "hookSpecificOutput": {
                        "hookEventName": hook_event,
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"危险命令被拦截: {reason}"
                    },
                    "systemMessage": (
                        f"⚠️ 危险命令被拦截\n"
                        f"原因: {reason}\n"
                        f"命令: {cmd[:300]}"
                    )
                }
                print(json.dumps(output, ensure_ascii=False))
                return

        # No match — safe to proceed
        print('{}')

    except Exception as e:
        # Never block on hook errors, just surface a warning
        print(json.dumps({"systemMessage": f"bash_guard error: {e}"}))
    finally:
        sys.exit(0)


if __name__ == '__main__':
    main()
