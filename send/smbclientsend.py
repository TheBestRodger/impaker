#!/usr/bin/env python3
from impacket.smbconnection import SMBConnection

AD_IP   = "172.16.12.1"       # IP AD
DOMAIN  = "AD.LOCAL"
USER    = "Администратор"
PASSWD  = "Mos123098!"

def main():
    smb = SMBConnection(AD_IP, AD_IP, sess_port=445)
    smb.login(USER, PASSWD, DOMAIN)   # или smb.login('', '') для guest, если разрешено
    print("[+] Connected. Server name:", smb.getServerName())
    print("[+] Shares:")
    for share in smb.listShares():
        print("   -", share['shi1_netname'][:-1])
    smb.logoff()

if __name__ == "__main__":
    main()
