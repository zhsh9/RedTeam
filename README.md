# 1. Recon

## scanner

- nmap
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
- AutoRecon
```bash
```
- RustScan
```bash
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

## directory

## smb

- enum4linux
```bash
enum4linux -A $IP
```

## dns

## subdomain

## cdn

## waf

## web source code

## website

## asset

# 2. Vulns

## SQL注入

## 文件上传

## XSS

## 命令注入

## CSRF

## 反序列化

## 代码审计

# 3. Privilege Escalation

## shell

## methodology

## 手工枚举

## 自动枚举

# 4. Post Pentest

# 5. AWD

# 6. Social Engineer

# 7. Software Engineer

# Appendix. 靶场

- [ ] [OSCP练习推荐靶场库](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8)

# Appendix. 学习资料

