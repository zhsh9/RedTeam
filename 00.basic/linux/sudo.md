## 概要

`sudo`是一个强大的Unix和Linux命令行工具，它的全称是“superuser do”，意思是以超级用户（也就是root用户）的权限执行命令。`sudo`可以让系统管理员给予普通用户执行部分或全部的超级用户命令的权限，而无需知道root的密码。

基本用法：
```bash
sudo cmd
```
在这里，“cmd”是你想要以超级用户权限执行的命令。在输入这个命令后，系统会提示你输入你自己的密码，而不是root的密码。如果你在一段时间内（通常是5分钟）再次使用`sudo`，你不需要再次输入密码。

sudo的使用是由`/etc/sudoers`文件来控制的。在这个文件中，系统管理员可以定义哪些用户（或用户组）可以执行哪些命令。你也可以设置一些更复杂的权限，比如限制某个用户只能在某些时间或在某些主机上使用`sudo`。

常见配置文件条目：
```bash
qwe ALL=(ALL:ALL) ALL
```
含义是：
- qwe：用户可以执行下面定义的规则
- ALL=：在所有主机上
- (ALL:ALL)：可以以所有用户和所有组的身份运行命令
- ALL：可以运行所有命令

## 配置文件

- /etc/sudoers
- 修改配置文件：sudo visudo
- 修改超时时间：默认情况下，当你使用`sudo`运行一个命令后，你在接下来的5分钟内再次使用`sudo`时，不需要再次输入密码。这个超时时间是可以修改的。要修改它，你需要编辑`/etc/sudoers`文件，找到`Defaults env_reset`行，在该行的下面添加`Defaults timestamp_timeout=x`，其中`x`是你想要的超时时间（以分钟为单位）。例如，要设置超时时间为10分钟，你可以添加`Defaults timestamp_timeout=10`。

基本配置内容：
```bash
# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin  ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
```
- **root ALL=(ALL:ALL) ALL:** 这一行表示 `root` 用户在任何主机 (`ALL`) 可以作为任何用户 (`ALL`) 和组 (`ALL`) 执行任何命令 (`ALL`)。
- **%admin ALL=(ALL) ALL:** 这一行表示 `admin` 组的所有成员可以在任何主机 (`ALL`) 上作为任何用户 (`ALL`) 执行任何命令 (`ALL`)。
- **%sudo ALL=(ALL:ALL) ALL:** 这一行表示 `sudo` 组的所有成员可以在任何主机 (`ALL`) 上作为任何用户 (`ALL`) 和组 (`ALL`) 执行任何命令 (`ALL`)。

### 命令别名

在`sudoers`文件中，你可以定义任意你想要的命令别名。命令别名是一种方便的方式，用于将一组相关的命令组合在一起，然后你可以将特定的权限分配给这个别名，而不是分配给每个单独的命令。

下面是一个定义命令别名的例子：

```bash
Cmnd_Alias NETWORKING = /sbin/route, /sbin/ifconfig, /bin/ping, /sbin/dhclient, /usr/bin/net, /sbin/iptables, /usr/bin/rfcomm, /usr/bin/wvdial, /sbin/iwconfig, /sbin/mii-tool
```

在这个例子中，`NETWORKING` 是一个命令别名，它代表了一组网络相关的命令。然后你可以将这个别名用在 `sudoers` 文件的其他地方，来给用户或用户组分配权限。例如：

```bash
user ALL=(ALL) NOPASSWD: NETWORKING
```

这行配置会让用户 `user` 在所有主机上以所有用户身份运行 `NETWORKING` 别名定义的所有命令，而无需输入密码。

### 默认环境变量（Default行）

`Defaults` 行用于设置在 `sudo` 环境中的默认选项和变量。比如，你可以使用 `Defaults` 来改变 `sudo` 的超时设置，或者定义哪些环境变量可以传递到 `sudo` 环境。

例如：
```bash
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

在这个例子中，
- `env_reset` 是一个选项，它会重置 `sudo` 的执行环境，只保留少数必要的环境变量。
- `mail_badpass` 是一个选项，它会在用户输入错误的 `sudo` 密码时发送邮件。
- `secure_path` 是一个变量，它定义了 `sudo` 命令的安全路径。

### 特定用户或组的特定权限

可以在 `/etc/sudoers` 文件中指定哪些用户或组可以运行哪些命令。

例如：
```bash
john ALL=(ALL) NOPASSWD: /sbin/shutdown, /sbin/reboot
%staff ALL=(ALL) /usr/bin/git, /usr/bin/svn
```

在这个例子中，
- `john` 用户在所有主机上可以以所有用户身份运行 `/sbin/shutdown`和 `/sbin/reboot` 命令，而不需要输入密码。
- 所有属于 `staff` 组的用户在所有主机上可以以所有用户身份运行 `/usr/bin/git` 和 `/usr/bin/svn` 命令。

## 使用方法

基本使用：
```bash
# 以另一个用户的身份运行命令
sudo -u qwe whoami
# 切换为另一个用户
sudo -u qwe -i
# 在特定目录下执行命令
sudo -u qwe -i -c 'cd /home/qwe && ls -l'
# 用sudo运行图形app
gksudo firefox  # GTK app
kdesudo firefox # KDE app
```

添加新用户，赋予sudo权限：
```bash
sudo useradd newuser # adduser
sudo passwd newuser
sudo usermod -aG sudo newuser
```
```bash
sudo userdel someuser
sudo userdel -r someuser
```

## sudo -l

`sudo -l` 命令用于列出当前用户可以（根据 `sudoers` 文件）以 `sudo` 执行的所有命令。
`sudo -l` 命令的输出可能会根据你的系统和 `sudoers` 文件的配置而变化。

sudo -l的典型输出：
```bash
Matching Defaults entries for user on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on this host:
    (ALL : ALL) ALL
```

- **Matching Defaults entries for user on this host:** 这一行显示的是对应于当前用户在当前主机上的默认 `sudo` 行为。
	- `env_reset` 表示在运行 `sudo` 命令时重置环境变量
	- `env_keep` 表示在执行 `sudo` 命令时哪些环境变量应该被保留
	- `mail_badpass` 表示在用户输错 `sudo` 密码时发送邮件通知
	- `secure_path` 表示 `sudo` 命令的安全路径
- **User user may run the following commands on this host:** 这一行后面列出的是用户可以在当前主机上运行的命令。
- **(ALL : ALL) ALL:** 这表示用户可以作为任何用户（第一个 `ALL`）从任何终端（第二个 `ALL`）运行任何命令（最后的 `ALL`）。如果这里有特定的命令、用户或终端，那么用户的权限将受到限制。