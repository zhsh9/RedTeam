在 Linux 中，Capabilities 是一种更细粒度的权限控制机制，它允许系统管理员能够将特定的权限赋予用户或程序，而无需赋予它们完全的 `root` 权限。这种机制提供了比传统的 UNIX 用户和组权限模型更精细的控制。

在传统的 UNIX 权限模型中，`root` 用户（或者说，用户 ID 为 0 的用户）有系统上所有操作的完全权限。这种模型的问题在于，如果一个程序需要执行某个需要 `root` 权限的操作（例如，监听一个小于 1024 的端口），那么这个程序必须以 `root` 用户运行，从而拥有系统上所有的权限。这在安全性上是一种风险，因为如果这个程序被利用，攻击者就能够获得对整个系统的控制。

为了解决这个问题，Linux 引入了 Capabilities。Capabilities 将 `root` 用户的权限分割成一系列的不同部分，每一部分都代表了一种特定的权限。例如，`CAP_NET_BIND_SERVICE` Capability 允许程序监听一个小于 1024 的端口，而 `CAP_DAC_OVERRIDE` Capability 允许程序绕过文件权限检查。

通过 Capabilities，系统管理员可以为用户或程序赋予它们所需要的最小权限，而无需赋予它们完全的 `root` 权限。例如，如果一个程序只需要监听一个小于 1024 的端口，那么系统管理员可以只为这个程序赋予 `CAP_NET_BIND_SERVICE` Capability，而不是 `root` 权限。

```bash
# setcap 增加or删除 cap
sudo setcap cap_net_bind_service+ep /path/to/program
# getcap 查看 cap
getcap /path/to/program
```

## 常见caps

Capabilities 分为三种类型：

- 有效（Effective）：这是当前对进程有效的一组 Capabilities。
- 可继承（Inheritable）：这是进程可以传给其子进程的一组 Capabilities。
- 允许（Permitted）：这是进程可以使用的 Capabilities 的最大集合。

caps完整列表：[capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)

1. `CAP_CHOWN`：允许进程更改文件的所有者。
2. `CAP_DAC_OVERRIDE`：允许进程绕过文件读取、写入和执行权限检查。
3. `CAP_DAC_READ_SEARCH`：允许进程绕过文件读取权限检查以及目录读取和执行权限检查。
4. `CAP_FOWNER`：允许进程执行通常需要进程的文件系统 UID 与文件的 UID 匹配的操作。
5. `CAP_FSETID`：在文件被修改时，不清除 set-user-ID 和 set-group-ID 模式位。
6. `CAP_KILL`：允许进程向任何进程发送任何信号。
7. `CAP_SETGID`：允许进程设置组 ID。
8. `CAP_SETUID`：允许进程设置用户 ID。
9. `CAP_NET_BIND_SERVICE`：允许进程将套接字绑定到 1024 以下的端口。
10. `CAP_NET_RAW`：允许进程使用 RAW 和 PACKET 套接字。
11. `CAP_SYS_CHROOT`：允许进程使用 `chroot()` 函数。

## setcap 的使用

在`setcap`命令中，`+ep`，`-ep`和`=ep`都是用来设置文件的执行权限的。这三个标志的意思如下：
- `+ep`：增加某种capabilities。例如，`setcap 'cap_net_bind_service=+ep' /bin/ping`表示将`cap_net_bind_service`权限赋予`/bin/ping`程序。
- `-ep`：删除某种capabilities。例如，`setcap 'cap_net_bind_service=-ep' /bin/ping`表示删除`/bin/ping`程序的`cap_net_bind_service`权限。
- `=ep`：设置某种capabilities，清空其他所有的capabilities。例如，`setcap 'cap_net_bind_service=ep' /bin/ping`表示只给`/bin/ping`程序设置`cap_net_bind_service`权限，其他所有的capabilities都被清空。
- `=+ep`：这个操作符表示先清空文件的所有权限，然后再增加某种权限。也就是说，如果文件原来已经有了某些权限，那么`=+ep`操作之后，这些权限将会被清空，只保留新增加的权限。
