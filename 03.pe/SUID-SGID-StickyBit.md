在 Linux 系统中，文件权限是通过一组位（bit）来管理的，包括读（r）、写（w）和执行（x）权限。这些权限按照所有者（owner）、组（group）和其他（other）三个类别进行分组。此外，还有三个特殊的权限位：Set User ID（SUID）、Set Group ID（SGID）和 Sticky Bit。

## SUID

SUID 是一个特殊的权限位，当设置了这个位的时候，运行该文件的用户将拥有该文件所有者的权限。

例如，`passwd` 命令就设置了 SUID 位。`passwd` 命令需要访问 `/etc/shadow` 文件来更新用户密码，而 `/etc/shadow` 文件只允许 root 用户读写。如果没有 SUID，普通用户就无法使用 `passwd` 命令来更改他们的密码。但是由于 `passwd` 命令设置了 SUID，因此当普通用户运行 `passwd` 命令时，`passwd` 命令将以文件所有者（在这种情况下是 root）的权限来运行，从而能够访问 `/etc/shadow` 文件。

在 ls -l 输出中，SUID 权限被表示为 `s` 或 `S`。
- 如果文件具有 SUID 权限并且可执行，那么所有者权限中的 `x` 将被 `s` 替换。
- 如果文件具有 SUID 权限但不可执行，那么所有者权限中的 `x` 将被 `S` 替换。

```bash
chmod u+s file
chmod u-s file
```

## SGID

SGID 是 Linux 中的一种特殊权限位，当一个可执行文件的 SGID 位被设置时，执行该文件的用户会暂时获得文件所属组的权限。这在多用户协作环境中很有用，因为它允许用户共享他们的文件，同时仍然限制对文件的访问。

例如，如果一个文件属于 "staff" 组，并且设置了 SGID，那么当其他用户执行这个文件时，他们将以 "staff" 组的权限来执行该文件。

在 `ls -l` 输出中，SGID 权限被表示为 `s` 或 `S`。
- 如果文件具有 SGID 权限并且可执行，那么组权限中的 `x` 将被 `s` 替换。
- 如果文件具有 SGID 权限但不可执行，那么组权限中的 `x` 将被 `S` 替换。

```bash
chmod g+s filename
chmod g-s filename
```

## Sticky Bit

Sticky Bit 是 Linux 文件系统中的另一个特殊权限位。在目录上设置 Sticky Bit 会影响在该目录中创建的文件。如果一个目录设置了 Sticky Bit，那么只有文件的所有者、目录的所有者或 root 用户才能删除该目录中的文件。

这在 `/tmp` 目录中特别有用，因为 `/tmp` 目录是所有用户都可以读写的，如果没有 Sticky Bit，任何用户都可以删除 `/tmp` 中的文件。但是由于 `/tmp` 设置了 Sticky Bit，所以只有文件的所有者、目录的所有者或 root 用户才能删除 `/tmp` 中的文件。

在 `ls -l` 输出中，Sticky Bit 权限被表示为 `t` 或 `T`。
- 如果目录具有 Sticky Bit 权限并且可执行，那么其他权限中的 `x` 将被 `t` 替换。
- 如果目录具有 Sticky Bit 权限但不可执行，那么其他权限中的 `x` 将被 `T` 替换。

```bash
chmod +t directoryname
chmod -t directoryname
```