**AppArmor** 和 **SELinux** 都是 Linux 系统中用来增强系统安全的工具，它们通过限制进程的能力来防止潜在的攻击。

## AppArmor

AppArmor（Application Armor）是另一个 Linux 安全模块，它使用路径名访问控制（path-based access control）策略来限制程序的权限。AppArmor 通过定义一套包含文件路径的规则来限制进程访问文件系统，每个应用程序都有一套专属的访问规则。

AppArmor 的操作模式包括：

- **Enforce**：强制模式，AppArmor 的访问控制策略将会被强制执行。
- **Complain**：抱怨模式，AppArmor 会记录所有被阻止的操作，但并不会真的阻止它们。
- **Unconfined**：无限制模式，进程可以访问所有文件和功能。

## SELinux

SELinux（Security-Enhanced Linux）是一个 Linux 内核的安全模块，提供了一种访问控制安全策略，包括强制访问控制（MAC）。SELinux策略规定了哪些进程可以访问哪些文件，设备和端口等。这些策略规则确保即使进程或用户获得了 root 权限，也只能在 SELinux 策略允许的范围内操作，增加了对系统的保护。

SELinux 提供了三种工作模式：

- **Enforcing**：强制模式，即 SELinux 策略被强制执行，违反策略的操作会被阻止并记录日志。
- **Permissive**：许可模式，只记录违反策略的操作，不阻止。
- **Disabled**：禁用模式，SELinux 被完全关闭。
