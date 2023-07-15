Linux 中的 UGO 权限体系是指基于用户（User）、组（Group）和其他人（Others）三个角色来对文件和目录进行权限管理的一种权限体系。在 UGO 权限体系中，每个文件和目录都有一个所有者和一个所属组，同时也分配了对应的权限，包括读（Read）、写（Write）和执行（Execute）权限。用 `rwx` 表示分别代表读、写和执行权限，如果没有相应权限则用 `-` 表示。

具体来说，UGO 权限体系中的权限可以分为三类：

- 用户权限（User Permissions）：指文件或目录所有者拥有的权限
- 组权限（Group Permissions）：指文件或目录所属组拥有的权限
- 其他人权限（Other Permissions）：指除了文件或目录所有者和所属组以外的其他人拥有的权限

在 Linux 中，可以使用 `chmod` 命令来修改文件和目录的权限，使用 `chown`和 `chgrp` 命令来修改文件和目录的所有者和所属组。

查看当前文件or文件夹权限：

- ls -l file
- stat file

chmod命令常用：
- corresponding permission values:
	- `4` for read permission
	- `2` for write permission
	- `1` for execute permission
- symbolic mode:
	- `u` for the file owner
	- `g` for the group
	- `o` for other users
	- `a` for all users
	- `+` to add permissions
	- `-` to remove permissions
	- `=` to set permissions