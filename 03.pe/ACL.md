在 Linux 系统中，访问控制列表（Access Control List，简称ACL）是一种更为灵活的权限管理机制，它可以为每个用户和用户组设置不同的权限，而不仅仅是文件的所有者、所有者所在的组和其他用户这三种类型。

传统的 Unix/Linux 文件权限系统只能针对三类用户（文件所有者、文件所有者所在的组和其他用户）设置读、写和执行权限。这在大多数情况下都足够用了，但是在某些需要更细粒度权限控制的场景下就显得力不从心。

而 ACL 就可以解决这个问题。比如，我们可以为特定的用户或者用户组设置某个文件或者目录的访问权限，而不需要改变文件的所有者或者所属组。每个文件或目录可以有一个关联的 ACL，其中可以包含多条访问控制条目（Access Control Entry，简称ACE），每条ACE都指定了一个用户或者组对该文件或目录的访问权限。

在 Linux 系统中，可以使用 `getfacl` 命令查看文件或目录的 ACL，使用 `setfacl` 命令设置文件或目录的 ACL。

例如，我们可以使用下面的命令为用户 `user1` 设置对文件 `file1` 的读/写权限：

```bash
setfacl -m u:user1:rw file1
```

然后，我们可以使用 `getfacl` 命令查看 `file1` 的 ACL：

```bash
getfacl file1
```

这将显示 `file1` 的 ACL，其中应该包含用户 `user1` 的读/写权限。

需要注意的是，不是所有的文件系统都支持 ACL。在 Linux 中，ext2、ext3、ext4、reiserfs 和 jfs 文件系统都支持 ACL。要在这些文件系统中使用 ACL，需要在挂载时指定 `acl` 选项，或者在 `/etc/fstab` 文件中为文件系统添加 `acl` 选项。

## 如何使用 ACL

- 在挂载时指定ACL选项
```bash
sudo mount -o acl /dev/sda1 /mnt
```
- 在 `/etc/fstab` 文件中添加 `acl` 选项
``` bash
# change /etc/fstab
sudo vim /etc/fstab
##/dev/sda1 /mnt ext4 default 1 2
##/dev/sda1 /mnt ext4 default,acl 1 2
# remount fs
sudo umount /mnt
sudo mount /mnt
```
