# checkpoint

在 tar 命令中，`--checkpoint` 选项用于在打包或解包文件时定期输出进度信息，以便用户了解命令的运行情况。该选项需要指定一个检查点文件（checkpoint file），该文件用于存储命令的进度信息，可以在命令中断后恢复使用。

`--checkpoint` 选项的语法如下：

```bash
--checkpoint[=num] [--checkpoint-action=action]
```

其中，`num` 是检查点的数量，`action` 是在每个检查点处执行的操作。如果省略 `num` 参数，则默认为 10。

`--checkpoint-action` 选项用于指定在每个检查点处执行的操作。可以指定多个操作，每个操作之间用逗号分隔。以下是一些常用的操作：

- `echo`：在标准输出中显示检查点信息。
- `exec`：执行指定的命令或脚本。
- `log=filename`：将检查点信息记录到指定的文件中。
- `mail=user`：将检查点信息通过邮件发送给指定的用户。
- `run-command=command`：执行指定的命令或脚本。

例如，以下命令将在打包文件时，每 1000 个文件输出一个检查点信息，并将检查点信息记录到指定的文件中：

```bash
tar -czf backup.tar.gz --checkpoint=1000 --checkpoint-action='log=checkpoint.log' /path/to/files
```

在命令执行过程中，tar 将每 1000 个文件输出一个检查点信息，并将检查点信息记录到 `checkpoint.log` 文件中。如果命令中断，可以使用 `--checkpoint` 选项和检查点文件来恢复命令的运行。

需要注意的是，`--checkpoint` 选项需要 tar 版本 1.15 或更高版本支持。