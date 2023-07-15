cron 是一个常驻后台的进程，用于在预定的时间和日期执行指定的命令或脚本。它通过配置文件 `/etc/crontab` 和每个用户的个人配置文件来定义自动任务。cron 基于时间的自动任务是非常重要的，可以用来自动化许多系统管理任务。使用 cron 的关键是理解 cron 表达式，它是由五个时间字段组成的，分别表示分钟、小时、日、月、周几。通过编辑 cron 配置文件，可以定义在特定时间和日期执行指定命令或脚本。例如：

```bash
# m h dom mon dow user	command
0 0 * * * /path/to/my/script.sh
```

这个 cron 表达式表示在每天的午夜时分（0 分钟，0 小时）执行 `/path/to/my/script.sh` 脚本。

## cron 表达式格式

```
*     *     *     *     *     *
|     |     |     |     |     |
|     |     |     |     |     +------ 周几（0 - 7）(0 或 7 表示周日)
|     |     |     |     +------ 月份 (1 - 12)
|     |     |     +------ 日 (1 - 31)
|     |     +------ 小时 (0 - 23)
|     +------ 分钟 (0 - 59)
|
+------ 秒 (0 - 59) 通常省略
```

## cron 配置文件

在 Linux 系统中，cron 通过 `/etc/crontab` 和每个用户的个人配置文件来定义自动任务。`/etc/crontab` 文件是系统级别的配置文件，可以定义全局的自动任务。每个用户的个人配置文件位于 `/var/spool/cron/crontabs/` 目录下，以用户名为文件名。用户可以通过编辑个人的配置文件来定义自己的自动任务。

## cron 命令

除了编辑配置文件以外，还可以使用 `cron` 命令来设置自动任务。`cron` 命令可以在当前用户的 crontab 中添加、编辑或删除自动任务。例如，要添加一个自动任务，可以使用 `crontab -e` 命令来编辑当前用户的 crontab 文件，这会打开一个文本编辑器，可以在其中添加一个新的自动任务；保存并退出编辑器后，新的自动任务就会被添加到当前用户的 crontab 中。

以下是一些常用的 cron 命令：

- `crontab -e`：编辑当前用户的 crontab 文件。
- `crontab -l`：列出当前用户的所有自动任务。
- `crontab -r`：删除当前用户的 crontab 文件。
- `service cron start`：启动 cron 服务。
- `service cron stop`：停止 cron 服务。