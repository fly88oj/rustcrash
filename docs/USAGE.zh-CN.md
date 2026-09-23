# RustCrash 使用说明书

RustCrash 是一个用于在路由器和低配置 x86 主机上运行 Clash/Mihomo 代理的跨平台工具。

> **注意**：本文是深入参考教程。首次安装与日常使用请以
> [README 快速开始](../README.zh-CN.md#快速开始) 和
> [安装指南](INSTALL.md)（英文）为准。

## 目录

- [快速开始](#快速开始)
- [使用方式](#使用方式)
- [命令详解](#命令详解)
- [配置文件](#配置文件)
- [常见问题](#常见问题)

---

## 快速开始

### 1. 安装

```bash
# 从源码编译
cargo build --release

# 可执行文件位于 target/release/rustcrash
```

### 2. 初始化

```bash
# 创建目录结构
sudo ./target/release/rustcrash init

# 目录结构：
#   /etc/rustcrash/          主目录
#   /etc/rustcrash/config/   配置文件
#   /etc/rustcrash/bin/      内核二进制
#   /etc/rustcrash/data/     数据文件
#   /etc/rustcrash/run/      运行时文件
#   /etc/rustcrash/logs/     日志文件
```

### 3. 配置

编辑配置文件：

```bash
sudo vim /etc/rustcrash/config/config.yaml
```

### 4. 下载内核

```bash
# 下载 Mihomo 内核
sudo ./target/release/rustcrash kernel install

# 或手动放置到 /etc/rustcrash/bin/mihomo
```

### 5. 启动

```bash
# 启动代理
sudo ./target/release/rustcrash start start

# 配置防火墙
sudo ./target/release/rustcrash firewall apply
```

---

## 使用方式

RustCrash 提供两种使用方式：

### 交互模式（无参数运行）

```bash
./rustcrash
```

启动 TUI 菜单界面，可视化操作。

### 命令行模式

```bash
# 直接执行子命令
./rustcrash init
./rustcrash config show
./rustcrash start status
./rustcrash firewall generate --backend nftables
```

---

## 命令详解

### rustcrash - 主命令

```bash
# 查看帮助
./rustcrash --help

# 查看版本
./rustcrash --version

# 指定 CrashDir（覆盖默认目录）
./rustcrash --crashdir /opt/rustcrash <command>
```

### init - 初始化

```bash
# 初始化目录结构
sudo ./rustcrash init

# 强制重新初始化
sudo ./rustcrash init --force
```

**功能：**
- 创建 `/etc/rustcrash/` 目录结构
- 生成默认配置文件
- 设置目录权限

### config - 配置管理

```bash
# 显示当前配置
./rustcrash config show

# 验证配置语法
./rustcrash config validate

# 导出配置（用于调试）
./rustcrash config export
```

### firewall - 防火墙管理

```bash
# 生成防火墙规则脚本
sudo ./rustcrash firewall generate --backend nftables
sudo ./rustcrash firewall generate --backend iptables

# 查看当前规则
sudo ./rustcrash firewall show

# 应用防火墙规则
sudo ./rustcrash firewall apply

# 清除防火墙规则
sudo ./rustcrash firewall clear
```

**支持的防火墙后端：**
- `nftables` - 默认，现代 Netfilter 实现
- `iptables` - 传统 Linux 包过滤

### start - 内核控制

```bash
# 启动代理内核
sudo ./rustcrash start start

# 停止代理内核
sudo ./rustcrash start stop

# 重启代理内核
sudo ./rustcrash start restart

# 查看内核状态
./rustcrash start status

# 查看内核日志
./rustcrash start logs
./rustcrash start logs --follow  # 实时跟踪
```

### sub - 订阅转换

```bash
# 检查 subconverter 是否可用
./rustcrash sub check

# 转换订阅（需要先安装 subconverter）
./rustcrash sub convert -i https://your-subscription-url/sub -t clash

# 合并多个订阅
./rustcrash sub merge -u url1 -u url2 -t clash
```

**安装 subconverter：**
```bash
curl -L https://raw.githubusercontent.com/tindy2013/subconverter/master/install.sh | sh
```

### kernel - 内核管理

```bash
# 安装内核
sudo ./rustcrash kernel install

# 指定版本
sudo ./rustcrash kernel install --version v1.18.0

# 卸载内核
sudo ./rustcrash kernel uninstall
```

### task - 定时任务

```bash
# 列出定时任务
./rustcrash task list

# 查看任务详情
./rustcrash task show <task-id>
```

### install - 系统安装

```bash
# 系统级安装
sudo ./rustcrash install
```

**功能：**
- 安装二进制到 `/usr/local/bin/rustcrash`
- 创建系统服务（systemd/openrc）
- 配置开机自启

### setboot - 启动管理

```bash
# 查看启动配置
./rustcrash setboot status

# 检查是否开机自启
./rustcrash setboot is-enabled
```

---

## 配置文件

位置：`/etc/rustcrash/config/config.yaml`

### 默认配置

```yaml
# RustCrash Configuration

# 内核设置
kernel: mihomo  # mihomo 或 sing-box

# 代理模式
mode: rule  # rule（规则）、global（全局）、direct（直连）

# 端口设置
api-port: 9090      # RESTful API 端口
portal-port: 7890   # HTTP/SOCKS5 代理端口

# 防火墙设置
firewall:
  backend: nftables  # nftables 或 iptables
  exclude-ips:       # 排除的 IP 段（不代理）
    - 192.168.0.0/16
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 127.0.0.0/8

# 日志设置
logging:
  level: info  # debug, info, warn, error
```

### 订阅配置

如使用订阅链接：

```yaml
subscription:
  url: "https://your-subscription-url/sub"
  # 可选：自动更新间隔
  interval: 86400  # 秒
```

### 本地配置

如使用本地配置：

```yaml
kernel:
  config: "/etc/rustcrash/config/mihomo.yaml"
```

---

## 防火墙工作原理

```
                    外部流量
                        │
                        ▼
              ┌─────────────────┐
              │  nftables/ipt   │
              │  重定向流量      │
              └────────┬────────┘
                       │ redir
                       ▼
              ┌─────────────────┐
              │   Mihomo 内核    │
              │   (localhost)   │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   代理服务器     │
              └─────────────────┘
```

### 规则说明

1. **局域网排除**：确保内网流量不被代理
2. **DNS 劫持**：53 端口重定向到内核
3. **HTTP/HTTPS 重定向**：80/443 端口重定向到代理端口

---

## 常见问题

### Q: 提示 "Permission denied"

需要 root 权限的操作：
```bash
sudo ./rustcrash init
sudo ./rustcrash start start
sudo ./rustcrash firewall apply
```

### Q: 内核启动失败

1. 检查配置：
   ```bash
   ./rustcrash config validate
   ```

2. 确认内核已安装：
   ```bash
   ./rustcrash start status
   ```

3. 查看日志：
   ```bash
   ./rustcrash start logs
   ```

### Q: 防火墙规则不生效

1. 确认使用正确的后端：
   ```bash
   ./rustcrash --version | grep Firewall
   ```

2. 检查规则：
   ```bash
   sudo nft list ruleset
   sudo iptables -L -n
   ```

### Q: 如何更新订阅？

```bash
# 编辑订阅 URL
sudo vim /etc/rustcrash/config/config.yaml

# 重启内核
sudo ./rustcrash start restart
```

### Q: 如何完全卸载？

```bash
# 停止内核
sudo ./rustcrash start stop

# 清除防火墙规则
sudo ./rustcrash firewall clear

# 删除目录
sudo rm -rf /etc/rustcrash

# 删除二进制
sudo rm /usr/local/bin/rustcrash
```

---

## 目录结构

```
/etc/rustcrash/
├── config/
│   ├── config.yaml      # 主配置
│   └── mihomo.yaml      # 内核配置（可选）
├── bin/
│   └── mihomo          # 内核二进制
├── data/
│   └── geoip.dat       # GeoIP 数据库
├── run/                 # 运行时 PID 文件
└── logs/                # 日志文件
```

---

## 安全建议

1. **使用 HTTPS 订阅**：防止订阅被篡改
2. **限制 API 访问**：API 端口仅本地访问
3. **定期更新**：保持内核和规则最新
4. **检查防火墙**：确保无流量泄露

---

## 获取帮助

```bash
# 查看所有命令
./rustcrash --help

# 查看子命令帮助
./rustcrash <command> --help
```
