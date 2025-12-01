# Docker API 漏洞扫描器

这是一个用于检测Docker API安全漏洞的Python扫描器。

## 功能特性

### 检测的漏洞类型

1. **未授权访问漏洞**
   - 检测Docker API端点是否可以被未授权访问
   - 测试的端点包括：/version, /info, /containers/json, /images/json等

2. **容器逃逸漏洞**
   - 检测是否可以创建特权容器
   - 测试主机目录挂载权限

3. **镜像拉取权限**
   - 检测是否可以拉取Docker镜像
   - 可能导致资源消耗攻击

4. **容器创建权限**
   - 检测是否可以创建Docker容器
   - 可能导致资源滥用

5. **网络访问权限**
   - 检测是否可以创建Docker网络
   - 可能导致网络隔离绕过

6. **卷访问权限**
   - 检测是否可以创建Docker卷
   - 可能导致数据泄露

7. **Swarm集群访问**
   - 检测Swarm集群信息泄露
   - 包含加入令牌等敏感信息

8. **敏感信息泄露**
   - 检测系统信息中的敏感字段
   - 如DriverStatus、SystemStatus等

## 安装依赖

### 拉取仓库
```bash
git clone https://github.com/sulan-hub/docker-api-scan
cd docker-api-scan-main
```

```bash
pip install requests
```

## 使用方法

### 基本用法

```bash
# 扫描默认端口2375
python dk.py 192.168.1.100

# 指定端口
python dk.py 192.168.1.100 -p 2376

# 使用TLS连接（自动切换到2376端口）
python dk.py 192.168.1.100 --tls

# 设置超时时间
python dk.py 192.168.1.100 -t 15

# 设置并发线程数
python dk.py 192.168.1.100 --threads 10
```

### 命令行参数

- `target`: 目标IP地址或域名（必需）
- `-p, --port`: Docker API端口（默认: 2375）
- `-t, --timeout`: 请求超时时间（默认: 10秒）
- `--threads`: 并发线程数（默认: 5）
- `--tls`: 使用TLS连接（端口2376）

## 输出示例

```
[2024-01-15 10:30:00] [INFO] 开始扫描目标: 192.168.1.100:2375
[2024-01-15 10:30:01] [INFO] 成功连接到Docker API: http://192.168.1.100:2375/version
[2024-01-15 10:30:02] [VULNERABILITY] 发现未授权访问漏洞: /info
[2024-01-15 10:30:03] [VULNERABILITY] 发现容器创建漏洞: 可以创建容器
[2024-01-15 10:30:04] [INFO] 完成 未授权访问 扫描，发现 3 个漏洞

============================================================
Docker API 漏洞扫描报告
============================================================
目标: 192.168.1.100:2375
扫描时间: 2024-01-15 10:30:05
发现漏洞总数: 5
------------------------------------------------------------

【未授权访问】 - 3 个
  1. 端点 /info 可以被未授权访问
     端点: /info
     URL: http://192.168.1.100:2375/info
     状态码: 200

【容器创建】 - 1 个
  1. 可以创建Docker容器，可能导致资源滥用
     端点: /containers/create
     URL: http://192.168.1.100:2375/containers/create
     状态码: 201

【敏感信息泄露】 - 1 个
  1. 系统信息中包含敏感字段: DriverStatus
     端点: /info
     URL: http://192.168.1.100:2375/info
     状态码: 200
```

## 安全建议

### 修复未授权访问

1. **启用TLS加密**
   ```bash
   # 在Docker守护进程配置中启用TLS
   dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376
   ```

2. **配置认证**
   ```bash
   # 使用证书认证
   dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376
   ```

3. **限制网络访问**
   ```bash
   # 只允许本地访问
   dockerd -H unix:///var/run/docker.sock
   ```

### 安全配置示例

```json
{
  "hosts": ["unix:///var/run/docker.sock"],
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/path/to/ca.pem",
  "tlscert": "/path/to/server-cert.pem",
  "tlskey": "/path/to/server-key.pem"
}
```

## 注意事项

1. **合法使用**: 请确保您有权限扫描目标系统
2. **测试环境**: 建议在测试环境中使用
3. **资源清理**: 扫描器会自动清理测试过程中创建的容器、网络和卷
4. **报告保存**: 扫描报告会自动保存为JSON文件

## 常见问题

### Q: 连接被拒绝怎么办？
A: 检查目标是否开启了Docker API，默认端口是2375（HTTP）或2376（HTTPS）

### Q: 扫描速度慢怎么办？
A: 可以增加并发线程数：`--threads 10`

### Q: 如何扫描多个目标？
A: 可以编写脚本循环调用扫描器

## 免责声明

本工具仅用于安全测试和漏洞评估。使用者需要确保：
- 获得目标系统的授权
- 遵守相关法律法规
- 不用于恶意攻击

## 许可证

MIT License 
