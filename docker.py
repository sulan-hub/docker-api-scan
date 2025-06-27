#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Docker API 漏洞扫描器
用于检测Docker API的安全漏洞
"""

import requests
import json
import argparse
import sys
import time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime
import socket
import ssl

class DockerAPIScanner:
    def __init__(self, target, port=2375, timeout=10, threads=5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.lock = threading.Lock()

        # 构建基础URL
        if not target.startswith(('http://', 'https://')):
            self.base_url = f"http://{target}:{port}"
        else:
            self.base_url = f"{target}:{port}"

        self.session = requests.Session()
        # 注意：requests.Session没有直接的timeout属性，需要在每个请求中设置

    def log(self, message, level="INFO"):
        """日志记录"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def test_connection(self):
        """测试Docker API连接"""
        try:
            url = f"{self.base_url}/version"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                self.log(f"成功连接到Docker API: {url}")
                return True
            else:
                self.log(f"连接失败，状态码: {response.status_code}", "WARNING")
                return False
        except requests.exceptions.RequestException as e:
            self.log(f"连接错误: {str(e)}", "ERROR")
            return False

    def test_unauthorized_access(self):
        """测试未授权访问"""
        vulnerabilities = []

        # 测试不需要认证的端点
        endpoints = [
            "/version",
            "/info",
            "/containers/json",
            "/images/json",
            "/volumes",
            "/networks",
            "/swarm",
            "/nodes",
            "/services",
            "/tasks"
        ]

        for endpoint in endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=self.timeout)

                if response.status_code == 200:
                    self.log(f"发现未授权访问漏洞: {endpoint}", "VULNERABILITY")
                    vulnerabilities.append({
                        "type": "未授权访问",
                        "endpoint": endpoint,
                        "url": url,
                        "status_code": response.status_code,
                        "description": f"端点 {endpoint} 可以被未授权访问"
                    })
                elif response.status_code == 401:
                    self.log(f"端点 {endpoint} 需要认证", "INFO")

            except requests.exceptions.RequestException as e:
                self.log(f"测试端点 {endpoint} 时出错: {str(e)}", "ERROR")

        return vulnerabilities

    def test_container_escape(self):
        """测试容器逃逸漏洞"""
        vulnerabilities = []

        try:
            container_config ={
                    "Image": "docker.1ms.run/library/alpine",
                    "Cmd": ["chroot", "/host", "bash"],
                    "AttachStdin": True,
                    "AttachStdout": True,
                    "AttachStderr": True,
                    "Tty": True,
                    "OpenStdin": True,
                    "HostConfig": {
                        "Privileged": True,
                        "Binds": ["/:/host"],
                        "AutoRemove": True
                    }
                }

            url = urljoin(self.base_url, "/containers/create")
            response = self.session.post(url, json=container_config, timeout=self.timeout)

            print(response.status_code)

            if response.status_code == 201:
                try:
                    container_id = response.json().get("Id")
                    self.log(f"发现容器逃逸风险: 可以创建特权容器并执行 chroot 命令", "VULNERABILITY")
                    vulnerabilities.append({
                        "type": "容器逃逸",
                        "endpoint": "/containers/create",
                        "url": url,
                        "status_code": response.status_code,
                        "description": "可以创建特权容器并执行 chroot 命令，存在容器逃逸风险",
                        "container_id": container_id
                    })

                    if container_id:
                        try:
                            delete_url = urljoin(self.base_url, f"/containers/{container_id}")
                            self.session.delete(delete_url, timeout=self.timeout)
                        except requests.exceptions.RequestException as e:
                            self.log(f"删除容器时出错: {str(e)}", "ERROR")
                except ValueError as e:
                    self.log(f"解析响应JSON时出错: {str(e)}", "ERROR")

        except requests.exceptions.RequestException as e:
            self.log(f"测试容器逃逸时出错: {str(e)}", "ERROR")

        return vulnerabilities

    def test_image_pull(self):
        """测试镜像拉取权限，并记录镜像ID后删除"""
        vulnerabilities = []
        image_id = None  # 用于存储镜像ID

        try:
            # 测试是否可以拉取镜像
            url = urljoin(self.base_url, "/images/create")
            params = {"fromImage": "alpine:latest"}
            response = self.session.post(url, params=params, timeout=self.timeout)

            if response.status_code == 200:
                # 从响应中提取镜像ID（假设响应体中包含镜像ID）
                response_data = response.json()
                image_id = response_data.get("Id")

                self.log(f"发现镜像拉取漏洞: 可以拉取镜像, 镜像ID: {image_id}", "VULNERABILITY")
                vulnerabilities.append({
                    "type": "镜像拉取",
                    "endpoint": "/images/create",
                    "url": url,
                    "status_code": response.status_code,
                    "description": "可以拉取Docker镜像，可能导致资源消耗攻击",
                    "image_id": image_id
                })

                # 删除拉取的镜像
                if image_id:
                    delete_url = urljoin(self.base_url, f"/images/{image_id}")
                    self.session.delete(delete_url, timeout=self.timeout)
                    # delete_response = self.session.delete(delete_url, timeout=self.timeout)
                    #
                    # if delete_response.status_code == 200:
                    #     self.log(f"成功删除镜像, 镜像ID: {image_id}", "INFO")
                    # else:
                    #     self.log(f"删除镜像失败, 镜像ID: {image_id}, 状态码: {delete_response.status_code}", "ERROR")

        except requests.exceptions.RequestException as e:
            self.log(f"测试镜像拉取时出错: {str(e)}", "ERROR")

        return vulnerabilities

    def test_container_creation(self):
        """测试容器创建权限"""
        vulnerabilities = []

        try:
            # 测试是否可以创建容器
            container_config = {
                "Image": "alpine:latest",
                "Cmd": ["echo", "test"],
                "HostConfig": {
                    "AutoRemove": True
                }
            }

            url = urljoin(self.base_url, "/containers/create")
            response = self.session.post(url, json=container_config, timeout=self.timeout)

            if response.status_code == 201:
                container_id = response.json().get("Id")
                self.log(f"发现容器创建漏洞: 可以创建容器", "VULNERABILITY")
                vulnerabilities.append({
                    "type": "容器创建",
                    "endpoint": "/containers/create",
                    "url": url,
                    "status_code": response.status_code,
                    "description": "可以创建Docker容器，可能导致资源滥用",
                    "container_id": container_id
                })

                # 清理创建的容器
                if container_id:
                    delete_url = urljoin(self.base_url, f"/containers/{container_id}")
                    self.session.delete(delete_url, timeout=self.timeout)

        except requests.exceptions.RequestException as e:
            self.log(f"测试容器创建时出错: {str(e)}", "ERROR")

        return vulnerabilities

    def test_network_access(self):
        """测试网络访问权限"""
        vulnerabilities = []

        try:
            # 测试是否可以创建网络
            network_config = {
                "Name": "test_network",
                "Driver": "bridge"
            }

            url = urljoin(self.base_url, "/networks/create")
            response = self.session.post(url, json=network_config, timeout=self.timeout)

            if response.status_code == 201:
                network_id = response.json().get("Id")
                self.log(f"发现网络创建漏洞: 可以创建网络", "VULNERABILITY")
                vulnerabilities.append({
                    "type": "网络创建",
                    "endpoint": "/networks/create",
                    "url": url,
                    "status_code": response.status_code,
                    "description": "可以创建Docker网络，可能导致网络隔离绕过",
                    "network_id": network_id
                })

                # 清理创建的网络
                if network_id:
                    delete_url = urljoin(self.base_url, f"/networks/{network_id}")
                    self.session.delete(delete_url, timeout=self.timeout)

        except requests.exceptions.RequestException as e:
            self.log(f"测试网络访问时出错: {str(e)}", "ERROR")

        return vulnerabilities

    def test_volume_access(self):
        """测试卷访问权限"""
        vulnerabilities = []

        try:
            # 测试是否可以创建卷
            volume_config = {
                "Name": "test_volume"
            }

            url = urljoin(self.base_url, "/volumes/create")
            response = self.session.post(url, json=volume_config, timeout=self.timeout)

            if response.status_code == 201:
                volume_name = response.json().get("Name")
                self.log(f"发现卷创建漏洞: 可以创建卷", "VULNERABILITY")
                vulnerabilities.append({
                    "type": "卷创建",
                    "endpoint": "/volumes/create",
                    "url": url,
                    "status_code": response.status_code,
                    "description": "可以创建Docker卷，可能导致数据泄露",
                    "volume_name": volume_name
                })

                # 清理创建的卷
                if volume_name:
                    delete_url = urljoin(self.base_url, f"/volumes/{volume_name}")
                    self.session.delete(delete_url, timeout=self.timeout)

        except requests.exceptions.RequestException as e:
            self.log(f"测试卷访问时出错: {str(e)}", "ERROR")

        return vulnerabilities

    def test_swarm_access(self):
        """测试Swarm集群访问权限"""
        vulnerabilities = []

        try:
            # 测试Swarm信息
            url = urljoin(self.base_url, "/swarm")
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                swarm_info = response.json()
                if swarm_info.get("JoinTokens"):
                    self.log(f"发现Swarm集群访问漏洞", "VULNERABILITY")
                    vulnerabilities.append({
                        "type": "Swarm集群访问",
                        "endpoint": "/swarm",
                        "url": url,
                        "status_code": response.status_code,
                        "description": "可以访问Swarm集群信息，包含加入令牌"
                    })

        except requests.exceptions.RequestException as e:
            self.log(f"测试Swarm访问时出错: {str(e)}", "ERROR")

        return vulnerabilities

    def test_sensitive_info_disclosure(self):
        """测试敏感信息泄露"""
        vulnerabilities = []

        try:
            # 测试系统信息泄露
            url = urljoin(self.base_url, "/info")
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                info = response.json()
                sensitive_fields = ["DriverStatus", "SystemStatus", "Plugins", "RegistryConfig"]

                for field in sensitive_fields:
                    if field in info and info[field]:
                        self.log(f"发现敏感信息泄露: {field}", "VULNERABILITY")
                        vulnerabilities.append({
                            "type": "敏感信息泄露",
                            "endpoint": "/info",
                            "url": url,
                            "status_code": response.status_code,
                            "description": f"系统信息中包含敏感字段: {field}"
                        })
                        break

        except requests.exceptions.RequestException as e:
            self.log(f"测试敏感信息泄露时出错: {str(e)}", "ERROR")

        return vulnerabilities

    def scan_all(self):
        """执行完整扫描"""
        self.log(f"开始扫描目标: {self.target}:{self.port}")

        # 测试连接
        if not self.test_connection():
            self.log("无法连接到Docker API，扫描终止", "ERROR")
            return []

        # 定义所有扫描函数
        scan_functions = [
            ("未授权访问", self.test_unauthorized_access),
            ("容器逃逸", self.test_container_escape),# 暂时不支持容器逃逸
            ("镜像拉取", self.test_image_pull),
            ("容器创建", self.test_container_creation),
            ("网络访问", self.test_network_access),
            ("卷访问", self.test_volume_access),
            ("Swarm集群访问", self.test_swarm_access),
            ("敏感信息泄露", self.test_sensitive_info_disclosure)
        ]

        all_vulnerabilities = []

        # 使用线程池执行扫描
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_scan = {executor.submit(func): name for name, func in scan_functions}

            for future in as_completed(future_to_scan):
                scan_name = future_to_scan[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
                    self.log(f"完成 {scan_name} 扫描，发现 {len(vulnerabilities)} 个漏洞")
                except Exception as e:
                    self.log(f"{scan_name} 扫描出错: {str(e)}", "ERROR")

        return all_vulnerabilities

    def generate_report(self, vulnerabilities):
        """生成扫描报告"""
        if not vulnerabilities:
            self.log("未发现漏洞", "INFO")
            return

        self.log(f"发现 {len(vulnerabilities)} 个漏洞", "VULNERABILITY")

        report = {
            "target": f"{self.target}:{self.port}",
            "scan_time": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

        # 按类型分组
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln["type"]
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)

        print("\n" + "="*60)
        print("Docker API 漏洞扫描报告")
        print("="*60)
        print(f"目标: {self.target}:{self.port}")
        print(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"发现漏洞总数: {len(vulnerabilities)}")
        print("-"*60)

        for vuln_type, vulns in vuln_by_type.items():
            print(f"\n【{vuln_type}】 - {len(vulns)} 个")
            for i, vuln in enumerate(vulns, 1):
                print(f"  {i}. {vuln['description']}")
                print(f"     端点: {vuln['endpoint']}")
                print(f"     URL: {vuln['url']}")
                print(f"     状态码: {vuln['status_code']}")

        # 保存报告到文件
        report_file = f"docker_scan_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.log(f"扫描报告已保存到: {report_file}")

        return report

def main():
    parser = argparse.ArgumentParser(description="Docker API 漏洞扫描器")
    parser.add_argument("target", help="目标IP地址或域名")
    parser.add_argument("-p", "--port", type=int, default=2375, help="Docker API端口 (默认: 2375)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="请求超时时间 (默认: 10秒)")
    parser.add_argument("--threads", type=int, default=5, help="并发线程数 (默认: 5)")
    parser.add_argument("--tls", action="store_true", help="使用TLS连接 (端口2376)")

    args = parser.parse_args()

    # 如果使用TLS，修改端口
    if args.tls and args.port == 2375:
        args.port = 2376

    try:
        scanner = DockerAPIScanner(
            target=args.target,
            port=args.port,
            timeout=args.timeout,
            threads=args.threads
        )

        vulnerabilities = scanner.scan_all()
        scanner.generate_report(vulnerabilities)

    except KeyboardInterrupt:
        print("\n扫描被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"扫描出错: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()