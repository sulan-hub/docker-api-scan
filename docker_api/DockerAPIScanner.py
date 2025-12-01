#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    def __init__(self, target, ports=2375, timeout=10, threads=5):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.lock = threading.Lock()

        # 解析端口范围
        self.ports = self._parse_ports(ports)

        # 构建基础URL前缀（不包含端口）
        if not target.startswith(('http://', 'https://')):
            self.base_prefix = f"http://{target}"
        else:
            self.base_prefix = target.rstrip('/')

        self.session = requests.Session()
        # 注意：requests.Session没有直接的timeout属性，需要在每个请求中设置

    def _parse_ports(self, ports):
        if ports is None:
            return [2375]  # 默认端口

        if isinstance(ports, (list, tuple)):
            return list(ports)

        if isinstance(ports, int):
            return [ports]

        if isinstance(ports, str):
            # 处理端口范围格式，如 "2375-2380"
            if '-' in ports:
                try:
                    start, end = map(int, ports.split('-'))
                    return list(range(start, end + 1))
                except ValueError:
                    raise ValueError(f"无效的端口范围格式: {ports}")
            # 处理逗号分隔的多个端口，如 "2375,2376,2377"
            elif ',' in ports:
                try:
                    return [int(p.strip()) for p in ports.split(',')]
                except ValueError:
                    raise ValueError(f"无效的端口格式: {ports}")
            # 处理单个端口字符串
            else:
                try:
                    return [int(ports)]
                except ValueError:
                    raise ValueError(f"无效的端口: {ports}")

        raise ValueError(f"不支持的端口格式: {ports}")

    def log(self, message, level="INFO"):
        """日志记录"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def test_connection(self, port):
        """测试Docker API连接"""
        try:
            url = f"{self.base_prefix}:{port}/version"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                self.log(f"端口 {port}: 成功连接到Docker API", "INFO")
                return True, url
            else:
                # self.log(f"端口 {port}: 连接失败，状态码: {response.status_code}", "WARNING")
                return False, url
        except requests.exceptions.RequestException as e:
            # self.log(f"端口 {port}: 连接错误: {str(e)}", "ERROR")
            return False, None

    def scan_port(self, port):
        """扫描单个端口的所有漏洞"""
        port_results = {
            "port": port,
            "accessible": False,
            "base_url": f"{self.base_prefix}:{port}",
            "vulnerabilities": []
        }

        # 测试连接
        accessible, base_url = self.test_connection(port)
        if not accessible:
            return port_results

        port_results["accessible"] = True
        self.base_url = base_url  # 设置当前扫描的基础URL

        # 测试未授权访问
        vulnerabilities = self.test_unauthorized_access()
        port_results["vulnerabilities"].extend(vulnerabilities)

        # 测试镜像拉取
        vulnerabilities = self.test_image_pull()
        port_results["vulnerabilities"].extend(vulnerabilities)

        # 测试容器创建
        vulnerabilities = self.test_container_creation()
        port_results["vulnerabilities"].extend(vulnerabilities)

        # 测试网络访问
        vulnerabilities = self.test_network_access()
        port_results["vulnerabilities"].extend(vulnerabilities)

        # 测试卷访问
        vulnerabilities = self.test_volume_access()
        port_results["vulnerabilities"].extend(vulnerabilities)

        # 测试Swarm集群访问
        vulnerabilities = self.test_swarm_access()
        port_results["vulnerabilities"].extend(vulnerabilities)

        # 测试敏感信息泄露
        vulnerabilities = self.test_sensitive_info_disclosure()
        port_results["vulnerabilities"].extend(vulnerabilities)

        return port_results

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
        """执行完整扫描 - 扫描所有端口"""
        self.log(f"开始扫描目标: {self.target}", "INFO")
        self.log(f"扫描端口范围: {self.ports}", "INFO")
        self.log(f"线程数: {self.threads}", "INFO")
        print("="*60)

        all_results = []

        # 使用线程池并发扫描所有端口
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 提交所有端口扫描任务
            future_to_port = {executor.submit(self.scan_port, port): port for port in self.ports}

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    all_results.append(result)

                    # 记录扫描结果
                    if result["accessible"]:
                        vuln_count = len(result["vulnerabilities"])
                        if vuln_count > 0:
                            self.log(f"端口 {port}: 发现 {vuln_count} 个漏洞", "VULNERABILITY")
                        else:
                            self.log(f"端口 {port}: 未发现漏洞", "INFO")
                    else:
                        self.log(f"端口 {port}: 无法访问", "WARNING")

                except Exception as e:
                    self.log(f"端口 {port} 扫描出错: {str(e)}", "ERROR")

        print("="*60)
        self.log(f"扫描完成! 共扫描 {len(self.ports)} 个端口", "INFO")

        # 收集所有漏洞
        all_vulnerabilities = []
        for result in all_results:
            if result["accessible"]:
                for vuln in result["vulnerabilities"]:
                    vuln["port"] = result["port"]
                    all_vulnerabilities.append(vuln)

        return all_vulnerabilities, all_results

    def generate_report(self, vulnerabilities, scan_results):
        """生成扫描报告"""
        if not scan_results:
            self.log("没有扫描结果", "INFO")
            return

        print("\n" + "="*80)
        print("Docker API 多端口漏洞扫描报告")
        print("="*80)
        print(f"目标: {self.target}")
        print(f"扫描端口数: {len(self.ports)}")
        print(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-"*80)

        # 统计信息
        accessible_ports = [r for r in scan_results if r["accessible"]]
        vulnerable_ports = [r for r in accessible_ports if r["vulnerabilities"]]

        print(f"可访问端口: {len(accessible_ports)}/{len(self.ports)}")
        print(f"存在漏洞的端口: {len(vulnerable_ports)}/{len(accessible_ports)}")
        print(f"发现漏洞总数: {len(vulnerabilities)}")
        print("-"*80)

        # 按端口显示结果
        for result in scan_results:
            port = result["port"]
            accessible = result["accessible"]

            if accessible:
                vuln_count = len(result["vulnerabilities"])
                status = "存在漏洞" if vuln_count > 0 else "安全"
                print(f"\n端口 {port}: {status} ({vuln_count} 个漏洞)")
                print(f"URL: {result['base_url']}")

                if vuln_count > 0:
                    for i, vuln in enumerate(result["vulnerabilities"], 1):
                        print(f"  {i}. [{vuln['type']}] {vuln['description']}")
            else:
                print(f"\n端口 {port}: 无法访问")

        # 按漏洞类型统计
        if vulnerabilities:
            vuln_by_type = {}
            for vuln in vulnerabilities:
                vuln_type = vuln["type"]
                if vuln_type not in vuln_by_type:
                    vuln_by_type[vuln_type] = []
                vuln_by_type[vuln_type].append(vuln)

            print("\n" + "-"*80)
            print("漏洞类型统计:")
            for vuln_type, vulns in vuln_by_type.items():
                print(f"  {vuln_type}: {len(vulns)} 个")

        # 保存报告到文件
        report = {
            "target": self.target,
            "ports": self.ports,
            "scan_time": datetime.now().isoformat(),
            "total_ports": len(self.ports),
            "accessible_ports": len(accessible_ports),
            "vulnerable_ports": len(vulnerable_ports),
            "total_vulnerabilities": len(vulnerabilities),
            "scan_results": scan_results,
            "vulnerabilities": vulnerabilities
        }

        report_file = f"docker_scan_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.log(f"扫描报告已保存到: {report_file}", "INFO")

        return report