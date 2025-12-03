#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import sys

import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime

from docker_api.DockerAPIScan.parse_ports import parse_ports
from docker_api.DockerAPIScan.scan_port import scan_port
from docker_api.DockerAPIScan.test_connection import test_connection
from docker_api.DockerAPIScan.test_container_creation import test_container_creation
from docker_api.DockerAPIScan.test_image_pull import test_image_pull
from docker_api.DockerAPIScan.test_network_access import test_network_access
from docker_api.DockerAPIScan.test_sensitive_info_disclosure import test_sensitive_info_disclosure
from docker_api.DockerAPIScan.test_swarm_access import test_swarm_access
from docker_api.DockerAPIScan.test_unauthorized_access import test_unauthorized_access
from docker_api.DockerAPIScan.test_volume_access import test_volume_access
from docker_api.DockerAttack import run_pratt, run_shell


class DockerAPI:
    def __init__(self, target, ports=2375, timeout=10, threads=5):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.results = []
        # self.lock = threading.Lock()

        # 添加必要的属性
        self.base_url = None  # 当前扫描的基础URL

        # 解析端口范围
        self.ports = parse_ports(ports)

        # 构建基础URL前缀
        if not target.startswith(('http://', 'https://')):
            self.base_prefix = f"http://{target}"
        else:
            self.base_prefix = target.rstrip('/')

        self.session = requests.Session()

        # 初始化漏洞测试方法列表
        self._init_vulnerability_tests()

    def _init_vulnerability_tests(self):
        """初始化漏洞测试方法列表"""
        self.vulnerability_tests = [
            self.test_unauthorized_access,
            self.test_image_pull,
            self.test_container_creation,
            self.test_network_access,
            self.test_volume_access,
            self.test_swarm_access,
            self.test_sensitive_info_disclosure
        ]

    def parse_ports(self, ports):
        """端口函数调用（兼容旧接口）"""
        return parse_ports(ports)

    def log(self, message, level="INFO"):
        """日志记录"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def test_connection(self, port):
        """测试Docker API连接"""
        return test_connection(self.base_prefix, self.session, port, self.timeout)

    def scan_port(self, port):
        """扫描单个端口的所有漏洞"""
        # 使用独立的scan_port函数
        return scan_port(self, port)

    def test_unauthorized_access(self):
        """测试未授权访问（包装函数）"""
        if not self.base_url:
            return []

        return test_unauthorized_access(
            base_url=self.base_url,
            session=self.session,
            timeout=self.timeout,
            log_func=self.log
        )

    def test_image_pull(self):
        """测试镜像拉取（包装函数）"""
        if not self.base_url:
            return []

        return test_image_pull(
            base_url=self.base_url,
            session=self.session,
            timeout=self.timeout,
            log_func=self.log
        )

    def test_container_creation(self):
        """测试容器创建（包装函数）"""
        if not self.base_url:
            return []

        return test_container_creation(
            base_url=self.base_url,
            session=self.session,
            timeout=self.timeout,
            log_func=self.log
        )

    def test_network_access(self):
        """测试网络访问权限（包装函数）"""
        if not self.base_url:
            return []

        return test_network_access(
            base_url=self.base_url,
            session=self.session,
            timeout=self.timeout,
            log_func=self.log
        )

    def test_volume_access(self):
        """测试卷访问权限（包装函数）"""
        if not self.base_url:
            return []

        return test_volume_access(
            base_url=self.base_url,
            session=self.session,
            timeout=self.timeout,
            log_func=self.log
        )

    def test_swarm_access(self):
        """测试Swarm集群访问权限（包装函数）"""
        if not self.base_url:
            return []

        return test_swarm_access(
            base_url=self.base_url,
            session=self.session,
            timeout=self.timeout,
            log_func=self.log
        )

    def test_sensitive_info_disclosure(self):
        """测试敏感信息泄露（包装函数）"""
        if not self.base_url:
            return []

        return test_sensitive_info_disclosure(
            base_url=self.base_url,
            session=self.session,
            timeout=self.timeout,
            log_func=self.log
        )

    def run_pratt(self, port, image_name="alpine"):
        """执行攻击准备 - 下载指定镜像"""
        return run_pratt(self.target, port, image_name, self.timeout)

    def run_shell(self, port, image_name="alpine"):
        """在远程Docker容器中执行交互式shell"""
        return run_shell(self.target, port, image_name)

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
        import os
        if not os.path.exists("logs"):
            os.makedirs("logs")

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

        report_file = f"logs/docker_scan_report_{self.target.replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.log(f"扫描报告已保存到: {report_file}", "INFO")

        return report