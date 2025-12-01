#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os


from docker_api.DockerAPIScanner import DockerAPIScanner


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Docker API 漏洞扫描器 (支持多端口扫描)")
    parser.add_argument("target", help="目标IP地址或域名")
    parser.add_argument("-p", "--ports", default="2375",
                        help="Docker API端口 (默认: 2375)。支持格式: 2375, 2375-2380, 2375,2376,2377")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="请求超时时间 (默认: 10秒)")
    parser.add_argument("--threads", type=int, default=5, help="并发线程数 (默认: 5)")
    parser.add_argument("--tls", action="store_true", help="使用TLS连接 (如果使用TLS，建议配合--ports参数)")

    args = parser.parse_args()

    try:
        scanner = DockerAPIScanner(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            threads=args.threads
        )

        vulnerabilities, scan_results = scanner.scan_all()
        scanner.generate_report(vulnerabilities, scan_results)

    except KeyboardInterrupt:
        print("\n扫描被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"扫描出错: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()