# test_swarm_access.py
import requests
from urllib.parse import urljoin


def test_swarm_access(base_url, session, timeout, log_func=None):
    """测试Swarm集群访问权限"""
    vulnerabilities = []

    try:
        # 测试Swarm信息
        url = urljoin(base_url, "/swarm")
        response = session.get(url, timeout=timeout)

        if response.status_code == 200:
            swarm_info = response.json()
            if swarm_info.get("JoinTokens"):
                if log_func:
                    log_func(f"发现Swarm集群访问漏洞", "VULNERABILITY")

                vulnerabilities.append({
                    "type": "Swarm集群访问",
                    "endpoint": "/swarm",
                    "url": url,
                    "status_code": response.status_code,
                    "description": "可以访问Swarm集群信息，包含加入令牌",
                    "join_tokens": swarm_info.get("JoinTokens")
                })

    except requests.exceptions.RequestException as e:
        if log_func:
            log_func(f"测试Swarm访问时出错: {str(e)}", "ERROR")

    return vulnerabilities