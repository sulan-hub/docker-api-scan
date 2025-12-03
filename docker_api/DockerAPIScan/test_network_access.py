# test_network_access.py
import requests
from urllib.parse import urljoin


def test_network_access(base_url, session, timeout, log_func=None):
    """测试网络访问权限"""
    vulnerabilities = []

    try:
        # 测试是否可以创建网络
        network_config = {
            "Name": "test_network",
            "Driver": "bridge"
        }

        url = urljoin(base_url, "/networks/create")
        response = session.post(url, json=network_config, timeout=timeout)

        if response.status_code == 201:
            network_id = response.json().get("Id")
            if log_func:
                log_func(f"发现网络创建漏洞: 可以创建网络", "VULNERABILITY")

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
                delete_url = urljoin(base_url, f"/networks/{network_id}")
                session.delete(delete_url, timeout=timeout)

    except requests.exceptions.RequestException as e:
        if log_func:
            log_func(f"测试网络访问时出错: {str(e)}", "ERROR")

    return vulnerabilities