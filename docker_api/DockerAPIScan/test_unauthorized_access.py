# test_unauthorized_access.py
import requests
from urllib.parse import urljoin


def test_unauthorized_access(base_url, session, timeout, log_func=None):
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
            url = urljoin(base_url, endpoint)
            response = session.get(url, timeout=timeout)

            if response.status_code == 200:
                if log_func:
                    log_func(f"发现未授权访问漏洞: {endpoint}", "VULNERABILITY")
                vulnerabilities.append({
                    "type": "未授权访问",
                    "endpoint": endpoint,
                    "url": url,
                    "status_code": response.status_code,
                    "description": f"端点 {endpoint} 可以被未授权访问"
                })
            elif response.status_code == 401:
                if log_func:
                    log_func(f"端点 {endpoint} 需要认证", "INFO")

        except requests.exceptions.RequestException as e:
            if log_func:
                log_func(f"测试端点 {endpoint} 时出错: {str(e)}", "ERROR")

    return vulnerabilities