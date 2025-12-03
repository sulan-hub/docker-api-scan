# test_volume_access.py
import requests
from urllib.parse import urljoin


def test_volume_access(base_url, session, timeout, log_func=None):
    """测试卷访问权限"""
    vulnerabilities = []

    try:
        # 测试是否可以创建卷
        volume_config = {
            "Name": "test_volume"
        }

        url = urljoin(base_url, "/volumes/create")
        response = session.post(url, json=volume_config, timeout=timeout)

        if response.status_code == 201:
            volume_name = response.json().get("Name")
            if log_func:
                log_func(f"发现卷创建漏洞: 可以创建卷", "VULNERABILITY")

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
                delete_url = urljoin(base_url, f"/volumes/{volume_name}")
                session.delete(delete_url, timeout=timeout)

    except requests.exceptions.RequestException as e:
        if log_func:
            log_func(f"测试卷访问时出错: {str(e)}", "ERROR")

    return vulnerabilities