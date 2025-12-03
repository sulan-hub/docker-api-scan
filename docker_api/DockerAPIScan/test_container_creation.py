# test_container_creation.py
import requests
from urllib.parse import urljoin


def test_container_creation(base_url, session, timeout, log_func=None):
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

        url = urljoin(base_url, "/containers/create")
        response = session.post(url, json=container_config, timeout=timeout)

        if response.status_code == 201:
            container_id = response.json().get("Id")
            if log_func:
                log_func(f"发现容器创建漏洞: 可以创建容器", "VULNERABILITY")

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
                delete_url = urljoin(base_url, f"/containers/{container_id}")
                session.delete(delete_url, timeout=timeout)

    except requests.exceptions.RequestException as e:
        if log_func:
            log_func(f"测试容器创建时出错: {str(e)}", "ERROR")

    return vulnerabilities