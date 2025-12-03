# test_image_pull.py
import requests
from urllib.parse import urljoin


def test_image_pull(base_url, session, timeout, log_func=None):
    """测试镜像拉取权限，并记录镜像ID后删除"""
    vulnerabilities = []
    image_id = None  # 用于存储镜像ID

    try:
        # 测试是否可以拉取镜像
        url = urljoin(base_url, "/images/create")
        params = {"fromImage": "alpine:latest"}
        response = session.post(url, params=params, timeout=timeout)

        if response.status_code == 200:
            # 从响应中提取镜像ID（假设响应体中包含镜像ID）
            response_data = response.json()
            image_id = response_data.get("Id")

            if log_func:
                log_func(f"发现镜像拉取漏洞: 可以拉取镜像, 镜像ID: {image_id}", "VULNERABILITY")

            vulnerabilities.append({
                "type": "镜像拉取",
                "endpoint": "/images/create",
                "url": url,
                "status_code": response.status_code,
                "description": "可以拉取Docker镜像，可能导致资源消耗攻击",
                "image_id": image_id
            })

            # 删除拉取的镜像
            if image_id:
                delete_url = urljoin(base_url, f"/images/{image_id}")
                session.delete(delete_url, timeout=timeout)
                # delete_response = session.delete(delete_url, timeout=timeout)
                #
                # if delete_response.status_code == 200:
                #     if log_func:
                #         log_func(f"成功删除镜像, 镜像ID: {image_id}", "INFO")
                # else:
                #     if log_func:
                #         log_func(f"删除镜像失败, 镜像ID: {image_id}, 状态码: {delete_response.status_code}", "ERROR")

    except requests.exceptions.RequestException as e:
        if log_func:
            log_func(f"测试镜像拉取时出错: {str(e)}", "ERROR")

    return vulnerabilities