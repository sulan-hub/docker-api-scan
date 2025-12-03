# test_sensitive_info_disclosure.py
import requests
from urllib.parse import urljoin


def test_sensitive_info_disclosure(base_url, session, timeout, log_func=None):
    """测试敏感信息泄露"""
    vulnerabilities = []

    try:
        # 测试系统信息泄露
        url = urljoin(base_url, "/info")
        response = session.get(url, timeout=timeout)

        if response.status_code == 200:
            info = response.json()
            sensitive_fields = ["DriverStatus", "SystemStatus", "Plugins", "RegistryConfig"]

            for field in sensitive_fields:
                if field in info and info[field]:
                    if log_func:
                        log_func(f"发现敏感信息泄露: {field}", "VULNERABILITY")

                    vulnerabilities.append({
                        "type": "敏感信息泄露",
                        "endpoint": "/info",
                        "url": url,
                        "status_code": response.status_code,
                        "description": f"系统信息中包含敏感字段: {field}",
                        "field_name": field,
                        "field_data": str(info[field])[:100]  # 只保存前100字符，避免数据过大
                    })
                    break

    except requests.exceptions.RequestException as e:
        if log_func:
            log_func(f"测试敏感信息泄露时出错: {str(e)}", "ERROR")

    return vulnerabilities