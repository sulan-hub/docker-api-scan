import requests


def test_connection(base_prefix, session, port, timeout=10):
    """测试Docker API连接"""
    try:
        url = f"{base_prefix}:{port}/version"
        response = session.get(url, timeout=timeout)
        if response.status_code == 200:
            # self.log(f"端口 {port}: 成功连接到Docker API", "INFO")
            return True, url
        else:
            # self.log(f"端口 {port}: 连接失败，状态码: {response.status_code}", "WARNING")
            return False, url
    except requests.exceptions.RequestException as e:
        # self.log(f"端口 {port}: 连接错误: {str(e)}", "ERROR")
        return False, None