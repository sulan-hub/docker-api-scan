# scan_port.py 需要修改：

def scan_port(scanner_instance, port):
    """扫描单个端口的所有漏洞"""
    port_results = {
        "port": port,
        "accessible": False,
        "base_url": f"{scanner_instance.base_prefix}:{port}",
        "vulnerabilities": []
    }

    # 测试连接
    accessible, base_url = scanner_instance.test_connection(port)
    if not accessible:
        return port_results

    port_results["accessible"] = True
    port_results["base_url"] = base_url  # 更新为实际的URL

    # 设置当前扫描的base_url
    scanner_instance.base_url = base_url

    # 执行所有漏洞测试
    for test_func in scanner_instance.vulnerability_tests:
        vulnerabilities = test_func()  # 这里test_func是实例方法，会自动获取self
        port_results["vulnerabilities"].extend(vulnerabilities)

    return port_results