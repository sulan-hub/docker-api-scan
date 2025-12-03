# parse_ports.py

def parse_ports(ports):
    """解析端口配置函数"""
    if ports is None:
        return [2375]  # 默认端口

    if isinstance(ports, (list, tuple)):
        return list(ports)

    if isinstance(ports, int):
        return [ports]

    if isinstance(ports, str):
        # 处理端口范围格式，如 "2375-2380"
        if '-' in ports:
            try:
                start, end = map(int, ports.split('-'))
                return list(range(start, end + 1))
            except ValueError:
                raise ValueError(f"无效的端口范围格式: {ports}")
        # 处理逗号分隔的多个端口，如 "2375,2376,2377"
        elif ',' in ports:
            try:
                return [int(p.strip()) for p in ports.split(',')]
            except ValueError:
                raise ValueError(f"无效的端口格式: {ports}")
        # 处理单个端口字符串
        else:
            try:
                return [int(ports)]
            except ValueError:
                raise ValueError(f"无效的端口: {ports}")

    raise ValueError(f"不支持的端口格式: {ports}")