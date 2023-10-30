import re
import platform

import subprocess

fsacn = ''
if platform.system().lower() == 'windows':
    fsacn = './fscan64.exe'
elif platform.system().lower() == 'linux':
    fsacn = './fscan_amd64'


def scan_by_fscan(ip: str, proxy=None) -> dict:
    _fscan = fsacn + f' -h {ip} -nobr -no'
    if proxy:
        _fscan += f' -socks5 {proxy}'

    print('use proxy:', proxy)

    try:
        out_bytes = subprocess.check_output([fsacn, '-h', ip, '-nobr', '-no'], timeout=60 * 10)
    except subprocess.TimeoutExpired as e:
        print(e)
        return {}

    result = out_bytes.decode('utf-8')
    p = r'(?:((?:\d|[1-9]\d|1\d{2}|2[0-5][0-5])\.(?:\d|[1-9]\d|1\d{2}|2[0-5][0-5])\.(?:\d|[1-9]\d|1\d{2}|2[0-5][0-5])\.(?:\d|[1-9]\d|1\d{2}|2[0-5][0-5]))\D+?(6[0-5]{2}[0-3][0-5]|[1-5]\d{4}|[1-9]\d{1,3}|[0-9]))'

    ips = re.findall(p, result)

    result = {}
    for row in ips:
        if row[0] not in result:
            result[row[0]] = [row[1]]
        else:
            result[row[0]].append(row[1])
    return result


if __name__ == '__main__':
    print(scan_by_fscan('192.168.31.1-255'))
