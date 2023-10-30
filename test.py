import re

import subprocess


def te():
    try:
        out_bytes = subprocess.check_output(['./fscan64.exe', '-h', '192.168.31.1-255', '-nobr'], timeout=60 * 30)
    except subprocess.TimeoutExpired as e:
        print(e)
        return

    result = out_bytes.decode('utf-8')
    p = r'(?:((?:\d|[1-9]\d|1\d{2}|2[0-5][0-5])\.(?:\d|[1-9]\d|1\d{2}|2[0-5][0-5])\.(?:\d|[1-9]\d|1\d{2}|2[0-5][0-5])\.(?:\d|[1-9]\d|1\d{2}|2[0-5][0-5]))\D+?(6[0-5]{2}[0-3][0-5]|[1-5]\d{4}|[1-9]\d{1,3}|[0-9]))'

    ips = re.findall(p, result)

    print(ips)


if __name__ == '__main__':
    te()