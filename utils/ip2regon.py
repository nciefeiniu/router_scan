import requests


def ip2geo(ipv4: str) -> dict:
    resp = requests.get(f'http://ip-api.com/json/{ipv4}?lang=zh-CN')
    return resp.json()


if __name__ == '__main__':
    print(ip2geo('133.242.187.117'))