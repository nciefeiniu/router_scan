import requests


def ip2geo(ipv4: str) -> dict:
    resp = requests.get(f'http://ip-api.com/json/{ipv4}?lang=zh-CN&fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query')
    return resp.json()


if __name__ == '__main__':
    print(ip2geo('2.255.254.85'))