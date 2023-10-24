import json

with open('mac-vendors-export.json', 'r', encoding='utf-8') as f:
    base_data = json.loads(f.read())

MAC2PRODUCT_MAP = {_['macPrefix']: _['vendorName'] for _ in base_data}


def mac2producer(mac: str):
    if not mac:
        return None
    mac = mac[:8]
    return MAC2PRODUCT_MAP.get(mac)


if __name__ == '__main__':
    res = mac2producer('D4:35:38:AE:CB:A1')

    print(res)