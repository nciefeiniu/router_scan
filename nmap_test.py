import nmap
from pprint import pprint


def nmap_t():
    nm = nmap.PortScanner()
    result = nm.scan('100.33.263.10-200', '22,80')
    print(result)

    for result in result["scan"].values():
        if result["status"]["state"] == "up":
            try:
                host_list = result["addresses"]["ipv4"]
            except:
                host_list = ""
            try:
                vendor = result["vendor"]
            except:
                vendor = ""
            try:
                reason = result["status"]["reason"]
            except:
                reason = ""
            try:
                port = result["portused"]
            except:
                port = ""
            try:
                os = result["osmatch"]
            except:
                os = ""
            data = {"host": host_list, "vendor": vendor, "reason": reason, "port": port, "os": os}

            print(data)


def nmap3_t():
    import nmap3
    nmap_3 = nmap3.Nmap()
    os_results = nmap_3.nmap_os_detection("192.168.1.1-254", args='-T4 -PE -n --min-hostgroup 1024 --min-parallelism 1024 -sS')  # MOST BE ROOT
    pprint(os_results)

    for k, item in os_results.items():
        if k in ('task_results', 'runtime', 'stats'):
            continue
        if not item:
            continue
        _mac = (item.get('macaddress', {}) or {}).get('addr')
        os_info = item.get('osmatch', [])
        for _ in os_info:
            name = _.get('name')
            os_family = _.get('osclass', {}).get('osfamily')
            os_gen = _.get('osclass', {}).get('osgen')
            os_type = _.get('osclass', {}).get('type')
            os_vendor = _.get('osclass', {}).get('vendor')


if __name__ == '__main__':
    nmap3_t()
