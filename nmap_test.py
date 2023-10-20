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
    # nmap_3 = nmap3.Nmap()
    # os_results = nmap_3.nmap_list_scan("192.168.31.1-200", args='-T4')  # MOST BE ROOT
    # pprint(os_results)
    nmap_3 = nmap3.NmapScanTechniques()
    result = nmap_3.nmap_idle_scan("192.168.178.1")
    pprint(result)

if __name__ == '__main__':
    nmap3_t()