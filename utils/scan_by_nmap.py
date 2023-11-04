import os
import subprocess
from xml.etree import ElementTree as ET

from nmap3 import NmapCommandParser


class ScanByNmap:
    @staticmethod
    def run_command(cmd, timeout=None):

        sub_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output, errs = sub_proc.communicate(timeout=timeout)
        except Exception as e:
            sub_proc.kill()
            raise (e)
        else:
            if 0 != sub_proc.returncode:
                raise Exception('Error during command: "' + ' '.join(cmd) + '"\n\n' + errs.decode('utf8'))

            # Response is bytes so decode the output and return
            return output.decode('utf8').strip()

    @staticmethod
    def get_xml_et(command_output):
        return ET.fromstring(command_output)

    def scan_by_namp(self, ip: str, proxy: str = None):
        _command = ['nmap', '-v', '-oX', '-', ip, '-O', '-T4', '-PE', '-n', '--min-hostgroup', '1024', '--min-parallelism', '1024', '-sS']
        if proxy:
            proxy = proxy.replace(':', ' ')
            with open('/etc/proxychains.conf', 'w', encoding='utf-8') as f:
                f.write(f"""
strict_chain
tcp_read_time_out 1500000
tcp_connect_time_out 8000000
[ProxyList]
socks5 {proxy}""")
            _command.insert(0, 'proxychains4')
        xml_root = self.get_xml_et(self.run_command(_command))

        return NmapCommandParser(None).os_identifier_parser(xml_root)


if __name__ == '__main__':
    result = ScanByNmap().scan_by_namp('192.168.31.1')
    print(result)