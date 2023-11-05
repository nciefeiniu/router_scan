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

    def scan_by_nmap(self, ip: str, proxy: str = None):
        _command = ['nmap', '-v', '-oX', '-', ip, '-O', '-T1', '-sT', '-Pn', '--min-hostgroup', '1024',
                    '--min-parallelism', '1', '-p',
                    '80,89,8000,9090,1433,1521,3306,5432,445,135,443,873,5984,6379,7001,7002,9200,9300,11211,27017,27018,50000,50070,50030,21,22,23,2601,3389']  # -sT -Pn 不走icmp和ping协议，因为socks的代理，只能使用tcp协议，
        if proxy:
            _command.insert(0, 'proxychains')
        xml_root = self.get_xml_et(self.run_command(_command))

        return NmapCommandParser(None).os_identifier_parser(xml_root)


if __name__ == '__main__':
    result = ScanByNmap().scan_by_nmap('192.168.31.1')
    print(result)
