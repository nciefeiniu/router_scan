import os
import subprocess
from xml.etree import ElementTree as ET

from nmap3 import NmapCommandParser


ports = '21-23,80-90,135,137,161,389,443,445,873,1099,1433,1521,1900,2082,2083,2222,2375,2376,2601,2604,3128,3306,3311,3312,3389,4440,4848,5001,5432,5560,5900-5902,6082,6379,7001-7010,7778,8009,8080-8090,8649,8888,9000,9200,10000,11211,27017,28017,50000,51111,50030,50060'


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
        _command = ['nmap', '-v', '-oX', '-', ip, '-O', '-T2', '-sT', '-Pn', '--min-hostgroup', '1024',
                    '--min-parallelism', '1', '-p',
                    ports]  # -sT -Pn 不走icmp和ping协议，因为socks的代理，只能使用tcp协议，
        if proxy:
            _command.insert(0, 'proxychains')
        xml_root = self.get_xml_et(self.run_command(_command))

        return NmapCommandParser(None).os_identifier_parser(xml_root)


if __name__ == '__main__':
    result = ScanByNmap().scan_by_nmap('192.168.31.1')
    print(result)
