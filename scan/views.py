import re
import json
import uuid
import traceback

from datetime import datetime, timedelta

from django.views import View

from django.http.response import JsonResponse

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor
from django_apscheduler.jobstores import DjangoJobStore
from django.db import transaction

from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR

from scan.models import ScanResult, ScanTask, RouterCVE
from utils.ip2regon import ip2geo
from utils.mac2producer import mac2producer
from utils.task_id import get_task_id
from scan.find_cve import find_cve
from utils.scan_by_nmap import ScanByNmap

jobstores = {
    'default': DjangoJobStore()
    # 'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
}
executors = {
    'default': ThreadPoolExecutor(100),
    'processpool': ProcessPoolExecutor(5)
}
job_defaults = {
    'coalesce': False,
    'max_instances': 3
}


def my_listerner(event):
    if event.exception:
        print('任务出错了！')
    else:
        print('任务正常运行中...')


scheduler = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults)
scheduler.add_listener(my_listerner, EVENT_JOB_ERROR | EVENT_JOB_EXECUTED)
scheduler.start()


def check_ip(ip_addr: str) -> bool:
    compile_ip = re.compile(
        '^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ip_addr):
        return True
    else:
        return False


class LoginView(View):
    """
    登录。这里因为主要是做扫描检测，登陆注册就不细写

    只要账户密码都是admin即可登录
    """

    def post(self, request):
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        if username != 'admin' or username != password:
            return JsonResponse({'code': 60204, 'message': '账户或者密码错误'})
        return JsonResponse({'code': 20000, 'data': 'test-token'})


class UserInfoView(View):
    """
    获取用户基本信息

    这里也是直接返回
    """

    def get(self, request):
        return JsonResponse({'code': 20000, 'data': {
            'roles': ['admin'],
            'introduction': 'I am a super administrator',
            'avatar': 'https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif',
            'name': 'Super Admin'}})


class LogoutView(View):
    """
    同样是直接返回
    """

    def post(self, request):
        return JsonResponse({'code': 20000, 'data': 'success'})


def save_cve(device_name: str, task_id: str, scan_result_id):
    """
    根据cve找漏洞，并存储
    """
    if not device_name:
        return
    for row in find_cve(device_name):
        RouterCVE(task_id=task_id, scan_result_id=scan_result_id, cve_id=row['cve_id'],
                  cve_desc=row['description']).save()


@transaction.atomic
def _scan_host(ip: str, task_id, child_id, proxy):
    os_results = ScanByNmap().scan_by_nmap(ip, proxy)  # 需要root权限，这是获取主机的IP以及判断主机的类型
    st = ScanTask.objects.select_for_update().get(scan_id=task_id)  # 加锁，防止多线程同时修改出问题
    try:
        for k, item in os_results.items():
            if k in ('task_results', 'runtime', 'stats'):
                continue
            if not item:
                continue
            _mac = (item.get('macaddress', {}) or {}).get('addr')
            os_info = item.get('osmatch', [])
            ports = [row.get('portid') for row in item.get('ports', [])]
            ports = [_ for _ in ports if _]
            for _ in os_info:
                name = _.get('name')
                os_family = _.get('osclass', {}).get('osfamily')
                os_gen = _.get('osclass', {}).get('osgen')
                os_type = _.get('osclass', {}).get('type')  # 只需要 WAP 和 broadband router or switch
                if os_type not in ('WAP', 'broadband router', 'switch'):
                    continue
                os_vendor = _.get('osclass', {}).get('vendor')

                if not ScanResult.objects.filter(ip_v4=k).exists():
                    resp = ip2geo(k)
                else:
                    cache = ScanResult.objects.filter(ip_v4=k)[0]
                    resp = {'status': 'success', 'country': cache.country_name, 'lat': cache.latitude,
                            'lon': cache.longitude, 'continent': cache.region}
                _sr = ScanResult(ip_v4=k, device_name=name, os_name=name, type=os_type, vendor=os_vendor, os_gen=os_gen,
                                 os_family=os_family, mac_address=_mac, producer=mac2producer(_mac), task_id=st.id,
                                 open_ports=','.join(ports))

                if resp['status'] != 'success':
                    _sr.country_name = ''
                    _sr.latitude = 0
                    _sr.longitude = 0
                else:
                    _sr.country_name = resp['country']
                    _sr.latitude = resp['lat']
                    _sr.longitude = resp['lon']
                    _sr.region = resp['continent']
                _sr.save()
                save_cve(name, st.id, _sr.id)  # 查找CVE漏洞，并存储下来
    except:
        print(traceback.format_exc())
    st.child_task_status[child_id] = True
    print(f'更新子任务: {child_id}     is True')
    _ok = True
    for _v in st.child_task_status.values():
        if _v is False:
            _ok = False
            break
    if _ok:
        st.status = 1
    st.save()


class ScanView(View):
    """
    扫描接口
    """
    ip_num = 10

    def post(self, request):
        """
        需要携带start_ip 和 end_ip 进行扫描

        并且IP必须合法，而且起始和结束IP也必须合法
        """
        data = json.loads(request.body)
        start_ip = data.get('start_ip')
        end_ip = data.get('end_ip')
        proxy = data.get('proxy') or None
        quickly = data.get('quickly', '1')  # 如果 是1 就是进行快速扫描，如果是0就是慢速

        proxy = proxy.replace(':', ' ')
        with open('/etc/proxychains.conf', 'w', encoding='utf-8') as f:
            f.write(f"""
strict_chain
tcp_read_time_out 1500000
tcp_connect_time_out 8000000
[ProxyList]
socks5 {proxy}""")
        if not check_ip(start_ip) or not check_ip(end_ip):
            return JsonResponse({'code': 500, 'message': 'IP地址不合法'})

        start_ip = start_ip.split('.')
        end_ip = end_ip.split('.')

        for _i in range(3):
            if start_ip[_i] != end_ip[_i]:
                return JsonResponse({'code': 50000, 'message': 'IP起始地址不在同一网段！'})
        if int(start_ip[-1]) > int(end_ip[-1]):
            return JsonResponse({'code': 50000, 'message': 'IP起始地址不能大于结束地址！'})

        _start_num = int(start_ip[-1])
        _end_num = int(end_ip[-1])

        task_id = get_task_id()

        child_tasks = {}
        if quickly == '1':
            # 快速扫描，把ip按段划分，然后塞给Apshceduler进行扫描
            _tmp = _start_num + self.ip_num
            _seconds = 10
            while _tmp < _end_num:
                _child_id = get_task_id()
                child_tasks[_child_id] = False
                scheduler.add_job(_scan_host,
                                  args=('.'.join(start_ip[:3]) + f'.{_start_num}-{_tmp}', task_id, _child_id, proxy),
                                  trigger='date',
                                  next_run_time=datetime.now() + timedelta(seconds=_seconds),
                                  id=f'{int(datetime.now().timestamp())}_{_tmp}')
                _start_num = _tmp
                _tmp += self.ip_num
                _seconds += 1
            else:
                _seconds += 1
                _child_id = get_task_id()
                child_tasks[_child_id] = False
                scheduler.add_job(_scan_host,
                                  args=('.'.join(start_ip[:3]) + f'.{_start_num}-{_end_num}', task_id, _child_id),
                                  trigger='date',
                                  next_run_time=datetime.now() + timedelta(seconds=_seconds),
                                  id=f'{int(datetime.now().timestamp())}_{_tmp}')

        _st = ScanTask(scan_id=task_id, child_task_status=child_tasks)
        _st.save()

        return JsonResponse({'code': 20000, 'message': '扫描中~', 'data': {
            'scan_id': _st.scan_id
        }})


class CheckScanStatus(View):
    def get(self, request):
        scan_id = request.GET.get('scan_id')
        if not scan_id:
            return JsonResponse({'code': 50000, 'message': '参数错误！'})
        if not ScanTask.objects.filter(scan_id=scan_id).exists():
            return JsonResponse({'code': 50000, 'message': '任务不存在！'})

        _st = ScanTask.objects.get(scan_id=scan_id)

        data = []
        geos = []
        if _st.status == 1:
            for row in ScanResult.objects.filter(task_id=_st.id):
                data.append({
                    'id': str(uuid.uuid4()),
                    'ip_v4': row.ip_v4,
                    'device_name': row.device_name,
                    'country': row.country_name,
                    'latitude': row.latitude,
                    'longitude': row.longitude,
                    'ports': row.open_ports,
                    'children': [
                        {
                            'id': str(uuid.uuid4()),
                            'device_name': _.cve_id,
                            'ip_v4': _.cve_desc,
                            'country': '',
                            'ports': ''

                        } for _ in RouterCVE.objects.filter(scan_result_id=row.id)
                    ]
                })
                geos.append([{
                    'coord': [116.40, 39.90]  # 起点坐标
                }, {
                    'coord': [row.longitude, row.latitude]  # 终点坐标
                }])

        return JsonResponse({'code': 20000, 'data': {
            'ok': _st.status == 1,  # 0 是还在扫描，1是扫描完成
            'cve_data': data,
            'geos': geos
        }})


class IndexView(View):
    def get(self, request):
        vendor = {}
        countries = {}
        geos = []

        for row in ScanResult.objects.values('ip_v4', 'device_name', 'vendor', 'country_name', 'longitude',
                                             'latitude').distinct().all():
            if row['vendor'] not in vendor:
                vendor[row['vendor']] = 1
            else:
                vendor[row['vendor']] += 1
            if row['country_name'] not in countries:
                countries[row['country_name']] = 1
            else:
                countries[row['country_name']] += 1
            geos.append([{
                'coord': [116.40, 39.90]  # 起点坐标
            }, {
                'coord': [row['longitude'], row['latitude']]  # 终点坐标
            }])
        return JsonResponse({'code': 20000, 'data': {
            'vendor': [{'value': v, 'name': k} for k, v in vendor.items()],
            'countries': [[k for k, v in countries.items()], [v for k, v in countries.items()]],
            'geos': geos
        }})
