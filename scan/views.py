from django.shortcuts import render
import re
import json
import nmap3

from datetime import datetime, timedelta

from django.views import View

from django.http.response import JsonResponse

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from django_apscheduler.jobstores import DjangoJobStore
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR

jobstores = {
    'default': DjangoJobStore()
    # 'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
}
executors = {
    'default': ThreadPoolExecutor(20),
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


scheduler = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults, daemon=False)
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


def _scan_host(ip: str):
    print(ip)
    nmap_3 = nmap3.Nmap()
    os_results = nmap_3.nmap_os_detection(ip, args='-T4')  # 需要root权限，这是获取主机的IP以及判断主机的类型
    print(os_results)


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
        quickly = data.get('quickly', '1')  # 如果 是1 就是进行快速扫描，如果是0就是慢速

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
        if quickly == '1':
            # 快速扫描，把ip按段划分，然后塞给Apshceduler进行扫描
            _tmp = _start_num + self.ip_num
            while _tmp < _end_num:
                scheduler.add_job(_scan_host, args=('.'.join(start_ip[:3]) + f'.{_start_num}-{_tmp}',), trigger='date',
                                  next_run_time=datetime.now() + timedelta(seconds=5),
                                  id=f'{int(datetime.now().timestamp())}_{_tmp}')
                # self._scan_host('.'.join(start_ip) + f'-{_tmp}')
                _start_num = _tmp
                _tmp += self.ip_num
            else:
                scheduler.add_job(_scan_host, args=('.'.join(start_ip[:3]) + f'.{_start_num}-{_end_num}',),
                                  trigger='date',
                                  next_run_time=datetime.now() + timedelta(seconds=5),
                                  id=f'{int(datetime.now().timestamp())}_{_tmp}')

        return JsonResponse({'code': 20000, 'message': '扫描中~'})
