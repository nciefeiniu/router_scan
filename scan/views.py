from django.shortcuts import render
import re
import json

from django.views import View

from django.http.response import JsonResponse


def check_ip(ip_addr: str) -> bool:
    compile_ip = re.compile(
        '^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ip_addr):
        return True
    else:
        return False


class LoginView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        if username != 'admin' or username != password:
            return JsonResponse({'code': 60204, 'message': '账户或者密码错误'})
        return JsonResponse({'code': 20000, 'data': 'test-token'})


class UserInfoView(View):
    def get(self, request):
        return JsonResponse({'code': 20000, 'data': {
            'roles': ['admin'],
            'introduction': 'I am a super administrator',
            'avatar': 'https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif',
            'name': 'Super Admin'}})


class LogoutView(View):
    def post(self, request):
        return JsonResponse({'code': 20000, 'data': 'success'})


class ScanView(View):
    def get(self, request):
        start_ip = request.GET.get('start_ip')
        end_ip = request.GET.get('end_ip')

        if not check_ip(start_ip) or not check_ip(end_ip):
            return JsonResponse({'code': 500, 'message': 'IP地址不合法'})

        start_ip = start_ip.split('.')
        end_ip = end_ip.split('.')

        for _i in range(3):
            if start_ip[_i] != end_ip[_i]:
                return JsonResponse({'code': 500, 'message': 'IP起始地址不在同一网段！'})
        if int(start_ip[-1]) > int(end_ip[-1]):
            return JsonResponse({'code': 500, 'message': 'IP起始地址不能大于结束地址！'})
