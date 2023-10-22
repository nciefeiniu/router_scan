from django.db import models


# Create your models here.


class ScanResult(models.Model):
    id = models.BigAutoField(primary_key=True)
    ip_v4 = models.GenericIPAddressField('IP地址', protocol='IPv4')
    device_name = models.CharField('设备名', max_length=255)
    os_name = models.CharField('系统名字', max_length=255)
    type = models.CharField('系统类型', max_length=255)
    vendor = models.CharField('系统分类', max_length=255)
    os_gen = models.CharField('系统版本', max_length=255)
    os_family = models.CharField('系统家族', max_length=255)

    country_name = models.CharField('国家', max_length=255)
    latitude = models.CharField('纬度', max_length=32)
    longitude = models.CharField('精度', max_length=32)

    mac_address = models.CharField('Mac地址', max_length=255)
    producer = models.CharField('制造商，根据MAC地址查询出来的', max_length=255)

    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')
