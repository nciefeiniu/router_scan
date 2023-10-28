from django.db import models


# Create your models here.

class CveData(models.Model):
    id = models.BigAutoField(primary_key=True)
    cve_id = models.CharField(unique=True, max_length=255, blank=True, null=True)
    cve_url = models.CharField(max_length=255, blank=True, null=True)
    score = models.CharField(max_length=255, blank=True, null=True)
    access = models.CharField(max_length=255, blank=True, null=True)
    complexity = models.CharField(max_length=255, blank=True, null=True)
    authentication = models.CharField(max_length=255, blank=True, null=True)
    confidentiality = models.CharField(max_length=255, blank=True, null=True)
    integrity = models.CharField(max_length=255, blank=True, null=True)
    availability = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    vendor = models.CharField(max_length=255, blank=True, null=True)
    product = models.CharField(max_length=255, blank=True, null=True)
    version = models.TextField(blank=True, null=True)
    snapshot_time = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'cve_data'


class ScanTask(models.Model):
    """
    扫描任务表
    """
    STATUS = (
        (0, '正在扫描'),
        (1, '扫描完成')
    )

    id = models.BigAutoField(primary_key=True)
    scan_id = models.CharField('扫描任务的ID', max_length=64)
    child_task_status = models.JSONField('子任务状态')
    status = models.IntegerField('扫描状态', choices=STATUS, default=0)

    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')


class ScanResult(models.Model):
    """
    扫描结果表
    """
    id = models.BigAutoField(primary_key=True)
    task = models.ForeignKey(ScanTask, on_delete=models.CASCADE)  # 外键，和ScanTask表关连
    ip_v4 = models.GenericIPAddressField('IP地址', protocol='IPv4')
    device_name = models.CharField('设备名', max_length=255, null=True, blank=True)
    os_name = models.CharField('系统名字', max_length=255, null=True, blank=True)
    type = models.CharField('系统类型', max_length=255, null=True, blank=True)
    vendor = models.CharField('系统分类', max_length=255, null=True, blank=True)
    os_gen = models.CharField('系统版本', max_length=255, null=True, blank=True)
    os_family = models.CharField('系统家族', max_length=255, null=True, blank=True)

    country_name = models.CharField('国家', max_length=255, null=True, blank=True)
    latitude = models.CharField('纬度', max_length=32, null=True, blank=True)
    longitude = models.CharField('精度', max_length=32, null=True, blank=True)
    region = models.CharField('哪个州', max_length=32, null=True, blank=True)

    mac_address = models.CharField('Mac地址', max_length=255, null=True, blank=True)
    producer = models.CharField('制造商，根据MAC地址查询出来的', max_length=255, null=True, blank=True)

    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')


class RouterCVE(models.Model):
    """
    扫描出来的 路由器的 漏洞表

    路由器有哪些漏洞都存储在这里
    """
    id = models.BigAutoField(primary_key=True)
    task = models.ForeignKey(ScanTask, on_delete=models.CASCADE)  # 外键，和ScanTask表关连
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE)  # 外键，和上面的这张表进行关连上

    cve_id = models.CharField('CVE＿ID', max_length=255)
    cve_desc = models.TextField('描述')

    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, verbose_name='更新时间')
