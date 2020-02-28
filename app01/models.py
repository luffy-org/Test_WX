import hashlib

from django.db import models

# Create your models here.

class UserInfo(models.Model):
    username = models.CharField(verbose_name='用户名', max_length=64, unique=True)
    password = models.CharField(verbose_name='密码', max_length=64)
    uid = models.CharField(verbose_name='个人唯一ID', max_length=64, unique=True)
    wx_id = models.CharField(verbose_name='微信ID', max_length=64, blank=True, null=True)

    def save(self, *args, **kwargs):
        print('开始走save方法')
        if not self.pk:
            print('个人ID', self.id)
            m = hashlib.md5()
            m.update(self.username.encode('utf-8'))
            self.uid = m.hexdigest()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

    class Meta:
        verbose_name_plural = '01-用户表'
        verbose_name = verbose_name_plural



'''
方式1：
user=UserInfo()
user.username="alex"
user.password="123"
user.save()


方式2：
UserInfo.objects.create(username="alex",password="123")





'''
