import functools
import json

import requests
from django.http import JsonResponse
from django.shortcuts import render, HttpResponse, redirect
from urllib.parse import urlencode

# Create your views here.
from app01 import models


def auth(func):
    @functools.wraps(func)
    def inner(request, *args, **kwargs):
        user_info = request.session.get('user_info')
        if not user_info:
            return redirect('/login/')
        return func(request, *args, **kwargs)

    return inner


def login(request):
    if request.method == 'POST':
        user = request.POST.get('user')
        pwd = request.POST.get('pwd')
        user_obj = models.UserInfo.objects.filter(username=user, password=pwd).first()
        if user_obj:
            request.session['user_info'] = {'id': user_obj.id, 'name': user_obj.username, 'uid': user_obj.uid}
            return redirect('/bind/')

    return render(request, 'login.html')


@auth  # bind = auth(bind)
def bind(request):
    """
    登录后，关注公众号 并绑定个人微信

    """
    print(request.session['user_info'])
    return render(request, 'bind.html')


@auth
def bind_qcode(request):
    """
    前端向后端发送ajax请求到此，我们生成二维码数据返回
    :param request:
    :return:
    """
    # token :b5b87bf9590ca8d260ac4d7e9e2a75a2
    if request.method == 'GET':
        ret = {'code': 1000}
        try:
            access_url = 'https://open.weixin.qq.com/connect/oauth2/authorize?appid={appid}&redirect_uri={redirect_uri}&response_type=code&scope=snsapi_userinfo&state={state}#wechat_redirect'
            access_url = access_url.format(
                appid="wx8aa094571ee97536",
                redirect_uri='http://39.108.134.78:8000/callback',
                state=request.session['user_info']['uid']
            )

            ret['data'] = access_url

        except Exception as e:
            ret['code'] = 1001
            ret['msg'] = str(e)

        return JsonResponse(ret)


def callback(request):
    """
    发送二次请求，以通过微信的认证，认证后拿到用户的openid
    :param request:
    :return:
    """
    # 1. 获取微信的code
    code = request.GET.get('code')
    # 2. 获取用户uid
    state = request.GET.get('state')

    ret = requests.get(url='https://api.weixin.qq.com/sns/oauth2/access_token', params={
        "appid": "wx8aa094571ee97536",
        "secret": "779a492b89fe2a9c369531cd35ea200d",
        "code": code,
        "grant_type": "authorization_code"

    }).json()

    open_id = ret.get("openid")  # 通过微信验证后从微信返回的结果中拿到openid
    if open_id:
        models.UserInfo.objects.filter(uid=state).update(wx_id=open_id)  # 将用户的微信ID存入数据库
        response = "<h1>授权成功 %s </h1>" % open_id

    else:
        response = "<h1>用户扫码之后，手机上的提示</h1>"
    return HttpResponse(response)


def sendmsg(request):
    def get_access_token():
        result = requests.get('https://api.weixin.qq.com/cgi-bin/token', params={
            "grant_type": "client_credential",
            "appid": "wx8aa094571ee97536",
            "appsecret": "779a492b89fe2a9c369531cd35ea200d"
        }).json()
        if result.get("access_token"):
            access_token = result.get("access_token")
        else:
            access_token = None
        return access_token

    access_token = get_access_token()
    openid1 = models.UserInfo.objects.filter(id=1).first().wx_id
    openid2 = models.UserInfo.objects.filter(id=2).first().wx_id

    def send_custom_msg():
        body = {
            "touser": [openid1, openid2],
            "msgtype": "text",
            "text": {"content": "耗时24h终于等到你"}
        }

        response = requests.post(url='https://api.weixin.qq.com/cgi-bin/message/mass/send',
                                 params={
                                     "access_token": access_token
                                 },
                                 data=bytes(json.dumps(body, ensure_ascii=False), encoding='utf-8')
                                 )
        result = response.json()
        return result

    result = send_custom_msg()
    if result.get('errcode') == 0:
        return HttpResponse('发送成功')
    return HttpResponse('发送失败')


