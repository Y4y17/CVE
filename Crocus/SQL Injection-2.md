# SQL Injection vulnerability
##### Vulnerability Location: RecordStateMapper.xml
##### Affected Range: Crocus V1.3.8.4 
##### Vulnerability Cause: The RecordStateMapper.xml file contains an SQL injection vulnerability, specifically an orderby injection vulnerability, which uses ${}.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions; Obtain data from other databases; Stealing users' confidential information includes accounts, personal private information, transaction information, etc.
##### Link: https://cn.streamax.com/
# Vulnerability recurrence

Using delayed injection, the echo time is 5 seconds.

<img width="1494" height="661" alt="image" src="https://github.com/user-attachments/assets/1ebe728e-4e3e-455f-8a8d-dd433ba71408" />

Check if the current database username is root@localhost

<img width="1486" height="648" alt="image" src="https://github.com/user-attachments/assets/dda8b887-0c58-4525-8af3-019f123783ca" />

# Code Analysis

The controller layer receives the parameter `orderfield` and subsequently passes it to the service layer.
<img width="1148" height="777" alt="image" src="https://github.com/user-attachments/assets/00e1dff3-d9e5-4351-81a7-8045c362ffd4" />

<img width="1128" height="780" alt="image" src="https://github.com/user-attachments/assets/15682bef-a4fc-45f7-b3d0-47d473a6384e" />

Upon further investigation at the Service layer, it was found that different Mapper layers were accessed when start and end were either null or not null.

<img width="1086" height="738" alt="image" src="https://github.com/user-attachments/assets/2704ce18-3372-46ee-850c-0d503e05fca2" />

Following the mapper layer, you'll find that both queryHistory and query directly concatenate the orderfield parameter into the SQL statement.

<img width="1060" height="643" alt="image" src="https://github.com/user-attachments/assets/36deda4d-4dfe-4525-8932-8280de8fadf1" />


<img width="1066" height="727" alt="image" src="https://github.com/user-attachments/assets/e6ea745b-bcbf-4721-b6b3-47dfd1cee7f2" />
