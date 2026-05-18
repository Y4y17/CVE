# SQL Injection vulnerability
##### Vulnerability Location: DeviceFaultMapper.xml
##### Affected Range: Crocus V1.3.44
##### Vulnerability Cause: The DeviceFaultMapper.xml file contains an SQL injection vulnerability, specifically an orderby injection vulnerability, which uses ${}.
##### Vulnerability Impact: Obtain database access rights, and even DBA permissions; Obtain data from other databases; Stealing users' confidential information includes accounts, personal private information, transaction information, etc.
##### Link: https://cn.streamax.com/
# Vulnerability recurrence

Delayed injection for 5 seconds

<img width="1432" height="622" alt="image" src="https://github.com/user-attachments/assets/21b8d6f5-e16c-4079-8ebc-6a5f956753e8" />

Check if the current database username is root@localhost

<img width="1487" height="653" alt="image" src="https://github.com/user-attachments/assets/3d740691-7822-4c7e-89ec-91db4b288821" />

# Code Analysis

The Controller layer receives the `orderField` parameter and passes it to the `queryLatest/query` function in the Service layer.

<img width="1145" height="781" alt="image" src="https://github.com/user-attachments/assets/f1589b0f-0a71-4d61-a8d1-c1dcd733cbe5" />

Follow up at the Service layer:

<img width="1162" height="781" alt="image" src="https://github.com/user-attachments/assets/50656ba0-b7a0-4a1c-aab8-b37b025fbf95" />

They may respectively call query/queryLaster in the Mapper

<img width="1044" height="636" alt="image" src="https://github.com/user-attachments/assets/27b8d083-6042-4c45-925f-f6d0e9a2515f" />

<img width="1149" height="675" alt="image" src="https://github.com/user-attachments/assets/868e9b33-9ece-4101-814d-7f34e47767ce" />

Follow up at the Mapper layer:

<img width="1096" height="738" alt="image" src="https://github.com/user-attachments/assets/3b5a69f4-3b49-4c3a-8469-0364153835e9" />

<img width="1015" height="587" alt="image" src="https://github.com/user-attachments/assets/98efcf8e-12ed-4c39-b242-81352c8b58c4" />

As you can see, the orderField parameter is directly appended to the SQL statement.
