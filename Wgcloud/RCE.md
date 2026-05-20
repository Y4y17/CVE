# Wgcloud V3.6.4 RCE Vulnerability
##### Vulnerability Location: /warnScript/test
##### Affected Range: Wgcloud V3.6.4
##### Vulnerability Cause: The "content" parameter was directly concatenated to the ProcessBuilder for execution, resulting in the emergence of a command execution vulnerability.
##### Vulnerability Impact: Obtained server access rights;
##### Link: https://www.wgstart.com/
# Vulnerability recurrence

<img width="1278" height="365" alt="image" src="https://github.com/user-attachments/assets/fdfaead7-1d93-429a-95ce-5271762d5742" />

<img width="1152" height="474" alt="image" src="https://github.com/user-attachments/assets/9cfa2910-8ed9-4245-8d29-de649bc09e8e" />

# Code Analysis

<img width="982" height="602" alt="image" src="https://github.com/user-attachments/assets/e28fc26a-7099-47d2-9813-0561678fd927" />

接受参数 content！直接添加到了 List 中，通过 ProcessBuilder 执行命令。

<img width="851" height="610" alt="image" src="https://github.com/user-attachments/assets/ff627147-2601-4c8c-9809-5cd28ba43d75" />

其他的参数可以不传递，默认初始化。寻找上层调用：

<img width="1397" height="397" alt="image" src="https://github.com/user-attachments/assets/80189389-ace5-4337-861f-0d8b28f48645" />
