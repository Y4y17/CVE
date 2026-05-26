# Any SpringBean invocation vulnerability
##### Vulnerability Location: /api/v1/sysJob/update
##### Affected Range: AiFlowy <= V2.1.2
##### Vulnerability Cause: The JobUtil.java file contains a serious vulnerability that enables attackers to carry out arbitrary SpringBean invocations.
##### Vulnerability Impact: Resulting in the leakage of sensitive information, and even obtaining server access privileges.
##### Link: https://gitee.com/aiflowy/aiflowy
# Vulnerability recurrence
