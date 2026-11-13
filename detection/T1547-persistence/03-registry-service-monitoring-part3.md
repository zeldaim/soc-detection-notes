# T1547 Persistence 탐지 3

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 생략했습니다.

완료된 것

- Agent 4.9.2 업그레이드 (크래시 버그 해결)
- Rule 100220 필드명 수정 (win.eventdata.image → image)
- 0860-sysmon_id_13.xml에 룰 삽입
- 파이프라인 각 단계 디버깅 방법론 확립

미해결 블로커

- EventID 13이 archives에 간헐적으로만 도달함 (12는 오는데 13은 누락)
- Rule 100220 실제 발동 미확인

다음 단계 순서

Step 1 — 재부팅 후 기본 상태 확인 (가설 검증)
```bash
# Windows 재부팅 후 서비스 순서 확인
Get-Service -Name "Sysmon64", "WazuhSvc" | Select-Object Name, Status, StartType
```

Sysmon이 먼저 뜨고 Wazuh agent가 나중에 뜨는지 확인. 순서가 바뀌면 eventchannel 구독 타이밍 이슈 발생 가능.

Step 2 — EventID 13 archives 도달 여부 재확인
```bash
# 기존 키 삭제 (재설정 시 이벤트 미발생 이슈 회피)
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday3" -ErrorAction SilentlyContinue

# 새 키 이름으로 테스트
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday4" -Value "calc.exe" -PropertyType String -Force
```

Rocky
```bash
# manager에서 30초 안에 확인
docker exec single-node-wazuh.manager-1 grep -a "EvilToday4" /var/ossec/logs/archives/archives.json | tail -3
```

Step 3 — archives에 도달했는데 rule 미발동이면
```bash
# 실제 필드명 재확인 (decoder 출력이 image인지 win.eventdata.image인지)
docker exec single-node-wazuh.manager-1 grep -a "EvilToday4" /var/ossec/logs/archives/archives.json | tail -1 | python3 -m json.tool | grep -E "image|targetObject|decoder|rule"
```

Expecting value: line 1 column 1 (char 0) — archives.json에 EvilToday4가 없다는 뜻.

grep 결과가 빈 문자열이라 python3 파싱이 실패한 것.

EventID 13이 manager까지 아직 안 도달하고 있음.

파이프라인 어디서 끊겼는지 단계별로 확인:

Step 1 — Windows에서 Sysmon이 실제로 캡처했는지
```bash
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Where-Object {$_.Id -eq 13} | Select-Object TimeCreated, Message | Format-List
```

EventID 13이 보이면 Sysmon은 정상인 것이지만 확인 결과 아무 값이 없음.

키 이름 확인:
```bash
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Select-Object EvilToday4
```

Step 2 — Agent가 살아있는지 확인
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

DESKTOP-5408CBA (ID: 003) Active 확인. agent 연결은 정상.

그러면 문제는 Windows → Sysmon 캡처 또는 agent eventchannel 전송 단계.
```bash
# 1. 기존 키 삭제
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday4" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday5" -ErrorAction SilentlyContinue

# 2. 새 키 생성
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday6" -Value "calc.exe" -PropertyType String -Force

# 3. Sysmon 캡처 즉시 확인
Start-Sleep -Seconds 3
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.Id -eq 13} | Select-Object TimeCreated, @{N='Msg';E={$_.Message.Substring(0,200)}}

```

Get-WinEvent 결과가 빈 출력. EventID 13이 Sysmon에 캡처 안 되고 있음.

키 생성(EvilToday6 : calc.exe)은 성공했는데 Sysmon이 못 잡은 것 → Sysmon config 문제.
```bash
# Sysmon 현재 config 확인
C:\Windows\sysmon64.exe -c
```

Sysmon config는 정상. T1547_Run_Key_Set이 SOFTWARE\Microsoft\Windows\CurrentVersion\Run을 감시 중.

근데 맨 아래 Exclude 규칙이 문제:
```bash
Compound Rule Exclude_System_Processes
  Image: is 'C:\Windows\System32\svchost.exe'
  Image: is 'C:\Windows\System32\services.exe'
  Image: is 'C:\Windows\System32\regedit.exe'
  Image: contains 'MsMpEng.exe'
  Image: contains 'msiexec.exe'
```

PowerShell 경로가 C:\Windows\System32\WindowsPowerShell\...\powershell.exe인데, 이게 exclude에 없으니 문제가 아님.

그러면 실제로 PowerShell이 system32에서 실행되는지 확인 필요. 지금 PS C:\Windows\system32> 프롬프트에서 실행 중인데, 혹시 32비트 PowerShell이면 레지스트리 경로가 리다이렉트될 수 있음.
```bash
# 현재 PowerShell 비트 확인
[Environment]::Is64BitProcess

# 64비트 PowerShell로 명시적 실행 후 테스트
& "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command {
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday6" -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday7" -Value "calc.exe" -PropertyType String -Force
}

Start-Sleep -Seconds 3
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.Id -eq 13}
```

Sysmon EventID 13 캡처 확인됨. 3개 이벤트 2026-04-26 오후 6:04:24~25.

파이프라인 1단계 통과. 이제 Rocky에서 archives 도달 여부 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday7" /var/ossec/logs/archives/archives.json | tail -3
```

archives에 없음. Sysmon은 잡았는데 agent가 manager로 전송 못 하고 있음.

agent의 ossec.conf에 Sysmon eventchannel 설정이 실제로 적용됐는지 확인:
```bash
Select-String "Sysmon" "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

그리고 agent 로그에서 에러 확인:
```bash
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" | Select-Object -Last 20
```

두 가지 확인됨:

1. ossec.conf line 209 — Sysmon eventchannel 설정 존재 ✅
1. ossec.log — 17:46:34에 재연결 성공, 현재 online ✅

근데 로그 타임스탬프가 17:46이고 EvilToday7 키 생성은 18:04. agent가 재시작되면서 eventchannel 구독이 리셋되고, 재구독 후 이벤트를 못 잡고 있을 가능성 있음.

지금 당장 agent 재시작 없이 새 키로 다시 테스트:
```bash
# 삭제 후 새 키
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday7" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday8" -Value "calc.exe" -PropertyType String -Force
Start-Sleep -Seconds 5

# Sysmon 캡처 확인
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Where-Object {$_.Id -eq 13} | Select-Object TimeCreated
```

EvilToday7, 8 모두 archives에 없음. agent → manager 전송 자체가 안 되고 있음.

agent는 online인데 eventchannel 이벤트만 안 오는 것. Sysmon 채널 구독 문제.

archives에 Windows 이벤트가 아예 안 오는지, 아니면 Sysmon만 안 오는지 확인:
```bash
# Windows agent (003)에서 온 이벤트 최근 것 확인
docker exec single-node-wazuh.manager-1 bash -c 'grep -a "DESKTOP-5408CBA" /var/ossec/logs/archives/archives.json | tail -3'
```

결과
```bash
[yhc@localhost ~]$ # Windows agent (003)에서 온 이벤트 최근 것 확인
docker exec single-node-wazuh.manager-1 bash -c 'grep -a "DESKTOP-5408CBA" /var/ossec/logs/archives/archives.json | tail -3'
{"timestamp":"2026-04-24T17:09:32.831+0000","agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777050572.4728551","full_log":"{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Sysmon\",\"providerGuid\":\"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}\",\"eventID\":\"12\",\"version\":\"2\",\"level\":\"4\",\"task\":\"12\",\"opcode\":\"0\",\"keywords\":\"0x8000000000000000\",\"systemTime\":\"2026-04-24T17:09:31.0859820Z\",\"eventRecordID\":\"16950\",\"processID\":\"2692\",\"threadID\":\"3792\",\"channel\":\"Microsoft-Windows-Sysmon/Operational\",\"computer\":\"DESKTOP-5408CBA\",\"severityValue\":\"INFORMATION\",\"message\":\"\\\"Registry object added or deleted:\\r\\nRuleName: T1543_Service_Registry\\r\\nEventType: CreateKey\\r\\nUtcTime: 2026-04-24 17:09:31.082\\r\\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\\r\\nProcessId: 2772\\r\\nImage: C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe\\r\\nTargetObject: HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters\\r\\nUser: NT AUTHORITY\\\\SYSTEM\\\"\"},\"eventdata\":{\"ruleName\":\"T1543_Service_Registry\",\"eventType\":\"CreateKey\",\"utcTime\":\"2026-04-24 17:09:31.082\",\"processGuid\":\"{4fb3ada3-635a-69db-4400-000000000500}\",\"processId\":\"2772\",\"image\":\"C:\\\\\\\\Program Files\\\\\\\\VMware\\\\\\\\VMware Tools\\\\\\\\vmtoolsd.exe\",\"targetObject\":\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\Tcpip\\\\\\\\Parameters\",\"user\":\"NT AUTHORITY\\\\\\\\SYSTEM\"}}}","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"12","version":"2","level":"4","task":"12","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T17:09:31.0859820Z","eventRecordID":"16950","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry object added or deleted:\r\nRuleName: T1543_Service_Registry\r\nEventType: CreateKey\r\nUtcTime: 2026-04-24 17:09:31.082\r\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\r\nProcessId: 2772\r\nImage: C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\r\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\r\nUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"ruleName":"T1543_Service_Registry","eventType":"CreateKey","utcTime":"2026-04-24 17:09:31.082","processGuid":"{4fb3ada3-635a-69db-4400-000000000500}","processId":"2772","image":"C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe","targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters","user":"NT AUTHORITY\\\\SYSTEM"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T17:09:32.845+0000","agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777050572.4728551","full_log":"{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Sysmon\",\"providerGuid\":\"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}\",\"eventID\":\"12\",\"version\":\"2\",\"level\":\"4\",\"task\":\"12\",\"opcode\":\"0\",\"keywords\":\"0x8000000000000000\",\"systemTime\":\"2026-04-24T17:09:31.0871055Z\",\"eventRecordID\":\"16952\",\"processID\":\"2692\",\"threadID\":\"3792\",\"channel\":\"Microsoft-Windows-Sysmon/Operational\",\"computer\":\"DESKTOP-5408CBA\",\"severityValue\":\"INFORMATION\",\"message\":\"\\\"Registry object added or deleted:\\r\\nRuleName: T1543_Service_Registry\\r\\nEventType: CreateKey\\r\\nUtcTime: 2026-04-24 17:09:31.082\\r\\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\\r\\nProcessId: 2772\\r\\nImage: C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe\\r\\nTargetObject: HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters\\r\\nUser: NT AUTHORITY\\\\SYSTEM\\\"\"},\"eventdata\":{\"ruleName\":\"T1543_Service_Registry\",\"eventType\":\"CreateKey\",\"utcTime\":\"2026-04-24 17:09:31.082\",\"processGuid\":\"{4fb3ada3-635a-69db-4400-000000000500}\",\"processId\":\"2772\",\"image\":\"C:\\\\\\\\Program Files\\\\\\\\VMware\\\\\\\\VMware Tools\\\\\\\\vmtoolsd.exe\",\"targetObject\":\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\Tcpip\\\\\\\\Parameters\",\"user\":\"NT AUTHORITY\\\\\\\\SYSTEM\"}}}","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"12","version":"2","level":"4","task":"12","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T17:09:31.0871055Z","eventRecordID":"16952","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry object added or deleted:\r\nRuleName: T1543_Service_Registry\r\nEventType: CreateKey\r\nUtcTime: 2026-04-24 17:09:31.082\r\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\r\nProcessId: 2772\r\nImage: C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\r\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\r\nUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"ruleName":"T1543_Service_Registry","eventType":"CreateKey","utcTime":"2026-04-24 17:09:31.082","processGuid":"{4fb3ada3-635a-69db-4400-000000000500}","processId":"2772","image":"C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe","targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters","user":"NT AUTHORITY\\\\SYSTEM"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T17:09:32.845+0000","agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777050572.4728551","full_log":"{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Sysmon\",\"providerGuid\":\"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}\",\"eventID\":\"12\",\"version\":\"2\",\"level\":\"4\",\"task\":\"12\",\"opcode\":\"0\",\"keywords\":\"0x8000000000000000\",\"systemTime\":\"2026-04-24T17:09:31.0870735Z\",\"eventRecordID\":\"16951\",\"processID\":\"2692\",\"threadID\":\"3792\",\"channel\":\"Microsoft-Windows-Sysmon/Operational\",\"computer\":\"DESKTOP-5408CBA\",\"severityValue\":\"INFORMATION\",\"message\":\"\\\"Registry object added or deleted:\\r\\nRuleName: T1543_Service_Registry\\r\\nEventType: CreateKey\\r\\nUtcTime: 2026-04-24 17:09:31.082\\r\\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\\r\\nProcessId: 2772\\r\\nImage: C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe\\r\\nTargetObject: HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters\\r\\nUser: NT AUTHORITY\\\\SYSTEM\\\"\"},\"eventdata\":{\"ruleName\":\"T1543_Service_Registry\",\"eventType\":\"CreateKey\",\"utcTime\":\"2026-04-24 17:09:31.082\",\"processGuid\":\"{4fb3ada3-635a-69db-4400-000000000500}\",\"processId\":\"2772\",\"image\":\"C:\\\\\\\\Program Files\\\\\\\\VMware\\\\\\\\VMware Tools\\\\\\\\vmtoolsd.exe\",\"targetObject\":\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\Tcpip\\\\\\\\Parameters\",\"user\":\"NT AUTHORITY\\\\\\\\SYSTEM\"}}}","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"12","version":"2","level":"4","task":"12","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T17:09:31.0870735Z","eventRecordID":"16951","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry object added or deleted:\r\nRuleName: T1543_Service_Registry\r\nEventType: CreateKey\r\nUtcTime: 2026-04-24 17:09:31.082\r\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\r\nProcessId: 2772\r\nImage: C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\r\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\r\nUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"ruleName":"T1543_Service_Registry","eventType":"CreateKey","utcTime":"2026-04-24 17:09:31.082","processGuid":"{4fb3ada3-635a-69db-4400-000000000500}","processId":"2772","image":"C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe","targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters","user":"NT AUTHORITY\\\\SYSTEM"}}},"location":"EventChannel"}
[yhc@localhost ~]$ 

```

또는
```bash
# 아니면 agent id 003으로 필터
docker exec single-node-wazuh.manager-1 bash -c 'grep -a "\"id\":\"003\"" /var/ossec/logs/archives/archives.json | tail -3'
```

결과
```bash
[yhc@localhost ~]$ # 아니면 agent id 003으로 필터
docker exec single-node-wazuh.manager-1 bash -c 'grep -a "\"id\":\"003\"" /var/ossec/logs/archives/archives.json | tail -3'
{"timestamp":"2026-04-24T17:09:32.831+0000","agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777050572.4728551","full_log":"{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Sysmon\",\"providerGuid\":\"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}\",\"eventID\":\"12\",\"version\":\"2\",\"level\":\"4\",\"task\":\"12\",\"opcode\":\"0\",\"keywords\":\"0x8000000000000000\",\"systemTime\":\"2026-04-24T17:09:31.0859820Z\",\"eventRecordID\":\"16950\",\"processID\":\"2692\",\"threadID\":\"3792\",\"channel\":\"Microsoft-Windows-Sysmon/Operational\",\"computer\":\"DESKTOP-5408CBA\",\"severityValue\":\"INFORMATION\",\"message\":\"\\\"Registry object added or deleted:\\r\\nRuleName: T1543_Service_Registry\\r\\nEventType: CreateKey\\r\\nUtcTime: 2026-04-24 17:09:31.082\\r\\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\\r\\nProcessId: 2772\\r\\nImage: C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe\\r\\nTargetObject: HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters\\r\\nUser: NT AUTHORITY\\\\SYSTEM\\\"\"},\"eventdata\":{\"ruleName\":\"T1543_Service_Registry\",\"eventType\":\"CreateKey\",\"utcTime\":\"2026-04-24 17:09:31.082\",\"processGuid\":\"{4fb3ada3-635a-69db-4400-000000000500}\",\"processId\":\"2772\",\"image\":\"C:\\\\\\\\Program Files\\\\\\\\VMware\\\\\\\\VMware Tools\\\\\\\\vmtoolsd.exe\",\"targetObject\":\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\Tcpip\\\\\\\\Parameters\",\"user\":\"NT AUTHORITY\\\\\\\\SYSTEM\"}}}","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"12","version":"2","level":"4","task":"12","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T17:09:31.0859820Z","eventRecordID":"16950","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry object added or deleted:\r\nRuleName: T1543_Service_Registry\r\nEventType: CreateKey\r\nUtcTime: 2026-04-24 17:09:31.082\r\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\r\nProcessId: 2772\r\nImage: C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\r\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\r\nUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"ruleName":"T1543_Service_Registry","eventType":"CreateKey","utcTime":"2026-04-24 17:09:31.082","processGuid":"{4fb3ada3-635a-69db-4400-000000000500}","processId":"2772","image":"C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe","targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters","user":"NT AUTHORITY\\\\SYSTEM"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T17:09:32.845+0000","agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777050572.4728551","full_log":"{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Sysmon\",\"providerGuid\":\"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}\",\"eventID\":\"12\",\"version\":\"2\",\"level\":\"4\",\"task\":\"12\",\"opcode\":\"0\",\"keywords\":\"0x8000000000000000\",\"systemTime\":\"2026-04-24T17:09:31.0871055Z\",\"eventRecordID\":\"16952\",\"processID\":\"2692\",\"threadID\":\"3792\",\"channel\":\"Microsoft-Windows-Sysmon/Operational\",\"computer\":\"DESKTOP-5408CBA\",\"severityValue\":\"INFORMATION\",\"message\":\"\\\"Registry object added or deleted:\\r\\nRuleName: T1543_Service_Registry\\r\\nEventType: CreateKey\\r\\nUtcTime: 2026-04-24 17:09:31.082\\r\\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\\r\\nProcessId: 2772\\r\\nImage: C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe\\r\\nTargetObject: HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters\\r\\nUser: NT AUTHORITY\\\\SYSTEM\\\"\"},\"eventdata\":{\"ruleName\":\"T1543_Service_Registry\",\"eventType\":\"CreateKey\",\"utcTime\":\"2026-04-24 17:09:31.082\",\"processGuid\":\"{4fb3ada3-635a-69db-4400-000000000500}\",\"processId\":\"2772\",\"image\":\"C:\\\\\\\\Program Files\\\\\\\\VMware\\\\\\\\VMware Tools\\\\\\\\vmtoolsd.exe\",\"targetObject\":\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\Tcpip\\\\\\\\Parameters\",\"user\":\"NT AUTHORITY\\\\\\\\SYSTEM\"}}}","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"12","version":"2","level":"4","task":"12","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T17:09:31.0871055Z","eventRecordID":"16952","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry object added or deleted:\r\nRuleName: T1543_Service_Registry\r\nEventType: CreateKey\r\nUtcTime: 2026-04-24 17:09:31.082\r\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\r\nProcessId: 2772\r\nImage: C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\r\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\r\nUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"ruleName":"T1543_Service_Registry","eventType":"CreateKey","utcTime":"2026-04-24 17:09:31.082","processGuid":"{4fb3ada3-635a-69db-4400-000000000500}","processId":"2772","image":"C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe","targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters","user":"NT AUTHORITY\\\\SYSTEM"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T17:09:32.845+0000","agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777050572.4728551","full_log":"{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Sysmon\",\"providerGuid\":\"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}\",\"eventID\":\"12\",\"version\":\"2\",\"level\":\"4\",\"task\":\"12\",\"opcode\":\"0\",\"keywords\":\"0x8000000000000000\",\"systemTime\":\"2026-04-24T17:09:31.0870735Z\",\"eventRecordID\":\"16951\",\"processID\":\"2692\",\"threadID\":\"3792\",\"channel\":\"Microsoft-Windows-Sysmon/Operational\",\"computer\":\"DESKTOP-5408CBA\",\"severityValue\":\"INFORMATION\",\"message\":\"\\\"Registry object added or deleted:\\r\\nRuleName: T1543_Service_Registry\\r\\nEventType: CreateKey\\r\\nUtcTime: 2026-04-24 17:09:31.082\\r\\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\\r\\nProcessId: 2772\\r\\nImage: C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe\\r\\nTargetObject: HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters\\r\\nUser: NT AUTHORITY\\\\SYSTEM\\\"\"},\"eventdata\":{\"ruleName\":\"T1543_Service_Registry\",\"eventType\":\"CreateKey\",\"utcTime\":\"2026-04-24 17:09:31.082\",\"processGuid\":\"{4fb3ada3-635a-69db-4400-000000000500}\",\"processId\":\"2772\",\"image\":\"C:\\\\\\\\Program Files\\\\\\\\VMware\\\\\\\\VMware Tools\\\\\\\\vmtoolsd.exe\",\"targetObject\":\"HKLM\\\\\\\\System\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\Tcpip\\\\\\\\Parameters\",\"user\":\"NT AUTHORITY\\\\\\\\SYSTEM\"}}}","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"12","version":"2","level":"4","task":"12","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T17:09:31.0870735Z","eventRecordID":"16951","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry object added or deleted:\r\nRuleName: T1543_Service_Registry\r\nEventType: CreateKey\r\nUtcTime: 2026-04-24 17:09:31.082\r\nProcessGuid: {4fb3ada3-635a-69db-4400-000000000500}\r\nProcessId: 2772\r\nImage: C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\r\nTargetObject: HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\r\nUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"ruleName":"T1543_Service_Registry","eventType":"CreateKey","utcTime":"2026-04-24 17:09:31.082","processGuid":"{4fb3ada3-635a-69db-4400-000000000500}","processId":"2772","image":"C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe","targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Tcpip\\\\Parameters","user":"NT AUTHORITY\\\\SYSTEM"}}},"location":"EventChannel"}

```

archives에 003 이벤트가 있긴 한데 타임스탬프가 2026-04-24T17:09 — 이틀 전 데이터. 오늘 18:04에 생성한 EvilToday7/8이 안 오고 있음.

그리고 EventID 12만 오고 있음. EventID 13이 선택적으로 누락되는 게 아니라 오늘 이후 이벤트 자체가 안 오고 있음.

원인: ossec.log에서 봤던 17:46:24 ERROR: Unable to add agent — agent가 재등록 실패 후 재연결됐는데, eventchannel reader가 과거 bookmark 위치부터 읽다가 멈춘 상태.

agent restart로 eventchannel reader 리셋:
```bash
Restart-Service WazuhSvc
Start-Sleep -Seconds 10

# 재시작 후 새 키 생성
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday8" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday9" -Value "calc.exe" -PropertyType String -Force

```
```bash
docker exec single-node-wazuh.manager-1 bash -c 'grep -a "003" /var/ossec/logs/archives/archives.json | tail -1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[\"timestamp\"])"'
```

타임스탬프 여전히 2026-04-24T17:09 — agent restart 후에도 오늘 이벤트가 전혀 안 오고 있음.

archives.json 파일 자체가 오늘 날짜 파일인지 확인:
```bash
# archives.json이 오늘 파일인지, 아니면 날짜별 파일이 따로 있는지
docker exec single-node-wazuh.manager-1 ls -la /var/ossec/logs/archives/
```
```bash
archives.json   Apr 24 17:09   719273 bytes  ← 이틀 전에 멈춤
archives.log    Apr 26 08:44   0 bytes       ← 오늘 파일인데 비어있음
```

logall_json이 꺼져 있어서 archives.json에 새 이벤트가 안 쌓이고 있음. Apr 24 이후로 파일 크기가 안 변했음.

이전에 TIL에서 Docker volume 휘발성 문제로 logall/logall_json 설정이 재시작 시 리셋된다고 적혀있었는데, 그게 지금 발생한 것.

호스트 볼륨 소스 파일 찾아서 영구 수정:
```bash
# 마운트 경로 확인
docker inspect single-node-wazuh.manager-1 --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' | grep ossec.conf
```

호스트 경로 확인됨.
```bash
/home/yhc/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
```
```bash
# logall 현재 값 확인
grep -n "logall" /home/yhc/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
```
```bash
# 수정
sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/' /home/yhc/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
sed -i 's/<logall_json>no<\/logall_json>/<logall_json>yes<\/logall_json>/' /home/yhc/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf

# 확인
grep -n "logall" /home/yhc/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
```

수정 확인 후 manager restart:
```bash
docker restart single-node-wazuh.manager-1 && sleep 40
```

logall_json>yes 확인, manager restart 완료.

이제 Windows에서 새 키 생성하고 바로 확인:
```bash
# Windows
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday9" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday10" -Value "calc.exe" -PropertyType String -Force
```
```bash
docker exec single-node-wazuh.manager-1 ls -la /var/ossec/logs/archives/
docker exec single-node-wazuh.manager-1 grep -a "EvilToday10" /var/ossec/logs/archives/archives.json | tail -3
```

파이프라인 통과.
```bash
archives.json   Apr 26 09:23   255728 bytes  ← 오늘 업데이트됨
EvilToday10     eventID: 13    image: powershell.exe
targetObject: HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilToday10
```

Sysmon EventID 13 → agent → manager archives 도달 확인. 이제 rule 발동 여부만 남았음:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday10" /var/ossec/logs/alerts/alerts.json | tail -3
```

archives는 도달했는데 alerts는 없음. rule 매칭 실패.

이벤트는 오는데 rule 100220이 안 발동하는 것. 필드명 문제일 가능성 높음. archives에서 실제 필드 구조 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday10" /var/ossec/logs/archives/archives.json | tail -1 | python3 -m json.tool | grep -E '"image"|"targetObject"|"ruleName"|"decoder"'
```

필드 구조 확인됨:
```bash
"decoder": {
    "ruleName": "T1547_Run_Key_Create",
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "targetObject": "HKU\\S-1-5-21-...\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilToday10"
}
```

필드명은 image, targetObject

이전에 수정한 것과 일치. 근데 rule이 안 발동하는 건 rule 100220이 0860-sysmon_id_13.xml에 실제로 들어갔는지 확인이 필요:
```bash

docker exec single-node-wazuh.manager-1 grep -n "100220" /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```
```bash
# 없으면 local_rules.xml 확인
docker exec single-node-wazuh.manager-1 grep -n "100220" /var/ossec/etc/rules/local_rules.xml
```

rule 100220이 두 군데 다 있음 — 이게 충돌 원인일 수 있음. 근데 그것보다 먼저 각 파일의 실제 내용 확인:
```bash
# 0860 파일의 100220 룰 전체 확인
docker exec single-node-wazuh.manager-1 sed -n '28,45p' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml

```
```bash
# local_rules.xml 전체 확인
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```

문제 두 개 발견됨.

문제 1 — local_rules.xml의 필드명이 틀림
```bash
<field name="win.eventdata.targetObject"  ← 잘못됨
```

archives에서 확인한 실제 필드명은 targetObject (win.eventdata. 없음)

문제 2 — 0860 파일의 100220과 local_rules.xml의 100220이 충돌

같은 rule id가 두 군데. Wazuh가 어느 걸 쓰는지 불명확.

해결: local_rules.xml을 올바른 필드명으로 수정하고, 0860 파일 버전과 통일:
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << EOF
<group name="sysmon,windows,">
  <rule id="100220" level="12">
    <if_sid>92300</if_sid>
    <field name="image" type="pcre2">(?i)powershell</field>
    <field name="targetObject" type="pcre2">(?i)CurrentVersion\\Run</field>
    <description>T1547 - Run key modified via PowerShell</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
EOF'
```

근데 0860 파일에도 동일한 100220이 있으니 둘 중 하나만 남겨야 함. local_rules.xml을 비우고 0860 파일 버전만 쓰는 게 더 깔끔:
```bash
# local_rules.xml에서 100220 제거 (빈 group만 남김)
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << EOF
<group name="sysmon,windows,">
</group>
EOF'

docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```

manager restart 완료. 이제 테스트:
```bash
# Windows
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday10" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday11" -Value "calc.exe" -PropertyType String -Force
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday11" /var/ossec/logs/alerts/alerts.json | tail -3
```

alerts에 여전히 없음. archives는 도달하는데 rule 매칭이 안 되는 것.

92300이 실제로 존재하는지, 그리고 EvilToday11이 92300에 매칭됐는지 확인:
```bash
# archives에서 EvilToday11 이벤트가 어느 rule로 처리됐는지
docker exec single-node-wazuh.manager-1 grep -a "EvilToday11" /var/ossec/logs/archives/archives.json | tail -1 | python3 -m json.tool | grep -E '"rule"|"id"' | head -10
```
```bash
# 92300 rule 존재 확인
docker exec single-node-wazuh.manager-1 grep -rn "92300" /var/ossec/ruleset/rules/
```

0860-sysmon_id_13.xml:11:  <rule id="92300" level="0">

92300이 level="0" — 1장에서 정리한 그 문제 그대로. level 0 rule은 child rule 체이닝을 막음. 100220이 if_sid>92300을 참조해도 92300이 이벤트를 suppress하고 있어서 발동 안 됨.

또한 Image 1에서 Expecting value: line 1 column 1 (char 0) — EvilToday11이 archives에도 아직 없음. manager restart 후 agent eventchannel이 다시 끊겼을 가능성.

두 가지 동시 해결:
```bash
# 1. 92300을 level 3으로 overwrite (local_rules.xml에)
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << EOF
<group name="sysmon,windows,">

  <!-- 92300 suppress 해제 -->
  <rule id="92300" level="3" overwrite="yes">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID" type="pcre2">^13$</field>
    <description>Sysmon - Event 13: Registry value set</description>
    <group>sysmon_event_13,</group>
  </rule>

</group>
EOF'

docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```

재시작 후 92300의 실제 parent sid가 뭔지 먼저 확인해야 함:
```bash
docker exec single-node-wazuh.manager-1 sed -n '8,25p' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

overwrite 전에 92300의 if_sid 값 확인하고 그대로 써야 함.

local_rules.xml에 뭐가 들어있는지 확인:
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```

0860 파일의 100220 룰 현재 상태:
```bash
docker exec single-node-wazuh.manager-1 grep -A8 'id="100220"' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

현재 상태 정리:

local_rules.xml — 92300을 overwrite, if_sid>61600, win.system.eventID ^13$으로 suppress 해제 시도 중

0860 파일의 100220 — if_sid>92300, image: powershell, targetObject: CurrentVersion\\Run ← 필드명 올바름

문제는 local_rules.xml의 92300 overwrite가 원본 92300과 조건이 다름. 원본은 if_group>sysmon_event_13인데 overwrite는 if_sid>61600 + eventID ^13$으로 작성됨. overwrite 시 조건이 달라지면 Wazuh가 다른 rule로 인식할 수 있음.

원본 92300과 동일한 조건으로 overwrite:
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << EOF
<group name="sysmon,windows,">

  <rule id="92300" level="3" overwrite="yes">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion.Run</field>
    <options>no_full_log</options>
    <description>T1547.001 - Registry Run key modified</description>
    <mitre><id>T1547.001</id></mitre>
    <group>sysmon_event_13,</group>
  </rule>

</group>
EOF'

docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```

이렇게 하면 92300이 level 3으로 살아있고, 100220이 if_sid>92300으로 체이닝 가능.
```bash
# Windows
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday11" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday12" -Value "calc.exe" -PropertyType String -Force
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday12" /var/ossec/logs/alerts/alerts.json | tail -3
```

여전히 없음. archives에는 도달하는지 먼저 확인:

archives에는 EvilToday12 도달 확인. eventID 13, powershell, CurrentVersion\Run 다 있음.

근데 alerts에 없다는 건 rule 매칭 자체가 실패하는 것. wazuh-logtest로 실제 이벤트를 rule 엔진에 직접 통과시켜서 어느 rule이 매칭되는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday12" /var/ossec/logs/archives/archives.json | tail -1 | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('full_log', d.get('data', '')))
"
```

full_log 내용 추출해서 logtest에 넣어야 하는데, 더 빠른 방법:
```bash
# analysisd 디버그 로그에서 rule 매칭 과정 확인
docker exec single-node-wazuh.manager-1 grep -a "92300\|100220" /var/ossec/logs/ossec.log | tail -10
```
```bash
# 또는 wazuh-logtest 인터랙티브 모드
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```
```bash
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-26T09:43:45.3303179Z","eventRecordID":"22401","processID":"2776","threadID":"4020","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","messag
```

두 개의 핵심 경고 발견:
```bash
WARNING: Could not open file 'ruleset/rules/0860-sysmon_id_13.xml' due to [(13)-(Permission denied)]
WARNING: Rule ID '92300' does not exist but 'overwrite' is set to 'yes'. Still, the rule will be loaded.
```

문제 1: 0860 파일을 docker cp로 수정할 때 권한이 root로 바뀜 → wazuh가 읽지 못함 → 100220 룰 로드 안 됨

문제 2: 92300 overwrite가 원본을 못 읽으니 "존재하지 않는 rule overwrite" 경고

Ctrl+C로 logtest 종료 후:
```bash
# 0860 파일 권한 수정
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/ruleset/rules/0860-sysmon_id_13.xml

# 확인
docker exec single-node-wazuh.manager-1 ls -la /var/ossec/ruleset/rules/0860-sysmon_id_13.xml

# manager restart
docker restart single-node-wazuh.manager-1 && sleep 40
```
```bash
# Windows
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday12" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday13" -Value "calc.exe" -PropertyType String -Force
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday13" /var/ossec/logs/alerts/alerts.json | tail -3
```

여전히 없음. logtest로 다시 확인, 이번엔 경고 메시지가 바뀌었는지 봐야 함:
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```
```bash
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"13","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION"},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\EvilToday13","details":"calc.exe"}}}
```

새로운 핵심 경고:
```bash
WARNING: (7605): It is not possible to overwrite 'if_group' value in rule '92300'. The original value is retained.
```

Wazuh는 if_group을 overwrite로 변경할 수 없음. 원본 값이 유지됨. 즉 92300 overwrite 자체가 level만 바꾸고 나머지는 원본 그대로.

그리고 Phase 2에서 필드가 win.eventdata.image, win.eventdata.targetObject로 디코딩됨 — logtest에서는 이 prefix가 붙어있음.

근본 원인: 0860 파일의 100220 룰이 image, targetObject로 작성돼 있는데, logtest Phase 2 출력은 win.eventdata.image, win.eventdata.targetObject. 실제 rule 매칭 시 필드명이 달라서 매칭 실패.

Phase 3 없음 = 아무 rule도 매칭 안 됨.

원인 확정: logtest Phase 2에서 필드가 win.eventdata.image, win.eventdata.targetObject로 디코딩되는데, 0860 파일의 100220은 image, targetObject (prefix 없음)로 작성돼 있어서 매칭 실패.

0860 파일의 100220 룰 필드명 수정:
```bash
# 컨테이너에서 꺼내기
docker cp single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml ~/0860-sysmon_id_13.xml

# 수정
sed -i 's/<field name="image" type="pcre2">(?i)powershell<\/field>/<field name="win.eventdata.image" type="pcre2">(?i)powershell<\/field>/' ~/0860-sysmon_id_13.xml
sed -i 's/<field name="targetObject" type="pcre2">(?i)CurrentVersion\\\\Run<\/field>/<field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion\\\\Run<\/field>/' ~/0860-sysmon_id_13.xml

# 확인
grep -A8 'id="100220"' ~/0860-sysmon_id_13.xml
```

확인 후 다시 넣기:
```bash
docker cp ~/0860-sysmon_id_13.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```

100220 룰 필드명 수정 확인:
```bash
<field name="win.eventdata.image" ...>(?i)powershell</field>
<field name="win.eventdata.targetObject" ...>(?i)CurrentVersion\\Run</field>
```

테스트
```bash
# Windows
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday13" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday14" -Value "calc.exe" -PropertyType String -Force
```

먼저 manager 상태 확인:
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
```

그리고 logtest로 경고 메시지 바뀌었는지 확인:
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

manager 정상 실행 중. logtest 준비됨.

아래 한 줄 복사해서 붙여넣고 엔터:
```bash
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"13","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION"},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\EvilToday14","details":"calc.exe"}}}
```

Phase 2 디코딩은 정상.

Phase 3 없음. 근본 원인은 92300이 이 이벤트에 매칭 자체가 안 되는 것.

92300의 원본 조건:
```bash
<if_group>sysmon_event_13</if_group>
```

logtest 입력에 sysmon_event_13 그룹이 없음. 이 그룹은 상위 rule 체인에서 부여되는데, logtest에 raw JSON만 넣으면 상위 rule 체인이 없어서 그룹 할당이 안 됨.

실제 이벤트 전체 full_log로 logtest 테스트해야 함. archives에서 꺼내서:
```bash
# logtest 종료 후
docker exec single-node-wazuh.manager-1 grep -a "EvilToday14" /var/ossec/logs/archives/archives.json | tail -1 | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d['full_log'])
"
```

full_log 확인됨. 이걸 logtest에 넣어야 함:
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```
```bash
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-26T09:57:36.0497793Z","eventRecordID":"22652","processID":"2776","threadID":"4020","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-26 09:57:36.045\r\nProcessGuid: {4fb3ada3-d0f1-69ed-3c01-000000000600}\r\nProcessId: 3672\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilToday14\r\nDetails: calc.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-26 09:57:36.045","processGuid":"{4fb3ada3-d0f1-69ed-3c01-000000000600}","processId":"3672","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\EvilToday14","details":"calc.exe","user":"DESKTOP-5408CBA\\\\yhc"}}}
```

결과
```bash
** Wazuh-Logtest: WARNING: (7605): It is not possible to overwrite 'if_group' value in rule '92300'. The original value is retained.

**Phase 1: Completed pre-decoding.
	full event: '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-26T09:57:36.0497793Z","eventRecordID":"22652","processID":"2776","threadID":"4020","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-26 09:57:36.045\r\nProcessGuid: {4fb3ada3-d0f1-69ed-3c01-000000000600}\r\nProcessId: 3672\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilToday14\r\nDetails: calc.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-26 09:57:36.045","processGuid":"{4fb3ada3-d0f1-69ed-3c01-000000000600}","processId":"3672","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\EvilToday14","details":"calc.exe","user":"DESKTOP-5408CBA\\\\yhc"}}}'

**Phase 2: Completed decoding.
	name: 'json'
	win.eventdata.details: 'calc.exe'
	win.eventdata.eventType: 'SetValue'
	win.eventdata.image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
	win.eventdata.processGuid: '{4fb3ada3-d0f1-69ed-3c01-000000000600}'
	win.eventdata.processId: '3672'
	win.eventdata.ruleName: 'T1547_Run_Key_Create'
	win.eventdata.targetObject: 'HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilToday14'
	win.eventdata.user: 'DESKTOP-5408CBA\\yhc'
	win.eventdata.utcTime: '2026-04-26 09:57:36.045'
	win.system.channel: 'Microsoft-Windows-Sysmon/Operational'
	win.system.computer: 'DESKTOP-5408CBA'
	win.system.eventID: '13'
	win.system.eventRecordID: '22652'
	win.system.keywords: '0x8000000000000000'
	win.system.level: '4'
	win.system.message: '"Registry value set:
RuleName: T1547_Run_Key_Create
EventType: SetValue
UtcTime: 2026-04-26 09:57:36.045
ProcessGuid: {4fb3ada3-d0f1-69ed-3c01-000000000600}
ProcessId: 3672
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetObject: HKU\S-1-5-21-3385978295-689239366-777767380-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilToday14
Details: calc.exe
User: DESKTOP-5408CBA\yhc"'
	win.system.opcode: '0'
	win.system.processID: '2776'
	win.system.providerGuid: '{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'
	win.system.providerName: 'Microsoft-Windows-Sysmon'
	win.system.severityValue: 'INFORMATION'
	win.system.systemTime: '2026-04-26T09:57:36.0497793Z'
	win.system.task: '13'
	win.system.threadID: '4020'
	win.system.version: '2'

```

Phase 3 없음. 디코딩은 완벽한데 rule 매칭이 전혀 안 됨.

원인 확정: windows_eventchannel decoder가 아니라 json decoder로 처리되고 있음. 실제 agent에서 오는 이벤트는 windows_eventchannel decoder를 통해 처리되는데, logtest에 raw JSON을 넣으면 json decoder로 처리됨.

실제 파이프라인에서 어떤 rule이 매칭되는지 확인하는 가장 직접적인 방법:
```bash
# Ctrl+C로 logtest 종료 후
# alerts.json에서 003 agent의 최근 alert 확인 (rule id 포함)
docker exec single-node-wazuh.manager-1 grep -a '"agent":{"id":"003"' /var/ossec/logs/alerts/alerts.json | tail -5 | python3 -m json.tool | grep -E '"id"|"level"|"description"'
```

그리고 archives에서 EvilToday14가 어느 rule로 처리됐는지:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday14" /var/ossec/logs/archives/archives.json | tail -1 | python3 -m json.tool | grep -E '"rule"|"decoder"'
```

archives에는 rule 정보가 없을 수 있음. 결국 실제 alert이 안 나오는 이유는 92300 자체가 이 이벤트를 안 잡는 것.

92300의 실제 parent chain 확인:
```bash
docker exec single-node-wazuh.manager-1 head -30 /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

그리고 archives에서 EvilToday14가 어느 rule로 처리됐는지:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday14" /var/ossec/logs/archives/archives.json | tail -1 | python3 -m json.tool | grep -E '"rule"|"decoder"'
```

archives에는 rule 정보가 없을 수 있음. 결국 실제 alert이 안 나오는 이유는 92300 자체가 이 이벤트를 안 잡는 것.

92300의 실제 parent chain 확인:

이제 전체 그림이 보임.

핵심 문제: 92300은 if_group>sysmon_event_13을 요구하는데, sysmon_event_13 그룹을 부여하는 상위 rule이 별도 파일에 있음. 0860 파일은 그 그룹을 받아서 처리하는 파일이고, 그룹을 부여하는 rule이 어디있는지 찾아야 함:
```bash
docker exec single-node-wazuh.manager-1 grep -rn "sysmon_event_13" /var/ossec/ruleset/rules/ | grep -v "0860"
```

두 파일에서 sysmon_event_13 그룹을 부여하고 있음. 어느 rule인지 확인:
```bash
docker exec single-node-wazuh.manager-1 sed -n '90,105p' /var/ossec/ruleset/rules/0330-sysmon_rules.xml
docker exec single-node-wazuh.manager-1 sed -n '130,145p' /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
```

0330 파일: rule 185011 (level 0) — sysmon_event_13 그룹 부여

0595 파일: rule 61615 (level 0) — sysmon_event_13 그룹 부여

두 rule 모두 level 0. 이 중 하나가 이벤트를 먼저 잡고 sysmon_event_13 그룹을 붙인 다음 0860의 92300으로 체이닝되는 구조.

문제는 185011과 61615가 모두 level 0이라 alert는 안 나오지만 child 체이닝은 가능해야 함. 그런데 92300도 level 0이고 이게 이벤트를 최종 소비하면 100220까지 못 감.

가장 단순한 해결: 92300을 0860 파일에서 직접 level 12로 수정. overwrite 말고 파일 자체를:
```bash
docker cp single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml ~/0860-sysmon_id_13.xml

# 92300 level 0 → level 3으로 변경
sed -i 's/<rule id="92300" level="0">/<rule id="92300" level="3">/' ~/0860-sysmon_id_13.xml

# 확인
grep -n 'id="92300"' ~/0860-sysmon_id_13.xml

docker cp ~/0860-sysmon_id_13.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```

그리고 local_rules.xml의 92300 overwrite는 삭제 (충돌 방지):
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << EOF
<group name="sysmon,windows,">
</group>
EOF'
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
```

확인:

- 92300 level="3" 수정 완료
- local_rules.xml 비움
- restart 완료
```bash
# Windows
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday14" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday15" -Value "calc.exe" -PropertyType String -Force
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday15" /var/ossec/logs/alerts/alerts.json | tail -3
```

여전히 없음. archives에는 도달했는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday15" /var/ossec/logs/archives/archives.json | tail -1 | python3 -m json.tool | grep -E '"eventID"|"decoder"|"ruleName"'
```

archives 도달 확인. eventID 13, T1547_Run_Key_Create. 근데 alerts 없음.

decoder가 windows_eventchannel이 아니라 커스텀 decoder로 처리되고 있음. "decoder": {"eventID": "13", "ruleName": "T1547_Run_Key_Create"} — 이건 Sysmon config의 ruleName이 decoder 필드로 들어간 것.

실제 Wazuh decoder name 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday15" /var/ossec/logs/archives/archives.json | tail -1 | python3 -m json.tool | grep -E '"name"|"decoder"' | head -5
```

그리고 92300이 실제로 이 이벤트를 잡고 있는지 alerts에서 rule 92300 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a '"id":"92300"' /var/ossec/logs/alerts/alerts.json | tail -3
```

decoder는 windows_eventchannel 정상. 근데 92300 alert도 없음.

즉 92300이 level 3으로 수정됐는데도 alert가 안 나옴 — 0860 파일 수정이 실제로 컨테이너에 반영됐는지 재확인:
```bash
docker exec single-node-wazuh.manager-1 grep 'id="92300"' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

파일에는 level="3" 맞음. 근데 alert가 없다는 건 92300이 이 이벤트를 아예 안 잡고 있는 것.

92300의 조건:
```bash
<if_group>sysmon_event_13</if_group>
<field name="win.eventdata.targetObject">...CurrentVersion\\Run...</field>
```

sysmon_event_13 그룹을 부여하는 rule이 185011 또는 61615인데, 이것들도 level 0이라 체이닝이 되긴 해야 함. 근데 혹시 185011과 61615가 서로 다른 조건으로 매칭되고 있어서 92300까지 못 가는 것일 수도 있음.

가장 직접적인 확인:
```bash
# alerts에서 최근 003 agent 이벤트 rule id 확인
docker exec single-node-wazuh.manager-1 grep -a '"id":"003"' /var/ossec/logs/alerts/alerts.json | tail -1 | python3 -m json.tool | grep -E '"rule"|"id"|"level"|"description"'
```

003 agent에서 오는 alert가 있는지, 있다면 어느 rule인지 확인. alerts.json 자체가 비어있는 건지도 확인:
```bash
docker exec single-node-wazuh.manager-1 wc -l /var/ossec/logs/alerts/alerts.json
```

alerts.json에 307줄 있고 003 agent alert도 있음 (rule 60106 Windows Logon Success). alert 파이프라인 자체는 동작 중.

근데 Sysmon EventID 13 관련 alert가 없는 건 92300의 if_group>sysmon_event_13 조건이 매칭 안 되는 것.

185011/61615가 sysmon_event_13 그룹을 붙이는데, 이것들이 실제로 이 이벤트를 잡고 있는지 확인:
```bash
# alerts에서 185011 또는 61615 rule 확인
docker exec single-node-wazuh.manager-1 grep -a '"id":"185011"\|"id":"61615"' /var/ossec/logs/alerts/alerts.json | tail -3
```
```bash
# archives에서 EvilToday15가 어떤 rule로 처리됐는지 — rule 섹션 확인
docker exec single-node-wazuh.manager-1 grep -a "EvilToday15" /var/ossec/logs/archives/archives.json | tail -1 | python3 -m json.tool | grep -A5 '"rule"'
```

archives에 rule 섹션이 아예 없음. Wazuh는 archives.json에 rule 정보를 포함하지 않음 (alerts.json에만 있음).

그리고 185011/61615도 alerts에 없음 — level 0이라 당연함.

접근 방식을 바꿔야 함. 지금까지 rule 체인 디버깅이 너무 복잡해졌으니, 가장 단순하게 독립적인 rule로 만들어서 체인 없이 직접 매칭:
```bash
docker cp single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml ~/0860-sysmon_id_13.xml

# 100220을 if_sid 없이 독립 rule로 변경
cat ~/0860-sysmon_id_13.xml
```

결과
```bash
[yhc@localhost ~]$ docker cp single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml ~/0860-sysmon_id_13.xml

# 100220을 if_sid 없이 독립 rule로 변경
cat ~/0860-sysmon_id_13.xml
Successfully copied 4.58kB (transferred 6.14kB) to /home/yhc/0860-sysmon_id_13.xml
<!--
  Copyright (C) 2015, Wazuh Inc.
-->

<!--
  Sysmon Event 13 rules ID: 92300 - 92399
-->

<group name="sysmon,sysmon_eid13_detections,windows,">

  <rule id="92300" level="3">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)SOFTWARE\\\\(WOW6432NODE\\\\M|M)ICROSOFT\\\\WINDOW(S|S NT)\\\\CURRENTVERSION\\\\(RUN|TERMINAL SERVER\\\\INSTALL\\\\SOFTWARE\\\\MICROSOFT\\\\WINDOWS\\\\CURRENTVERSION\\\\RUN)</field>
    <options>no_full_log</options>
    <description>Added registry content to be executed on next logon</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="92301" level="12">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.details" type="pcre2">(?i)\.(lnk|vbs|vba)</field>
    <options>no_full_log</options>
    <description>Suspicious file extension detected in registry ASEP to be executed on next logon</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="100220" level="12">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell</field>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion\\Run</field>
    <description>T1547 - Run key modified via PowerShell</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
  <rule id="92302" level="6">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)reg\.exe</field>
    <options>no_full_log</options>
    <description>Registry entry to be executed on next logon was modified using command line application reg.exe</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="92303" level="12">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.details" type="pcre2">(?i)(VNC|tvnserver\.exe)</field>
    <options>no_full_log</options>
    <description>Registry entry to be executed on next logon points to a remote access tool</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="92304" level="6">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CLASSES\\\\(FOLDER|MS-SETTINGS)\\\\SHELL\\\\OPEN\\\\COMMAND</field>
    <options>no_full_log</options>
    <description>Modified registry key associated to UAC bypass by auto-elevated processes</description>
    <mitre>
      <id>T1548.002</id>
      <id>T1112</id>
    </mitre>
  </rule>

  <rule id="92305" level="12">
    <if_sid>92304</if_sid>
    <field name="win.eventdata.details" type="pcre2">(?i)(cmd|powershell)\.exe</field>
    <options>no_full_log</options>
    <description>Command interpreter added to registry key associated to UAC bypass by auto-elevated processes</description>
    <mitre>
      <id>T1548.002</id>
      <id>T1112</id>
    </mitre>
  </rule>

  <rule id="92306" level="12">
    <if_sid>92304</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)(cmd|powershell)\.exe</field>
    <options>no_full_log</options>
    <description>$(win.eventdata.image) added to the registry a subkey associated with UAC bypass by auto-elevated processes</description>
    <mitre>
      <id>T1548.002</id>
      <id>T1112</id>
    </mitre>
  </rule>

  <rule id="92307" level="3">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.details" type="pcre2">(?i)\.exe</field>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)System\\\\CurrentControlSet\\\\Services</field>
    <options>no_full_log</options>
    <description>Evidence of new service creation found in registry under $(win.eventdata.targetObject) binary is: $(win.eventdata.details)</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
  </rule>

  <rule id="92308" level="3">
    <if_sid>61615</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CLSID.*LocalServer</field>
    <options>no_full_log</options>
    <description>Possible COM Hijacking evidence found in registry under $(win.eventdata.targetObject) binary is: $(win.eventdata.details)</description>
    <mitre>
      <id>T1546.015</id>
    </mitre>
  </rule>

  <rule id="92309" level="15">
    <if_sid>92308</if_sid>
    <field name="win.eventdata.details" type="pcre2">(?i)AppData</field>
    <options>no_full_log</options>
    <description> COM Hijacking evidence found in registry under $(win.eventdata.targetObject) suspicious binary is: $(win.eventdata.details)</description>
    <mitre>
      <id>T1546.015</id>
    </mitre>
  </rule>

</group>

```

92300의 regex가 문제:
```bash
(?i)SOFTWARE\\\\(WOW6432NODE\\\\M|M)ICROSOFT\\\\WINDOW(S|S NT)\\\\CURRENTVERSION\\\\(RUN|...)
```

이 regex는 SOFTWAREMICROSOFT 또는 SOFTWAREWOW6432NODEMICROSOFT를 매칭하려는 건데 \\\\ 이스케이프가 잘못돼서 실제로 SOFTWARE\M 패턴을 찾고 있음. SOFTWARE\Microsoft 경로를 못 잡는 것.

실제 targetObject: HKU\...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilToday15

0860 파일에서 92300 regex 수정:
```bash
# 호스트 파일 직접 편집
vi ~/0860-sysmon_id_13.xml
```

92300의 field를 아래로 교체:
```bash
<field name="win.eventdata.targetObject" type="pcre2">(?i)SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</field>
```

저장 후:
```bash
docker cp ~/0860-sysmon_id_13.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```
```bash
docker exec single-node-wazuh.manager-1 grep -A3 'id="92300"' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

archives에 도달했는지 먼저:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday16" /var/ossec/logs/archives/archives.json | tail -1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['timestamp'])"
```

EvilToday16이 archives에도 없음. Windows에서 키 생성이 안 됐거나 agent 전송이 또 끊긴 것.

Windows에서 직접 확인:
```bash
# 키 생성 확인
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Select-Object EvilToday16

# Sysmon 캡처 확인
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Where-Object {$_.Id -eq 13} | Select-Object TimeCreated
```

EvilToday16 키는 있는데 Sysmon EventID 13이 없음. 기존 키에 동일 값 재설정이라 Sysmon이 캡처 안 한 것 — EvilToday16이 이미 있었던 것.
```bash
# 삭제 후 재생성
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday16" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilToday17" -Value "calc.exe" -PropertyType String -Force
Start-Sleep -Seconds 3
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Where-Object {$_.Id -eq 13} | Select-Object TimeCreated
```

Sysmon EventID 13 캡처 확인 2026-04-26 오후 7:35:10. Rocky에서:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday17" /var/ossec/logs/alerts/alerts.json | tail -3
```

계속 안 됨. 근본적으로 다른 접근이 필요함.

지금까지 문제의 핵심: sysmon_event_13 그룹을 부여하는 상위 rule (185011 또는 61615)이 실제로 이 이벤트를 잡고 있는지 확인이 안 된 상태에서 92300만 계속 고치고 있었음.

185011/61615 rule 내용 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -n "185011\|61615" /var/ossec/ruleset/rules/0330-sysmon_rules.xml | head -5
docker exec single-node-wazuh.manager-1 grep -n "185011\|61615" /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml | head -5
```

그리고 이 rule들의 parent인 18101/61600 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -n '"18101"\|"61600"' /var/ossec/logs/alerts/alerts.json | tail -3
```

모두 level 0이라 alerts에 없는 건 당연함. 체인 자체가 동작하는지 확인하려면 다른 방법 필요.

접근 방식 전환: rule 체인 디버깅 그만하고, 92300을 if_group 조건 없이 완전히 독립적인 rule로 만들어서 직접 win.system.eventID로 매칭:
```bash
docker cp single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml ~/0860-sysmon_id_13.xml
vi ~/0860-sysmon_id_13.xml
```

92300 rule 전체를 아래로 교체:
```bash
<rule id="92300" level="3">
  <if_sid>61600</if_sid>
  <field name="win.system.eventID" type="pcre2">^13$</field>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</field>
  <description>T1547.001 - Registry Run key modified</description>
  <mitre><id>T1547.001</id></mitre>
  <group>sysmon_event_13,</group>
</rule>
```

if_group 대신 if_sid>61600 (Sysmon 기본 부모 rule) + eventID 13 직접 필터링. 61600이 뭔지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -n 'id="61600"' /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml | head -3
```

61600도 level 0. 그리고 파일 저장 및 cp 완료된 것 같음.

수정 내용 확인 후 restart:
```bash
docker exec single-node-wazuh.manager-1 grep -A4 'id="92300"' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker cp ~/0860-sysmon_id_13.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```

92300이 아직 <if_group>sysmon_event_13</if_group> 그대로임. vi 수정이 저장 안 된 것 — swap 파일 때문에 이전 버전이 cp된 것.

swap 파일 삭제 후 다시 편집:
```bash
rm ~/.0860-sysmon_id_13.xml.swp
vi ~/0860-sysmon_id_13.xml
```

이번엔 vi 대신 sed로 직접 수정:
```bash
# if_group 라인 삭제하고 if_sid + eventID 두 줄로 교체
sed -i 's|<if_group>sysmon_event_13</if_group>|<if_sid>61600</if_sid>\n        <field name="win.system.eventID" type="pcre2">^13$</field>|' ~/0860-sysmon_id_13.xml

# 확인
grep -A5 'id="92300"' ~/0860-sysmon_id_13.xml
```
```bash
<rule id="92300" level="3">
  <if_sid>61600</if_sid>
  <field name="win.system.eventID" type="pcre2">^13$</field>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</field>
```

배포:
```bash
docker cp ~/0860-sysmon_id_13.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```

정리하면: 지금까지 문제는 rule 체인이 복잡하고 각 단계에서 막히는 지점이 달랐음. 더 이상 체인 디버깅에 시간 쓰지 말고 완전히 독립적인 rule을 local_rules.xml에 만들어서 체인 없이 직접 매칭:
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << EOF
<group name="sysmon,windows,">
  <rule id="100221" level="12">
    <decoded_as>windows_eventchannel</decoded_as>
    <field name="win.system.eventID" type="pcre2">^13\$</field>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion.Run</field>
    <description>T1547.001 - Run key modified via registry</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
EOF'

docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```

^13\$가 XML에 그대로 들어가서 regex가 ^13\$가 됨 — 잘못됨. 그리고 chown도 잘림.

파일은 일단 들어간 것 같으니 내용 확인 후 권한 따로 수정:
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
```
```bash
docker exec single-node-wazuh.manager-1 bash -c "cat > /var/ossec/etc/rules/local_rules.xml << 'XMLEOF'
<group name=\"sysmon,windows,\">
  <rule id=\"100221\" level=\"12\">
    <decoded_as>windows_eventchannel</decoded_as>
    <field name=\"win.system.eventID\" type=\"pcre2\">^13\$</field>
    <field name=\"win.eventdata.targetObject\" type=\"pcre2\">(?i)CurrentVersion.Run</field>
    <description>T1547.001 - Run key modified via registry</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
XMLEOF"

docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```

현재까지 확인된 사실 정리:

- Sysmon EventID 13 캡처 ✅
- Agent → Manager archives 전송 ✅
- decoder: windows_eventchannel ✅
- alerts 발동 ❌ (decoded_as 독립 rule 포함 모든 시도 실패)


## 2026-04-26 Wazuh EventID 13 파이프라인 디버깅 TIL
> 날짜: 2026-04-26

환경: VMware Workstation / Rocky Linux 9 (Wazuh Docker) / Windows 10 (Sysmon + Wazuh agent 4.9.2)

목표: Sysmon EventID 13 (Run 키 변조) → Wazuh alert 발동 (rule 100220/100221)

### 최종 상태

### 발견한 문제들

#### 문제 1 — logall_json 휘발 문제

현상: archives.json이 Apr 24 이후 업데이트 안 됨. 오늘 이벤트가 archives에 없음.

원인: Docker volume 마운트 구조상 컨테이너 내부 ossec.conf 수정이 재시작 시 덮어씌워짐.

해결: 호스트 볼륨 소스 파일 직접 수정
```bash
# 마운트 경로 확인
docker inspect single-node-wazuh.manager-1 \
  --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' | grep ossec.conf
# → /home/yhc/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf

# 영구 수정
sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/' \
  /home/yhc/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
sed -i 's/<logall_json>no<\/logall_json>/<logall_json>yes<\/logall_json>/' \
  /home/yhc/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
```

#### 문제 2 — 64비트 PowerShell 필요

현상: PowerShell에서 레지스트리 키 생성해도 Sysmon EventID 13 미캡처

원인: 32비트 PowerShell 실행 시 레지스트리 경로가 WOW6432Node로 리다이렉트됨

확인:
```powershell
[Environment]::Is64BitProcess  # True 여야 함
```

#### 문제 3 — 기존 키 재설정 시 EventID 13 미발생

현상: 같은 키 이름으로 반복 테스트 시 Sysmon이 캡처 안 함

원인: 이미 존재하는 키에 동일 값 SetValue 시 Sysmon이 이벤트를 발생시키지 않음

해결: 반드시 삭제 후 새 이름으로 생성
```powershell
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilTodayN" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilTodayN+1" -Value "calc.exe" -PropertyType String -Force
```

#### 문제 4 — 0860 파일의 92300 regex 버그

현상: 92300 rule이 Run 키 이벤트를 매칭 못 함

원인: 원본 regex의 이스케이프 오류
```plain text
# 원본 (버그 있음)
(?i)SOFTWARE\\\\(WOW6432NODE\\\\M|M)ICROSOFT\\\\WINDOW(S|S NT)\\\\CURRENTVERSION\\\\(RUN|...)
# SOFTWARE\Microsoft 경로를 실제로 못 잡음
```

해결:
```xml
<field name="win.eventdata.targetObject" type="pcre2">(?i)SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</field>
```

#### 문제 5 — docker cp 후 권한 문제 반복

현상: 0860 파일 수정 배포 후 manager가 rule 파일을 못 읽음

원인: docker cp 시 파일 소유자가 root로 설정됨

해결: cp 후 항상 chown 필수
```bash
docker cp ~/0860-sysmon_id_13.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

#### 문제 6 — vi swap 파일 충돌

현상: vi로 수정 후 cp했는데 이전 버전이 배포됨

원인: 백그라운드에 이전 vi 세션이 살아있어서 swap 파일이 남아있었음. 새 vi에서 E(편집)를 선택해도 swap 기반으로 열려서 저장이 꼬임

해결:
```bash
rm ~/.0860-sysmon_id_13.xml.swp
# 이후 sed로 수정하는 것이 더 안전
sed -i 's/패턴/교체/' ~/파일.xml
```

#### 문제 7 — heredoc에서 $() bash 해석 문제

현상: bash -c 'cat > file << EOF ... EOF' 사용 시 command not found 에러

원인: description에 $(win.eventdata.targetObject) 쓰면 bash가 서브쉘로 해석

해결: $ 이스케이프 또는 single-quote heredoc 사용
```bash
# 방법 1: single-quote heredoc
docker exec single-node-wazuh.manager-1 bash -c "cat > /path << 'XMLEOF'
...내용...
XMLEOF"

# 방법 2: description에서 변수 제거
<description>T1547.001 - Run key modified via registry</description>
```

#### 문제 8 — overwrite="yes"로 if_group 변경 불가

현상: local_rules.xml에서 92300 overwrite 시도했지만 if_group 변경 안 됨

에러:
```plain text
WARNING: (7605): It is not possible to overwrite 'if_group' value in rule '92300'. The original value is retained.
```

교훈: if_group은 overwrite 불가. 원본 파일 직접 수정 필요.

### 오늘 파악한 rule 체인 구조
```plain text
windows_eventchannel decoder
    ↓
61600 (Sysmon 기본, level 0)  ← 0595-win-sysmon_rules.xml
    ↓
61615 (EventID 13 분류, level 0) → sysmon_event_13 그룹 부여  ← 0595
  또는
185011 (EventID 13 분류, level 0) → sysmon_event_13 그룹 부여  ← 0330
    ↓
92300 (Run 키 필터, level 3) ← if_group: sysmon_event_13  ← 0860-sysmon_id_13.xml
    ↓
100220 (PowerShell 탐지, level 12) ← if_sid: 92300
```

문제: 61615/185011이 sysmon_event_13 그룹을 부여하는지, 92300이 실제로 이벤트를 잡는지 확인 불가 (모두 level 0이라 alerts에 안 나옴)

### 미해결 사항

- rule 100221 (decoded_as: windows_eventchannel 독립 rule)도 alert 미발동
- archives 도달 확인됐는데 어느 rule도 매칭 안 됨
- logtest Phase 3 결과 없음 (rule 미매칭)

### 내일 확인할 것
```bash
# 1. rule 로드 확인
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest -V 2>&1 | grep "100221"

# 2. analysisd 에러 확인
docker exec single-node-wazuh.manager-1 grep -i "100221\|error\|warning" /var/ossec/logs/ossec.log | tail -20

# 3. logtest에서 decoded_as 동작 여부 확인
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# archives의 full_log 붙여넣고 Phase 3 확인

# 4. analysisd 디버그 레벨 올려서 rule 매칭 과정 추적
# ossec.conf에 <logall>yes</logall> 확인 후
# <logging><log_level>2</log_level></logging> 추가 시도
```

### 핵심 명령어 모음
```bash
# archives 최신 이벤트 타임스탬프 확인
docker exec single-node-wazuh.manager-1 bash -c \
  'grep -a "003" /var/ossec/logs/archives/archives.json | tail -1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[\"timestamp\"])"'

# archives에서 특정 키워드 이벤트 필드 확인
docker exec single-node-wazuh.manager-1 grep -a "키워드" /var/ossec/logs/archives/archives.json \
  | tail -1 | python3 -m json.tool | grep -E '"image"|"targetObject"|"decoder"|"eventID"'

# alerts에서 agent 003 최근 rule 확인
docker exec single-node-wazuh.manager-1 grep -a '"id":"003"' /var/ossec/logs/alerts/alerts.json \
  | tail -1 | python3 -m json.tool | grep -E '"rule"|"id"|"level"|"description"'

# 파일 권한 수정 (docker cp 후 필수)
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/ruleset/rules/0860-sysmon_id_13.xml

# rule 파일 검증
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest -V

# logtest 인터랙티브
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```
