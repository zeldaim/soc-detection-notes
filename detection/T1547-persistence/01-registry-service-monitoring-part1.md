# T1547 Persistence 탐지 1 — Sysmon 레지스트리·서비스 모니터링

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

Sysmon EventID 12/13(레지스트리 변경), 7045(서비스 등록)를 Wazuh로 수집해 T1547/T1543 탐지 규칙 구성. 포트폴리오에 MITRE ATT&CK 매핑으로 기재.

### 데이트 흐름
```text
Windows VM
  → Sysmon이 레지스트리 변경 감지
  → 로그 생성 (EventID 13)
  → Wazuh agent가 Rocky로 전송
  → Rocky의 Wazuh가 규칙과 비교
  → 매칭되면 알럿 발생
```

> 📷 구성도: Windows 10 VM(피해자)에서 악성 행위(Run 키 변조·서비스 등록) → Sysmon이 EventID 12/13 로그 생성 → Wazuh agent가 암호화해 Rocky Linux(관제 서버)로 전송 → 매니저가 /var/ossec/etc/rules/의 local_rules.xml과 매칭 → 알림(alerts.json / Kibana).

### 프로젝트 수행과

1. 파일 배포

1-1. Sysmon config 업데이트 (Windows 10 VM)

Sysmon에게 레지스터리 Run키 변조를  Event13으로 기록후 탐지 요청
```powershell
# 관리자 PowerShell에서 실행
# 현재 config 백업
Copy-Item "C:\\Windows\\sysmon_config.xml" "C:\\Windows\\sysmon_config_backup.xml"

# 새 config 적용 (파일을 Windows VM으로 복사한 뒤)
Sysmon64.exe -c sysmon_persistence.xml

# 적용 확인
Sysmon64.exe -c
# → 출력에서 RegistryEvent / FileCreate include 규칙 확인
```

> 📷 `Sysmon64.exe -c sysmon_persistence.xml`로 설정 적용: 스키마 4.90 설정 파일 검증 완료, "Configuration updated".

Sysmon이 Run키 변조 감시 시작

1-2. Wazuh 규칙 배포 (Rocky Linux 관리 서버)
```bash
# 규칙 파일 복사
# 파일이 일반 서버에 위치할 경우
# sudo cp wazuh_persistence_rules.xml /var/ossec/etc/rules/local_rules.xml
# 파일이 컨테이너 안에 있을 경우
docker cp wazuh_persistence_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
# 문법 검증 (배포 전 필수)
sudo /var/ossec/bin/wazuh-logtest -V

# 규칙 reload (Wazuh manager 재시작 없이)
# sudo /var/ossec/bin/ossec-control reload
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest -V

# 또는 전체 재시작
# sudo systemctl restart wazuh-manager
docker restart single-node-wazuh.manager-1
```

> 📷 작성한 `wazuh_persistence_rules.xml`(6.7kB)을 매니저 컨테이너의 local_rules.xml로 복사.

> 📷 룰 복사 후 매니저 컨테이너 재시작.

> 📷 `wazuh-logtest -V`로 버전 확인: Wazuh v4.9.0 (앞 줄은 잘못 입력한 명령).
```text
전체흐름
Windows에서 Run 키가 변조되면 → Sysmon이 EventID 13 기록 → Wazuh agent가 Rocky로 전송 → Rocky의 Rule 100201이 "Run 키에 값 쓰기 감지" 조건과 매칭 → 알럿 발생.
```

1-3. 테스트
```powershell
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest" -Value "C:\temp\test.exe" -Force
```
```powershell
docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json
```

> 📷 alerts.json 실시간 출력: Windows Security 채널 4624 로그온(SYSTEM, logonType 5, services.exe)이 60106 "Windows Logon Success"(level 3, T1078)로 계속 기록됨.

알럿은 확인되었다. 파이프라인 전체가 살아있다는 의미이지만 이 Windows 로그온 이벤트 중에, Run키 알럿을 확인해야함.
```powershell
docker exec single-node-wazuh.manager-1 grep -a "100201\|100200\|SOCLabTest" /var/ossec/logs/alerts/alerts.json | tail -5
```

> 📷 alerts.json에서 커스텀 룰 100200·100201과 테스트 값 SOCLabTest 검색 → 결과 없음.

Run키 알럿이 하나도 없음.

Window VM Poweshell에  Run키 등록 확인.

> 📷 Windows에서 HKCU Run 키의 SOCLabTest = `C:\temp\test.exe` 등록 확인.

위의 캡쳐에서C:\temp\test.exe 값이 잘 들어가 있음을 확인함.

Sysmon이 감지 했는지 Window 이벤트 로그에서 확인한다. - Event13을 확인.
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Where-Object {$_.Id -eq 13} | Select-Object TimeCreated, Message | Format-List
```

> 📷 Sysmon 로그 조회 결과: EventID 13이 기록되지만 대부분 RuleName **T1543_Service_Registry**, Image lsass.exe, TargetObject `HKLM\System\CurrentControlSet\Services\W32Time\SecureTimeLimits\…`(시간 동기화 서비스의 정상 변경) — 노이즈만 보이고 Run 키 이벤트는 없음.

EventID 13이 잡히고 있고 T1543_Service_Registry 룰네임도 확인됨.

SOCLabTest Run 키를 확인하기 위해 Run키를 사용해서 한 번 더 트리거하기.
```powershell
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest" -Value "C:\temp\test.exe" -Force

```
```bash
docker exec single-node-wazuh.manager-1 grep -a "SOCLabTest\|100201" /var/ossec/logs/alerts/alerts.json | tail -5
```
```powershell
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Select-Object SOCLabTest
```

> 📷 SOCLabTest를 지우고 2초 뒤 다시 생성(`C:\temp\test.exe`)해 이벤트를 새로 발생시킴.

> 📷 alerts.json에서 SOCLabTest·100201 → 결과 없음.

Run키는 등록이 되었다.  하지만 알럿은 잡히고 있지 않음.

Sysmon이 감지는 하는데 Wazuh까지 전달이 안되고 있음.
```bash
#powershell- Sysmon 수집 설정 확인
type "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String -Pattern "Sysmon"
```

> 📷 Windows 에이전트 ossec.conf에 `<location>Microsoft-Windows-Sysmon/Operational</location>` 수집 설정 존재.

Sysmon 수집 설정 확인 결과 설정은 존재함.  그러므로 매칭에 문제가 있을 수 있다.

규칙 파일이 컨테이너에 제대로 들어갔는지 확인
```bash
docker exec single-node-wazuh.manager-1 grep -n "100201" /var/ossec/etc/rules/local_rules.xml
```

> 📷 local_rules.xml: 100201(level 12)이 40번째 줄에 있고, 147번째 줄에서 다른 룰이 `if_matched_sid 100201`로 참조(상관 분석 룰).

Rule 100201이 40번째 줄에 있음을 확인함.

Wazuh가 Sysmon EventID 13을 어떤 그룹으로 분류하는지 확인.

규칙이 sysmon_evevt_13 그룹을 기다리는데 Sysmon EventID 13을 그 그룹으로 분류하는지 확인.
```bash
docker exec single-node-wazuh.manager-1 grep -r "sysmon_event_13" /var/ossec/ruleset/rules/
```

> 📷 `sysmon_event_13` 그룹: 0330·0595에서 group으로 부여되고, 0860-sysmon_id_13.xml에서 if_group으로 3번 사용.

그룹명 매칭 확인함

Sysmon 이벤트가 실제로 Wazuh에 도달하는지 확인.

Run 키 관련 이벤트가 alerts가 아닌 일반 로그에 있는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "CurrentVersion.Run" /var/ossec/logs/alerts/alerts.json | tail -3
```

> 📷 alerts.json에서 "CurrentVersion.Run" → 없음.

alerts.jason이 아예 없음.

이벤트 자체가 Wazuh에 전혀 도달을 못하고 있음.

archives 로그(알럿 안 된 것도 전부 기록)에서 확인.
```bash
docker exec single-node-wazuh.manager-1 grep -a "CurrentVersion.Run" /var/ossec/logs/archives/archives.json 2>/dev/null | tail -3
```

> 📷 archives.json에서도 "CurrentVersion.Run" → 없음(당시 logall 꺼짐 또는 미수신).

archives에도 없음.

이벤트가 Windows에서 Rocky까지 아예 전송이 안 되고 있음.

Windows agent 서비스 상태확인
```powershell
Get-Service -Name "WazuhSvc"
```

> 📷 Windows `Get-Service WazuhSvc` → Running.

Runnig임. Agent는 살아있음.

그러면 살아있는 Agent가 실제로 Sysmon로그를 읽고 있는지 확인.
```powershell
type "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String -Pattern "Sysmon" -Context 2,2
```

> 📷 에이전트 ossec.conf의 Sysmon 블록: location Microsoft-Windows-Sysmon/Operational, `log_format eventchannel` — 수집 설정 정상.

eventchannel 포맷으로 Sysmon/Operational 채널을 수집하고 있음. - Agent 설정은 완벽함.

그러면 캐시문제인지 확인을 해보기 위해 Agent를 재시작하기
```powershell
Restart-Service -Name "WazuhSvc"
Start-Sleep -Seconds 5
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest2" -Value "C:\temp\evil.exe" -Force
```

그리고 록키에서 로그를 확인
```powershell
docker exec single-node-wazuh.manager-1 grep -a "SOCLabTest2\|CurrentVersion.Run" /var/ossec/logs/archives/archives.json 2>/dev/null | tail -3
```

> 📷 WazuhSvc 재시작, 5초 뒤 HKCU Run에 SOCLabTest2 = `C:\temp\evil.exe` 생성.

> 📷 archives.json에서 SOCLabTest2·CurrentVersion.Run → 없음.

이벤트가 Windows에서 전혀 안넘어오고 있음.

가설1. HKCU (현재 사용자) 키를 PowerShell로 바꾸면 Sysmon이 잡긴 하는데, Wazuh agent가 SYSTEM 권한으로 실행돼서 현재 사용자 세션 이벤트를 못 보는 경우가 있다.

우선 archives 자체가 활성화되었는지 먼저 확인:
```powershell
docker exec single-node-wazuh.manager-1 ls -la /var/ossec/logs/archives/

```

> 📷 매니저 `/var/ossec/logs/archives/`: archives.json 파일이 아예 없고 archives.log 0바이트 — archives 기록이 꺼진 상태.

archives.json이 없고 archives.log만 있는데 크기가 0이다. → archives로깅이 비활성화되어 있음.

alerts.jason 에도 없다는 것은 이벤트 자체가 안넘어오는 게 맞다. (?)

그래서

1. Wazuh manager 설정에서 archives를 킨다.
1. 동시에 Window agent가 이벤트를 실제 보내고 있는지 확인
```powershell
docker exec single-node-wazuh.manager-1 grep -a "archives" /var/ossec/etc/ossec.conf
```

> 📷 매니저 ossec.conf에서 "archives" 검색 → 없음.

위 결과를 통해 archives 설정 자체가 없음을 확인함.

이 문제를 해결하기 전에 더 중요한 문제인 alerts.jason 에도 없는 이유를 알아보기 위해 Window agent가 Sysmon 이벤트를 보내고 있는지 agent 로그를 확인.
```powershell
type "C:\Program Files (x86)\ossec-agent\ossec.log" | Select-String -Pattern "Sysmon|EventChannel" | Select-Object -Last 20
```

> 📷 Windows 에이전트 ossec.log: 13:42, 14:15, 14:33에 `(1951) Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'` — 에이전트는 Sysmon 채널을 읽고 있음.

agent가 Sysmon 채널을 읽고 있음. - Analyzing event log: 'Microsoft-Windows-Sysmon/Operational' 확인함.

하지만  시간 보면 13:42, 14:15, 14:33 — 주기적으로 체크만 하고있음

실시간으로 이벤트는 잡지 못함.

Sysmon config를 적용했을 때 기존에 발생한 이벤트는 못 잡아서 새로 이벤트를 발생시켜야 한다.

그런데 Wazuh agent가 재시작이 되면서 마지막으로 읽은 위치가 (bookmakr)가 초기화 되었을 수도 있다.

그래서 바로 이벤트를 발생시키기고 agent로그를 실시간으로 확인 시도:
```powershell

# 터미널 1: 실시간 agent 로그 모니터링
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Wait | Select-String "Sysmon|error|warn"

```

여기서 가장 중요한 점은 이번에 발생하는 로그는 Window에 있는 agent의 기록이므로 로키 서버가 아닌 같은 윈도우에서 또다른 파우쉘 창을 열어서 로그를 실시간으 보면서 Run 키 이벤트를 발생시킨다.
```powershell
# 터미널 2: Run 키 이벤트 발생
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest3" -Value "C:\temp\evil2.exe" -Force
```

결과

> 📷 에이전트 ossec.log 실시간 확인: 13:41~14:15에 `Unable to connect to [192.168.190.128]:1514/tcp`(연결 거부·강제 종료), `(1137) Lost connection with manager`, `(1208) Unable to connect to enrollment service :1515`, `Process locked due to agent is offline` 반복 — 매니저 재시작 동안 에이전트가 끊겼다가 14:15 이후 다시 Sysmon 분석 시작.

핵심 에러 발견
```powershell
Unable to connect to '[192.168.190.128]:1514/tcp': 대상 컴퓨터에서 연결을 거부했으므로 연결하지 못했습니다.
```

Windows agent가 Rocky(192.168.190.128)의 1514 포트에 연결을 못하고 있음.

그래서 이벤트를 읽긴하는데 보낼수가 없다. → 위의 가설1. HKCU (현재 사용자) 키를 PowerShell로 바꾸면 Sysmon이 잡긴 하는데, Wazuh agent가 SYSTEM 권한으로 실행돼서 현재 사용자 세션 이벤트를 못 보는 경우가 있다은 아님을 알수 있다.

가설1. Rocky에서 1514포트가 닫혀있음
```bash
docker ps --format "table {{.Names}}\t{{.Ports}}" | grep manager
```

> 📷 `docker ps`: 매니저 컨테이너가 1514-1515/tcp, 514/udp, 55000/tcp를 호스트에 정상 공개.

1514는 열려있음.

Docker 컨테이너는 정상.

가설2. 네트워크 확인

Rocky의 방화벽이 막고 있나?

하지만 이미 현제 진행중인 타 프로젝트에서 현재 환경은 방화벽 설정이 전혀 없음을 확인했다.
```bash
sudo firewall-cmd --list-ports
```

> 📷 `firewall-cmd --list-ports` → FirewallD is not running — 호스트 방화벽은 원인이 아님.

네트워크 연결 자체에 이상이 있는지 확인
```bash
ss -tlnp | grep 1514
```

> 📷 `ss -tlnp | grep 1514` → 0.0.0.0:1514, [::]:1514 LISTEN.

1514 포트 LISTEN 상태 확인

Rocky쪽은 정상.

가설3. Windows에서 RockyIP가 연결되는지?
```powershell
Test-NetConnection -ComputerName 192.168.190.128 -Port 1514
```

> 📷 Windows `Test-NetConnection 192.168.190.128 -Port 1514` → TcpTestSucceeded True(출발지 192.168.190.131).

TcpTestSucceeded: True.

가설4. Agent에서 확인한 에러로그가 재시작시 잠깐 연결이 끊겼던 기록인지 확인
```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 5
```

> 📷 에이전트 ossec.log 최근: FIM 스캔 종료·실시간 FIM 시작, SCA(cis_win10_enterprise) 평가 완료(28초) — 에이전트 정상 동작.

agent 정상 동작

FIM, SCA 다 돌고 연결도 성공함.

Windows 이벤트가 전혀 넘어가지 앟는 이유를 알기 위해 Rocky에서 agent가 실제로 연결된 상태인지 확인.
```powershell
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

> 📷 `agent_control -l`: 001 localhost, 002 yhc, 003 DESKTOP-… 모두 Active.

DESKTOP-5408CBA — Active

Windows agent 연결이 완벽함.

결론 :  이벤트는 전송이 되는데 Run 키 이벤트만 안 잡힌다.

의문점 :  Wazuh가 실제로 어떤 이벤트를 받고 있는지 확인
```bash

docker exec single-node-wazuh.manager-1 grep -a "DESKTOP-5408CBA" /var/ossec/logs/alerts/alerts.json | tail -3

```

> 📷 alerts.json의 DESKTOP-… 이벤트: Security 4624 로그온(60106), System 7040 "Background Intelligent Transfer Service 시작 유형 변경"(61104, level 3) 등 Windows 기본 채널 알림만 있음.

Windows 이벤트는 잘 들어오고 있고 Security 채널, System 채널 이벤트 다 집히는데 Sysmon채널말 확인 안됨.

의문점: Sysmon 채널 이벤트가 전혀 안 오는 건지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "Sysmon" /var/ossec/logs/alerts/alerts.json | tail -3
```

> 📷 alerts.json의 Sysmon 알림 예: 에이전트 SCA가 실행한 SecEdit.exe(EventID 1)와 **92200 \"Scripting file created under Windows Temp or User folder\"(level 6, T1059/T1105)** — Sysmon EventID 11, RuleName T1547_Startup_Folder_LNK, 대상 `…\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk`. Sysmon 채널 이벤트 일부는 알림이 됨.

Sysmon 이벤트는 들어오고 있음을 확인.

- Microsoft-Windows-Sysmon 채널 이벤트 확인
- T1547_Startup_Folder_LNK 룰네임 확인  — 우리 Sysmon config가 작동하고 있음
- ruleName: T1547_Startup_Folder_LNK — 시작 프로그램 폴더 .lnk 감지됨.

Sysmon → Wazuh 파이프라인 전체가 살아있음.

이제 Run 키 이벤트 확인만 남음.
```powershell
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest3" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest4" -Value "C:\temp\evil.exe" -Force
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "100201\|SOCLabTest4\|CurrentVersion.Run" /var/ossec/logs/alerts/alerts.json | tail -5
```

> 📷 SOCLabTest4 = `C:\temp\evil.exe`를 HKCU Run 키에 생성.

> 📷 alerts.json에서 100201·SOCLabTest4·CurrentVersion.Run → 없음.

Run키가 등록이 되었지만 아직 알럿이 없음.

Sysmon 이벤트가 들어온 것 = Event11(파일생성) 이었기 때문에 EvnetdID13 레지스트리 값 쓰기가 실제로 Wazuh에 들어오는지 확인
```bash
docker exec single-node-wazuh.manager-1 grep -a "eventID.*13\|sysmon_event_13" /var/ossec/logs/alerts/alerts.json | tail -3
```

> 📷 alerts.json의 Sysmon EventID 1 알림: `net1 user guest` 실행(Account Discovery), SecEdit.exe가 비정상 위치에서 powershell로 실행됨(92066, level 4, T1059.001) — 둘 다 에이전트 SCA 점검 동작이 만든 이벤트.

Sysmon EventID 1 (프로세스 생성)은 들어오는데 EventID 13은 없음.

가설: Sysmon config에서 EventID 13을 include했는데 Wazuh agent가 재시작되면서 이전 bookmark 위치부터 읽고 있어서 새 이벤트를 못 잡고 있음.

확인 : Windows PowerShell에서 Sysmon이 실제로 EventID 13을 기록하는지
```bash
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 | Where-Object {$_.Id -eq 13} | Select-Object -First 1 TimeCreated, Message | Format-List
```

> 📷 Sysmon EventID 13 최근 1건: RuleName T1543_Service_Registry, lsass.exe의 W32Time SecureTimeLimits 값 변경(정상 노이즈).

T1543_Service_Registry 룰네임으로 EventID 13이 Windows에는 존재.

하지만 경로가 HKLM\System\CurrentControlSet\Services- 서비스 레지스터리이다.

Run키 (CurrentVersion\Run)가 아님.

Sysmon config의 노이즈 제거 규칙에서 lsass.exe를 exclude 안 했는데, 서비스 레지스트리 이벤트는 잡히는 걸 보면 EventID 13 자체는 오고 있음.

다만, Run키 이벤트만 안 오고 있음.

PowerShell로 Run 키를 바꿀 때 어떤 프로세스가 실제 변경하는지 확인
```powershell

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 200 | Where-Object {$_.Id -eq 13 -and $_.Message -like "*CurrentVersion*Run*"} | Select-Object -First 3 TimeCreated, Message | Format-List

```

> 📷 Message에 CurrentVersion\Run이 들어간 EventID 13만 필터: **14:52:00 RuleName T1547_Run_Key_Create, SetValue, Image powershell.exe, TargetObject HKU\<SID>\…\CurrentVersion\Run\SOCLabTest4, Details C:	emp\evil.exe** — Sysmon은 정확히 잡았음.
```powershell
RuleName: T1547_Run_Key_Create
TargetObject: HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOCLabTest4
Details: C:\temp\evil.exe
Image: powershell.exe
```

Sysmon은 정확하게 감지하고 있다. 하지만 경로를 확인하면 — HKU\S-1-5-21-... 이다.  HKCU가 아니고,  HKU (HKEY_USERS) 경로로 기록이됨.

Wazuh 규칙의 정규식이 HKCU 또는 SOFTWARE\Microsoft\Windows\CurrentVersion\Run을 찾는데, 실제 이벤트는 HKU\S-1-5-21-숫자\SOFTWARE\... 형태로 와서 매칭이 안 됨.

그래서 규칙을 수정해야 한다.

정규식 확인
```bash
docker exec single-node-wazuh.manager-1 sed -i 's|SOFTWARE\\\\\\\\(WOW6432Node\\\\\\\\)?Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunOnce?|SOFTWARE\\\\\\\\(WOW6432Node\\\\\\\\)?Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run|g' /var/ossec/etc/rules/local_rules.xml
grep -n "pcre2" /var/ossec/etc/rules/local_rules.xml | head -10

```

> 📷 local_rules.xml의 pcre2 필드 목록: targetObject(29·42·55·68·126줄), targetFilename(84), win.system.message(113), image(129, negate=yes).

29번째 줄과 42번째 줄 내용 확인 - 이곳에 Rule 100200, 100201이 있음.
```bash
sed -n '28,45p' /var/ossec/etc/rules/local_rules.xml
```

> 📷 local_rules.xml 28~45줄: 100200(if_group sysmon_event_12, targetObject `(?i)\SOFTWARE\(WOW6432Node\)?Microsoft\Windows\CurrentVersion\Run`, \"Autorun registry key created or deleted\")와 100201(if_group sysmon_event_13, 같은 경로 + RunOnce?, \"Value written to Run/RunOnce key\", level 12).

정규식이 :
```bash
(?i)\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\RunOnce?
```

실제 이벤트 경로는:
```bash
HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOCLabTest4
```

앞에 HKU\S-1-5-21-숫자\가 붙어있어서 매칭이 안되었음. 그래서 정규식을 수정해야 한다.

100200 규칙도 같이 수정:
```bash

sed -i 's|(?i)\\\\SOFTWARE\\\\(WOW6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run$|(?i).*\\\\SOFTWARE\\\\(WOW6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|g' /var/ossec/etc/rules/local_rules.xml
```

적용 후 확인:
```bash
grep -A2 "100201" /var/ossec/etc/rules/local_rules.xml | head -5
```

> 📷 sed로 두 정규식 앞에 `.*`를 붙여 `HKU\<SID>\SOFTWARE…`처럼 앞부분이 있는 경로도 매칭되게 수정, grep으로 반영 확인.

sed 적용 실패

직접 파일 수정
```python
python3 -c "
content = open('/var/ossec/etc/rules/local_rules.xml').read()
content = content.replace(
    '(?i)\\\\SOFTWARE\\\\(WOW6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce?',
    '(?i).*SOFTWARE.*(WOW6432Node.*)?Microsoft.*Windows.*CurrentVersion.*RunOnce?'
)
content = content.replace(
    '(?i)\\\\SOFTWARE\\\\(WOW6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
    '(?i).*SOFTWARE.*(WOW6432Node.*)?Microsoft.*Windows.*CurrentVersion.*Run'
)
open('/var/ossec/etc/rules/local_rules.xml', 'w').write(content)
print('done')
"
```

done 확인

정규식이 바뀌었는지 확인
```bash
grep -A3 "100201" /var/ossec/etc/rules/local_rules.xml | head -6
```

> 📷 컨테이너에 vi가 없어(`vi: command not found`) python3 한 줄 스크립트로 local_rules.xml의 정규식을 `(?i).*SOFTWARE.*(WOW6432Node.*)?Microsoft.*Windows.*CurrentVersion.*Run(Once)?` 형태로 치환.

> 📷 치환 후 100201의 targetObject 정규식이 `(?i).*\SOFTWARE\(WOW6432Node\)?Microsoft\Windows\CurrentVersion\RunOnce?`로 바뀐 것 확인.

정규식 변경 확인
```bash
(?i).*\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\RunOnce?
```
```bash
exit
docker restart single-node-wazuh.manager-1
```

재시작되면 Windows PowerShell에서 테스트:
```powershell
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest5" -Value "C:\temp\evil.exe" -Force
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "100201\|SOCLabTest5" /var/ossec/logs/alerts/alerts.json | tail -3
```

> 📷 SOCLabTest5 = C:	emp\evil.exe를 HKCU Run 키에 생성.

> 📷 alerts.json에서 100201·SOCLabTest5 → 없음.

실패

EventID 13이 실제로 Wazuh에 들어오는지 확인
```powershell
docker exec single-node-wazuh.manager-1 grep -a "sysmon_event_13\|eventID.*13" /var/ossec/logs/alerts/alerts.json | tail -3
```

> 📷 alerts.json에서 sysmon_event_13/eventID 13 관련 검색: SecEdit.exe(EventID 1)와 60106 로그온 알림만 보이고 EventID 13 알림은 없음.

Sysmon EventID 1은 들어오는데 EventID 13이 없음

가설1.Wazuh가 EventID 13을 필터링하고 있을 가능성

Wazuh manager 설정에서 EventID 13을 명시적으로 수집하는지 확인
```powershell
docker exec single-node-wazuh.manager-1 grep -a "13\|registry\|sysmon" /var/ossec/etc/ossec.conf | head -20
```

> 📷 매니저 ossec.conf에서 13/registry/sysmon 검색 → `queue_size 131072` 한 줄뿐(관련 설정 없음).

manager 설정에 Sysmon 관련 내용이 없지만 EventID13 수집은 Windows agent 설정에서 하는 것이기 때문에 상관이 없다.

Windows 이벤트 뷰어에는 EventID 13이 있는데 Wazuh alerts에는 없음.

Wazuh가 EventID 13을 받긴 하는데 우리 규칙 레벨 미만으로 처리하거나, 아니면 아예 수집을 안 하는 것이다.

기본 Sysmon 규칙이 EventID 13을 어떻게 처리하는지 확인
```powershell
docker exec single-node-wazuh.manager-1 grep -n "sysmon_event_13\|event_13" /var/ossec/ruleset/rules/0330-sysmon_rules.xml | head -10
```

> 📷 0330-sysmon_rules.xml 98줄에 `group sysmon_event_13`.

98번 줄에 있음 - 규칙 전체 확인
```powershell
docker exec single-node-wazuh.manager-1 sed -n '90,105p' /var/ossec/ruleset/rules/0330-sysmon_rules.xml
```

> 📷 0330의 185011(if_sid 18101, `match Microsoft-Windows-Sysmon/Operational: INFORMATION(13)`)·185012(Event 14) — 구형 텍스트 이벤트 로그 형식을 전제로 한 룰.

분제 발견
```powershell
<rule id="185011" level="0">
    <match>Microsoft-Windows-Sysmon/Operational: INFORMATION(13)</match>
```

level="0” - Wazuh에서 level 0은 "무시(suppress)”EventID 13이 들어와도 Wazuh가 의도적으로 무시하고 있음

Rule 100201이 if_group>sysmon_event_13을 기다리는데, 부모 규칙이 level 0이라 자식 규칙까지 도달을 못 한것이다.
```bash
docker exec -it single-node-wazuh.manager-1 python3 -c "
content = open('/var/ossec/etc/rules/local_rules.xml').read()
content = content.replace(
    '<if_group>sysmon_event_13</if_group>',
    '<if_sid>185011</if_sid>'
)
open('/var/ossec/etc/rules/local_rules.xml', 'w').write(content)
print('done')
"
```

> 📷 python으로 local_rules.xml의 `if_group sysmon_event_13`을 `if_sid 185011`로 치환("done").
```bash
docker restart single-node-wazuh.manager-1
```
```powershell
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest6" -Value "C:\temp\evil.exe" -Force
```
```bash
sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "100201\|SOCLabTest6" /var/ossec/logs/alerts/alerts.json | tail -3
```

> 📷 SOCLabTest6 = C:	emp\evil.exe를 HKCU Run 키에 생성.

if_sid 방식 실패

level 0 규칙을 우회하는 대신, match 조건으로 직접 잡기 :
```bash
docker exec -it single-node-wazuh.manager-1 python3 -c "
content = open('/var/ossec/etc/rules/local_rules.xml').read()
content = content.replace(
    '<if_sid>185011</if_sid>',
    '<if_sid>18101</if_sid>\n    <match>INFORMATION(13)</match>'
)
open('/var/ossec/etc/rules/local_rules.xml', 'w').write(content)
print('done')
"

```
```bash
docker restart single-node-wazuh.manager-1
```
```powershell
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest7" -Value "C:\temp\evil.exe" -Force
```
```bash
sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "100201\|SOCLabTest7" /var/ossec/logs/alerts/alerts.json | tail -3
```

실패

#### <중간정리>

완성

- Sysmon config 적용 ✅
- Wazuh 규칙 파일 컨테이너에 배포 ✅
- Windows → Rocky 네트워크 연결 ✅
- Wazuh agent Active 확인 ✅
- Sysmon이 EventID 13 감지하는 것 확인 ✅

막힌 지점

Wazuh 기본 규칙 185011이 level="0"으로 EventID 13을 suppress하고 있어서 우리 커스텀 규칙까지 도달을 못 하고 있음

0860-sysmon_id_13.xml 파일을 보면 이미 Wazuh가 EventID 13을 별도로 처리하는 규칙셋이 존재한다.

그걸 기반으로 커스텀 규칙 다시 설계.

#### 다음 단계

0860-sysmon_id_13.xml확인
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

Rule 92300
```bash
<rule id="92300" level="0">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">
        (?i)SOFTWARE\\(WOW6432NODE\\M|M)ICROSOFT\\WINDOW(S|S NT)\\CURRENTVERSION\\RUN...
```

Wazuh가 EventID 13을 별도로 처리하는 규칙셋을 확인함

하지만, level="0"이라 suppress돼서 알럿이 안 나옴.

정규식이 HKU\S-1-5-...\SOFTWARE\... 경로를 못 잡는 것도 같은 문제임

그래서 level만 올려서 92300정규식을 그대로 사용하여 규칙을 만듦.
```bash

docker exec -it single-node-wazuh.manager-1 python3 -c "
content = open('/var/ossec/etc/rules/local_rules.xml').read()

new_rule = '''
  <!-- T1547 Run Key - level 0 override -->
  <rule id="100210" level="12" overwrite="yes">
    <if_group>sysmon_event_13</if_group>
    <field name=\"win.eventdata.targetObject\" type=\"pcre2\">(?i)SOFTWARE\\\\\\\\(WOW6432NODE\\\\\\\\M|M)ICROSOFT\\\\\\\\WINDOW(S|S NT)\\\\\\\\CURRENTVERSION\\\\\\\\RUN</field>
    <description>T1547 - Run key modified | Image: \$(win.eventdata.image) | Value: \$(win.eventdata.details)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
'''

content = new_rule + content
open('/var/ossec/etc/rules/local_rules.xml', 'w').write(content)
print('done')
"

```

재시작, 테스트
```bash
docker restart single-node-wazuh.manager-1
```
```powershell
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest8" -Value "C:\temp\evil.exe" -Force
```
```bash
sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "100210\|SOCLabTest8" /var/ossec/logs/alerts/alerts.json | tail -3
```

확인 실패

가설 :sysmon_event_13 그룹 자체가 실제로 발동되는지 확인.- 92300이 level 0이라도 그룹은 태깅돼야 한다. 혹시 전 단계인 18101 규칙을 못 타는 건 아닐지 확인
```bash
docker exec single-node-wazuh.manager-1 grep -a "185011\|18101\|sysmon_event_13" /var/ossec/logs/alerts/alerts.json | tail -5

```

alerts.json에 EventID 13 관련 내용이 존재하지 않음. level 0이라 suppress되고 있음.

확인 : 다른 해결책을 찾기 위해서 0595-win-sysmon_rules.xml에 EventID 13 처리하는 부분이 있는데 그 파일을 확인
```bash

docker exec single-node-wazuh.manager-1 grep -n "13\|registry" /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml | head -20

```

Rule 61613 — 이게 진짜 EventID 13 처리 규칙
```bash
rule id="61613" level="0"
field name="win.system.eventID">^13$
group>sysmon_event_13

```

level="0"이라 suppress되고 있다. 그래서 부모 규칙확인을 위해 118번 줄 확인
```bash

docker exec single-node-wazuh.manager-1 sed -n '110,142p' /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml

```

결과
```bash
[yhc@localhost ~]$ docker restart single-node-wazuh.manager-1
single-node-wazuh.manager-1
[yhc@localhost ~]$ sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "100210\|SOCLabTest8" /var/ossec/logs/alerts/alerts.json | tail -3
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 grep -a "185011\|18101\|sysmon_event_13" /var/ossec/logs/alerts/alerts.json | tail -5
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 grep -n "13\|registry" /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml | head -20
27:    <group>gpg13_4.12,</group>
35:    <group>system_error,gpg13_4.3,gdpr_IV_35.7.d,</group>
118:  <rule id="61613" level="0">
136:    <field name="win.system.eventID">^13$</field>
137:    <description>Sysmon - Event 13: RegistryEvent $(win.eventdata.eventType) on $(win.eventdata.targetObject) by $(win.eventdata.image)</description>
139:    <group>sysmon_event_13,</group>
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 sed -n '110,142p' /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
  <rule id="61612" level="0">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID">^10$</field>
    <description>Sysmon - Event 10: $(win.eventdata.targetImage) process accessed by $(win.eventdata.sourceImage)</description>
    <options>no_full_log</options>
    <group>sysmon_event_10,</group>
  </rule>
  <rule id="61613" level="0">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID">^11$</field>
    <description>Sysmon - Event 11: FileCreate by $(win.eventdata.image)</description>
    <options>no_full_log</options>
    <group>sysmon_event_11,</group>
  </rule>
  <rule id="61614" level="0">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID">^12$</field>
    <description>Sysmon - Event 12: RegistryEvent $(win.eventdata.eventType) on $(win.eventdata.targetObject) by $(win.eventdata.image)</description>
    <options>no_full_log</options>
    <group>sysmon_event_12,</group>
  </rule>
  <rule id="61615" level="0">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID">^13$</field>
    <description>Sysmon - Event 13: RegistryEvent $(win.eventdata.eventType) on $(win.eventdata.targetObject) by $(win.eventdata.image)</description>
    <options>no_full_log</options>
    <group>sysmon_event_13,</group>
  </rule>
  <rule id="61616" level="0">
```

Rule 61615가 진짜임. if_sid>61600을 부모로 쓰고 있음.

61615를 부모로 해서 우리 규칙을 만들어야 한다.
```bash
docker exec -it single-node-wazuh.manager-1 python3 -c "
content = open('/var/ossec/etc/rules/local_rules.xml').read()
new_rule = '''<group name=\"persistence,sysmon,windows,\">
  <rule id=\"100220\" level=\"12\">
    <if_sid>61615</if_sid>
    <field name=\"win.eventdata.targetObject\" type=\"pcre2\">(?i)SOFTWARE\\\\\\\\(WOW6432NODE\\\\\\\\M|M)ICROSOFT\\\\\\\\WINDOW(S|S NT)\\\\\\\\CURRENTVERSION\\\\\\\\RUN</field>
    <description>T1547 - Run key modified | Image: \$(win.eventdata.image) | Value: \$(win.eventdata.details)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
'''
content = new_rule + content
open('/var/ossec/etc/rules/local_rules.xml', 'w').write(content)
print('done')
"

```
```bash
docker restart single-node-wazuh.manager-1
```
```powershell
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest9" -Value "C:\temp\evil.exe" -Force
```
```powershell
sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "100220\|SOCLabTest9" /var/ossec/logs/alerts/alerts.json | tail -3
```

확인 실패

새로운 가설 :

61615가 level="0"이고 options>no_full_log가 문제일 수도 있다.  level 0 규칙을 부모로 쓰면 자식 규칙이 발동은 되는데, 실제로 EventID 13이 61615를 타고 있는지 확인이 안됨.

EventID 13이 Wazuh에 실제로 수신되는지 raw 로그에서  확인해야 한다.
```bash
docker exec single-node-wazuh.manager-1 grep -a "eventID.*13\|\"13\"" /var/ossec/logs/archives/archives.json 2>/dev/null | grep -i sysmon | tail -3
```

archives.json이 비어있다.

archives 로깅이 꺼져있음.

켜기.
```bash
docker exec -it single-node-wazuh.manager-1 python3 -c "
content = open('/var/ossec/etc/ossec.conf').read()
content = content.replace(
    '<logall>no</logall>',
    '<logall>yes</logall>'
)
content = content.replace(
    '<logall_json>no</logall_json>',
    '<logall_json>yes</logall_json>'
)
open('/var/ossec/etc/ossec.conf', 'w').write(content)
print('done')
"
```

재시작하고 이번엔 archives에서 EventID 13이 실제로 수신되는지 확인
```bash
docker restart single-node-wazuh.manager-1
```
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest10" -Value "C:\temp\evil.exe" -Force
```
```bash
sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "Sysmon" /var/ossec/logs/archives/archives.json 2>/dev/null | tail -3
```

archives.json 자체가 생성이 안 되고 있음 .

logall 설정이 적용이 안 된 것임

설정확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "logall" /var/ossec/etc/ossec.conf
```

Python replace가 적용되지 않음.
```bash
docker exec single-node-wazuh.manager-1 sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/g; s/<logall_json>no<\/logall_json>/<logall_json>yes<\/logall_json>/g' /var/ossec/etc/ossec.conf
```

확인
```bash
docker exec single-node-wazuh.manager-1 grep -a "logall" /var/ossec/etc/ossec.conf
```

yes
```bash
docker restart single-node-wazuh.manager-1
```
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabTest11" -Value "C:\temp\evil.exe" -Force
```
```bash
sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "eventID.*13\|INFORMATION(13)" /var/ossec/logs/archives/archives.json 2>/dev/null | tail -3
```

archives.json이 여전히 없음. 파일 자체가 생성되었는지 확인:
```bash
docker exec single-node-wazuh.manager-1 ls -la /var/ossec/logs/archives/
```

archives.json 이 없음.

archives.log만 있고 크기도 0이다.

다른 시도 ,  archives 대신 alerts에서 직접 EventID 13이 오는지 확인
```bash
Wazuh logtest로 직접 테스트
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest

```

프롬프트 뜨면 아래 내용 붙이기
```bash
Oct 24 10:00:00 WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(13): Sysmon: SYSTEM: NT AUTHORITY: DESKTOP-5408CBA: Registry value set: RuleName: T1547_Run_Key_Set EventType: SetValue UtcTime: 2024-10-24 01:00:00.000 Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe TargetObject: HKU\S-1-5-21-1234\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOCLabTest Details: C:\temp\evil.exe
```

매칭 rule 확인

Wazuh-logtest error when connecting with wazuh-analysisd — analysisd 데몬이 완전히 덜 뜸
```bash
sleep 20 && docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest

```

analysisd가 계속 에러

manager가 제대로 안 떴다.

상태 확인
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
```

전부 not running..

규칙 파일에 문법 오류가 있어서 manager가 시작을 못 했음.

에그 로그 확인
```bash
docker exec single-node-wazuh.manager-1 tail -20 /var/ossec/logs/ossec.log
```
```bash
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
wazuh-clusterd not running...
wazuh-modulesd: Process 795 not used by Wazuh, removing...
wazuh-modulesd not running...
wazuh-monitord not running...
wazuh-logcollector not running...
wazuh-remoted not running...
wazuh-syscheckd not running...
wazuh-analysisd not running...
wazuh-maild not running...
wazuh-execd not running...
wazuh-db not running...
wazuh-authd not running...
wazuh-agentlessd not running...
wazuh-integratord not running...
wazuh-dbd not running...
wazuh-csyslogd not running...
wazuh-apid: Process 401 not used by Wazuh, removing...
wazuh-apid not running...
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 tail -20 /var/ossec/logs/ossec.log
2026/04/24 06:20:29 wazuh-syscheckd: INFO: (1756): Shutdown received. Releasing resources.
2026/04/24 06:20:29 wazuh-monitord: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
2026/04/24 06:20:29 wazuh-logcollector: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
2026/04/24 06:20:29 wazuh-syscheckd: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
2026/04/24 06:20:30 wazuh-db: INFO: Graceful process shutdown.
2026/04/24 06:20:30 wazuh-authd: INFO: Exiting...
2026/04/24 06:20:40 wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/local_rules.xml' due to [(13)-(Permission denied)].
2026/04/24 06:20:40 wazuh-modulesd:router: INFO: Loaded router module.
2026/04/24 06:20:40 wazuh-modulesd:content_manager: INFO: Loaded content_manager module.
2026/04/24 06:20:41 wazuh-testrule: ERROR: (1226): Error reading XML file 'etc/rules/local_rules.xml': XMLERR: Attribute 'id' not followed by a " or '. (line 2).
2026/04/24 06:20:41 wazuh-testrule: CRITICAL: (1220): Error loading the rules: 'etc/rules/local_rules.xml'.
2026/04/24 06:25:50 wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/local_rules.xml' due to [(13)-(Permission denied)].
2026/04/24 06:25:50 wazuh-modulesd:router: INFO: Loaded router module.
2026/04/24 06:25:50 wazuh-modulesd:content_manager: INFO: Loaded content_manager module.
2026/04/24 06:28:21 wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/local_rules.xml' due to [(13)-(Permission denied)].
2026/04/24 06:28:21 wazuh-modulesd:router: INFO: Loaded router module.
2026/04/24 06:28:21 wazuh-modulesd:content_manager: INFO: Loaded content_manager module.
2026/04/24 06:32:27 wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/local_rules.xml' due to [(13)-(Permission denied)].
2026/04/24 06:32:27 wazuh-modulesd:router: INFO: Loaded router module.
2026/04/24 06:32:27 wazuh-modulesd:content_manager: INFO: Loaded content_manager module.
```

두 가지 문제 확인

- Permission denied — 파일 권한 문제
- Attribute 'id' not followed by a " or ' — XML 문법 오류

권한 수정
```bash
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/rules/local_rules.xml
```

망가진 local_rules.xml을 깨끗하게 다시 작성
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << '"'"'EOF'"'"'
<group name="persistence,sysmon,windows,">
  <rule id="100220" level="12">
    <if_sid>61615</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion.Run</field>
    <description>T1547 - Run key modified by $(win.eventdata.image)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
EOF'
```

확인
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```

1-4. Windows 이벤트로그 7045 수집 설정 확인

Rocky Linux의 /var/ossec/etc/ossec.conf에 아래 항목이 있는지 확인:
```xml
<localfile>
  <log_format>eventchannel</log_format>
  <location>System</location>
</localfile>
```

확인
```bash
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 tail -20 /var/ossec/logs/ossec.log
2026/04/24 06:20:29 wazuh-syscheckd: INFO: (1756): Shutdown received. Releasing resources.
2026/04/24 06:20:29 wazuh-monitord: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
2026/04/24 06:20:29 wazuh-logcollector: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
2026/04/24 06:20:29 wazuh-syscheckd: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
2026/04/24 06:20:30 wazuh-db: INFO: Graceful process shutdown.
2026/04/24 06:20:30 wazuh-authd: INFO: Exiting...
2026/04/24 06:20:40 wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/local_rules.xml' due to [(13)-(Permission denied)].
2026/04/24 06:20:40 wazuh-modulesd:router: INFO: Loaded router module.
2026/04/24 06:20:40 wazuh-modulesd:content_manager: INFO: Loaded content_manager module.
2026/04/24 06:20:41 wazuh-testrule: ERROR: (1226): Error reading XML file 'etc/rules/local_rules.xml': XMLERR: Attribute 'id' not followed by a " or '. (line 2).
2026/04/24 06:20:41 wazuh-testrule: CRITICAL: (1220): Error loading the rules: 'etc/rules/local_rules.xml'.
2026/04/24 06:25:50 wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/local_rules.xml' due to [(13)-(Permission denied)].
2026/04/24 06:25:50 wazuh-modulesd:router: INFO: Loaded router module.
2026/04/24 06:25:50 wazuh-modulesd:content_manager: INFO: Loaded content_manager module.
2026/04/24 06:28:21 wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/local_rules.xml' due to [(13)-(Permission denied)].
2026/04/24 06:28:21 wazuh-modulesd:router: INFO: Loaded router module.
2026/04/24 06:28:21 wazuh-modulesd:content_manager: INFO: Loaded content_manager module.
2026/04/24 06:32:27 wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/local_rules.xml' due to [(13)-(Permission denied)].
2026/04/24 06:32:27 wazuh-modulesd:router: INFO: Loaded router module.
2026/04/24 06:32:27 wazuh-modulesd:content_manager: INFO: Loaded content_manager module.
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/rules/local_rules.xml
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << '"'"'EOF'"'"'
<group name="persistence,sysmon,windows,">
  <rule id="100220" level="12">
    <if_sid>61615</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion.Run</field>
    <description>T1547 - Run key modified by $(win.eventdata.image)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
EOF'
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
<group name="persistence,sysmon,windows,">
  <rule id="100220" level="12">
    <if_sid>61615</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion.Run</field>
    <description>T1547 - Run key modified by $(win.eventdata.image)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
[yhc@localhost ~]$
```

XML 적용 확인. 재시작
```bash
docker restart single-node-wazuh.manager-1 && sleep 20 && docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status | grep analysisd
```

wazuh-analysisd is running 확인

manager 정상 기동!
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabFinal" -Value "C:\temp\evil.exe" -Force
```
```bash
sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "100220\|SOCLabFinal\|T1547" /var/ossec/logs/alerts/alerts.json | tail -5
```

T1547 알럿은 있음. 하지만 T1547_Startup_Folder_LNK 시작 프로그램 폴더 .lnk 이벤트일 뿐 아직 Rule 100220은 없음.

우선 확실히 확인하기 위해 Run키 이벤트만 필터링
```bash
docker exec single-node-wazuh.manager-1 grep -a "100220\|SOCLabFinal" /var/ossec/logs/alerts/alerts.json | tail -5
```

Run키가 아직 잡히고 있지 않음을 확인

longest규칙이 올바른지 확인
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

프롬프터에 아래를 입력
```bash
Oct 24 10:00:00 WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(13): Sysmon: SYSTEM: NT AUTHORITY: DESKTOP-5408CBA: Registry value set: RuleName: T1547_Run_Key_Set EventType: SetValue UtcTime: 2024-10-24 01:00:00.000 Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe TargetObject: HKU\S-1-5-21-1234\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOCLabFinal Details: C:\temp\evil.exe
```

그리고 매칭되는 rule확인

- Phase3에서 Rule 185011ㄹ 매칭된 후 종료됨. 하지만 level:'0' 이라서 Rule 100220까지 도달못하곡 있음
- `goups: ['sysmon' , 'sysmon_event_13'] - 그룹 태킹은 성공 그러면, if_sid>61615 가 아니라 if_group>sysmon_event_13 으로 바뀌어야 한다.
- 문젠느 0330-sysmon_rule,.xml 의 185011이 0595의 61615보다 먼저 매칭되는것. 원래는 여기서 멈추는 것이 아니라 child ruleㅇ 발동돼야하는데 안되는 이유는 우리 규칙은 61615 를 부모로 하고 있는데 실제로 매칭된 건 185011 이라서 이다.
- Wazuh rule chaining은 트리 구조이다. 하나의 이벤트가 여러 규칙에 동시에 매치이 되는 것이 아니라 먼저 매치된 규칙이 parent가 되고 if_sid 는 그 parent를 보고 child발동 여부를 결저함.
```bash
수정전
Event 13 (Registry value set)
  → 185011 매칭됨 (sysmon_rules.xml이 먼저 로드)
  → 0595의 61615는 아예 평가 안 됨 (185011이 이미 parent 확정)
```
```bash
수정후
Event 13
  → 185011 매칭됨
  → if_sid: 185011 → 100220 평가 → CurrentVersion\\Run 있으면 발동 ✓
```

185011이 매칭됐을때 추가로 100220도 발동시키는 구조.

수정
```bash
exit
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << '"'"'EOF'"'"'
<group name="persistence,sysmon,windows,">
  <rule id="100220" level="12">
    <if_sid>185011</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion.Run</field>
    <description>T1547 - Run key modified by $(win.eventdata.image)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
EOF'
```

재시작 후 longest 돌리기
```bash
docker restart single-node-wazuh.manager-1 && sleep 20
```
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```
```bash
Oct 24 10:00:00 WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(13): Sysmon: SYSTEM: NT AUTHORITY: DESKTOP-5408CBA: Registry value set: RuleName: T1547_Run_Key_Set EventType: SetValue UtcTime: 2024-10-24 01:00:00.000 Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe TargetObject: HKU\S-1-5-21-1234\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOCLabFinal Details: C:\temp\evil.exe
```

결과 : 185011 에서 멈춤. 즉, if_sid>185011 로 했는데 child rule 이 안올라오고 있음.

원인: Wazuh의 동작방식 떄문이다. level0규칙은 child rule 체이니을 막음. if_sid 로 부모를 지정해도 부모가 level0이면 child가 발동이 안됨.

해결책 : 185011을 overwrite해서 level을 올리기
```bash
exit
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << '"'"'EOF'"'"'
<group name="sysmon,windows,">
  <rule id="185011" level="3" overwrite="yes">
    <if_sid>18101</if_sid>
    <match>Microsoft-Windows-Sysmon/Operational: INFORMATION(13)</match>
    <description>Sysmon - Event 13</description>
    <group>sysmon_event_13,</group>
  </rule>

  <rule id="100220" level="12">
    <if_sid>185011</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion.Run</field>
    <description>T1547 - Run key modified by $(win.eventdata.image)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
EOF'
```
```bash
docker restart single-node-wazuh.manager-1 && sleep 20
```

XML 입력 성공
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```
```bash
Oct 24 10:00:00 WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(13): Sysmon: SYSTEM: NT AUTHORITY: DESKTOP-5408CBA: Registry value set: RuleName: T1547_Run_Key_Set EventType: SetValue UtcTime: 2024-10-24 01:00:00.000 Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe TargetObject: HKU\S-1-5-21-1234\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOCLabFinal Details: C:\temp\evil.exe
```

결과
```bash
**Phase 1: Completed pre-decoding.
	full event: 'Oct 24 10:00:00 WinEvtLog: Microsoft-Windows-Sysmon/Operational: INFORMATION(13): Sysmon: SYSTEM: NT AUTHORITY: DESKTOP-5408CBA: Registry value set: RuleName: T1547_Run_Key_Set EventType: SetValue UtcTime: 2024-10-24 01:00:00.000 Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe TargetObject: HKU\S-1-5-21-1234\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOCLabFinal Details: C:\temp\evil.exe'
	timestamp: 'Oct 24 10:00:00'
	hostname: 'WinEvtLog:'
	program_name: 'WinEvtLog'
**Phase 2: Completed decoding.
	name: 'windows'
	parent: 'windows'
	dstuser: 'SYSTEM'
	extra_data: 'Sysmon'
	id: '13'
	status: 'INFORMATION'
	system_name: 'DESKTOP-5408CBA'
	type: 'Microsoft-Windows-Sysmon/Operational'
**Phase 3: Completed filtering (rules).
	id: '185011'
	level: '3'
	description: 'Sysmon - Event 13'
	groups: '['sysmon', 'windows', 'sysmon_event_13']'
	firedtimes: '1'
	mail: 'False'
**Alert to be generated.-
```

level:'3' 로 올라왔음

Alert to be generted 확인

아직 100220이 안보임.

185011은 잡히는데 100220이 안 올라오는 이유는 longest가 이 형식의 로그를 win.eventdata 팔드로 파싱을 못하기 때문이다.

실제 Windows agent가 보내는 JSON 형식이 달라서 win.eventdata.targetObject 필드 매칭이 안됨.

longest는 여기서 한계임.

그래서 실제 Window이벤트에서 테스트를 한다.
```powershell
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabFinal2" -Value "C:\temp\evil.exe" -Force
```
```bash
sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "100220\|SOCLabFinal2\|T1547.*Run" /var/ossec/logs/alerts/alerts.json | tail -5
```

아무런 값이 잡히지 않으므로 실제 이벤트의 형식으로 Wazuh에 들어오는지 직접 확인.

alerts.jason에서 최근의 이벤트를 하나 확인해보기.
```bash
 docker exec single-node-wazuh.manager-1 grep -a "Sysmon" /var/ossec/logs/alerts/alerts.json | tail -1 | python3 -m json.tool 2>/dev/null | grep -A2 "eventdata\|targetObject\|eventID"
```

EventID11 (파일생성) 은 있지만 아직 EventID13이 아직 alerts에 없음.

EventID 13이 실제로 alerts에 들어오는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a '"eventID": "13"' /var/ossec/logs/alerts/alerts.json | tail -3
```

EventID 13이 alerts에 없음, 185011을 overwrite해서 level14으로 올렸지만 아직 확인이 안되고 있음.

manager가 overwrite 규칙을 제대로 로드했는지 확인 :
```bash
docker exec single-node-wazuh.manager-1 grep -a "185011\|overwrite" /var/ossec/logs/ossec.log | tail -10
```

아무런 값이 없음.

manager가 overwriter 규칙을 로드했다는 로그가 없음.

원인1. XML파일 자체가 안들어갔을 가능성.
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```

원인2.  파일은 들어갔는데 문법 오류로 로드 실패
```bash
docker exec single-node-wazuh.manager-1 grep -a "error\|Error\|invalid" /var/ossec/logs/ossec.log | grep -i "rule\|xml" | tail -10
```

XML 파일 자체는 들어갔는데 line 2에 XML 파싱 오류 발견.
```bash
XMLERR: Attribute 'id' not followed by a " or '. (line 2)
```

<group name="sysmon,windows,"> 바로 다음 줄인 <rule id="185011"...>에서 따옴표 문자가 깨짐.

heredoc으로 넣을 때 스마트 쿼트(")가 섞여 들어간 전형적인 증상

파일 통째로 덮어쓰기.
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << '\''ENDOFFILE'\''
<group name="sysmon,windows,">
  <rule id="185011" level="3" overwrite="yes">
    <if_sid>18101</if_sid>
    <match>Microsoft-Windows-Sysmon/Operational: INFORMATION(13)</match>
    <description>Sysmon - Event 13</description>
    <group>sysmon_event_13,</group>
  </rule>
  <rule id="100220" level="12">
    <if_sid>185011</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion\.Run</field>
    <description>T1547 - Run key modified by $(win.eventdata.image)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
ENDOFFILE'
```
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest -t 2>&1 | grep -i "error\|ok"
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "error\|Error" /var/ossec/logs/ossec.log | grep "local_rules" | tail -5
```
```bash
docker exec single-node-wazuh.manager-1 kill -HUP $(docker exec single-node-wazuh.manager-1 pgrep -f wazuh-analysisd)
```
```bash
sleep 10 && docker exec single-node-wazuh.manager-1 grep -a "185011\|overwrite\|100220" /var/ossec/logs/ossec.log | tail -10
```

- ossec.log의 에러는 06:20:41 — 이전 broken 파일 때 것이야. 새로 쓴 파일 이후 에러인지 확인 필요
- kill 명령이 컨테이너에 없어 — bash로 감싸야 해

새 파일 이후 에러 있는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "local_rules" /var/ossec/logs/ossec.log | tail -5
```

리로드는
```bash
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep -f wazuh-analysisd)'
```
```bash
sleep 10 && docker exec single-node-wazuh.manager-1 grep -a "local_rules\|185011\|overwrite" /var/ossec/logs/ossec.log | tail -10
```

Permission denied 발견

cat > 로 덮어쓸 때 root 소유로 생성됐는데 wazuh-analysisd가 읽을 수 없음

수정
```bash
docker exec single-node-wazuh.manager-1 bash -c 'chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml && chmod 660 /var/ossec/etc/rules/local_rules.xml'
```

확인:
```bash
docker exec single-node-wazuh.manager-1 ls -la /var/ossec/etc/rules/local_rules.xml
```
```bash
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep -f wazuh-analysisd)'
```
```bash
sleep 10 && docker exec single-node-wazuh.manager-1 grep -a "local_rules\|185011" /var/ossec/logs/ossec.log | tail -5
```

ossec.log가 아직 이전 에러만 보아고 HUP후 새 로그가 나오지 않고 있음.

ls -la 결과 상단에  wazuh 로 바뀐 것은 확인.  권한은 고쳐짐.

문제는 Hub이 실제로 적용이되었는지 확인.

restart
```bash
docker restart single-node-wazuh.manager-1
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "local_rules\|185011\|Loaded rules" /var/ossec/logs/ossec.log | tail -10
```

권한은 rw-rw----. 1 wazuh wazuh로 정상인데 ossec.log가 아직 06:32까지밖에 없음.

다시 restart..

local_rules 관련 에러가 없음.  정상 로드 확인.

"Loaded content-manager module” - manager가 올라온 것을 확인.
```bash
# Windows PowerShell에서
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabFinal3" -Value "C:\temp\evil.exe" -Force
```
```bash
sleep 30 && docker exec single-node-wazuh.manager-1 grep -a "100220\|T1547\|SOCLabFinal3" /var/ossec/logs/alerts/alerts.json | tail -5
```

alerts.json에 이벤트는 들어오는데 rule 92200 (EventID 11, 파일 생성)

여전히. 100220이 안보임.

두가지 확인

1. EventID 13이 실제로 들어왔는지
```bash
docker exec single-node-wazuh.manager-1 grep -a '"eventID":"13"' /var/ossec/logs/alerts/alerts.json | tail -3
```

2, Run key PowerShell 명령이 실제로 실행됐는지 — Windows에서 확인:
```bash
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabFinal3" 2>$null
```

EventID 13이 alerts에 없으면 Sysmon config에서 Registry 이벤트 수집이 꺼져 있다는 의미이므로 sysmonconfig.xml에서 EventID 13 include 여부 확인할 필요가 있다.

Sysmon config 확인:
```bash
# Windows에서
C:\Windows\sysmon64.exe -c 2>&1 | Select-String "RegistryEvent\|EventID 13\|include\|exclude" | head -20
```

또는 config 파일 직접:
```bash
Get-Content C:\Windows\sysmonconfig.xml | Select-String -Pattern "RegistryEvent" -Context 2,2
```

RegistryEvent 섹션이 없거나 onmatch="include"인데 rule이 없으면 수집 안함.
```bash
System Monitor v15.20 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2026 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com
Current configuration:
 - Service name:                  sysmon64
 - Driver name:                   SysmonDrv
 - Config file:                   C:\Users\yhc\Desktop\sysmon_persistence.xml
 - Config hash:                   SHA256=C431817758F8981EAC86D81AA08CEA760A974B6E06E01E7C1695320DF8BE8D03
 - HashingAlgorithms:             SHA256
 - Network connection:            disabled
 - Archive Directory:             -
 - Image loading:                 disabled
 - CRL checking:                  enabled
 - DNS lookup:                    enabled
Rule configuration (version 4.90):
 - FileCreate                         onmatch: include   combine rules using 'Or'
        Compound Rule T1547_Startup_Folder_LNK   combine using Or
            TargetFilename                 filter: contains     value: 'Microsoft\Windows\Start Menu\Programs\Startup'
            TargetFilename                 filter: end with     value: '.lnk'
 - RegistryEvent                      onmatch: include   combine rules using 'Or'
        Compound Rule T1547_Run_Key_Create   combine using Or
            TargetObject                   filter: contains     value: 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            TargetObject                   filter: contains     value: 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            TargetObject                   filter: contains     value: 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        Compound Rule T1547_Run_Key_Set   combine using Or
            TargetObject                   filter: contains     value: 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            TargetObject                   filter: contains     value: 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        Compound Rule T1547_Startup_Registry   combine using Or
            TargetObject                   filter: contains     value: 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            TargetObject                   filter: contains     value: 'SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute'
            TargetObject                   filter: contains     value: 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
            TargetObject                   filter: contains     value: 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
 - RegistryEvent                      onmatch: exclude   combine rules using 'Or'
        Compound Rule Exclude_System_Processes   combine using Or
            Image                          filter: is           value: 'C:\Windows\System32\svchost.exe'
            Image                          filter: is           value: 'C:\Windows\System32\services.exe'
            Image                          filter: is           value: 'C:\Windows\regedit.exe'
            Image                          filter: contains     value: 'MsMpEng.exe'
            Image                          filter: contains     value: 'msiexec.exe'
```

EventID 13이 alerts에 없다는 건 Sysmon은 캡처하는데 Wazuh agent가 전송을 안 하거나, manager가 level 0으로 드롭하고 있다는 의미.

archives.json 확인 — alerts보다 낮은 level 이벤트도 여기로 들어옴.
```bash
docker exec single-node-wazuh.manager-1 grep -a '"eventID":"13"' /var/ossec/logs/archives/archives.json | tail -3
```

archives가 비어있으면 agent 전송 자체가 문제.

Windows agent 설정 확인:
```bash
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String -Pattern "Microsoft-Windows-Sysmon" -Context 3,3
```

2가지 문제 발견:

1. archives.json 없음 — manager에서 archiving이 꺼져 있음
1. agent ossec.conf는 정상 — Microsoft-Windows-Sysmon/Operational eventchannel로 수집 설정 되어있음.

agent 설정은 맞는엗 EventID 13이 안오고 있음 .

angent가 실제로 뭘 보내고 있는지 확인.
```bash
# Windows에서 - agent log 확인
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" | Select-String "Sysmon\|eventID\|error" | Select-Object -Last 20
```

manager에서 archives 활성화해서 드롭되는 이벤트확인:
```bash
docker exec single-node-wazuh.manager-1 bash -c 'grep -A2 "logall" /var/ossec/etc/ossec.conf | head -10'
```

logall_json>no — archives가 꺼져 있음.

켜서 드롭되는 이벤트까지 전부 확인
```bash

docker exec single-node-wazuh.manager-1 bash -c "sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/' /var/ossec/etc/ossec.conf && sed -i 's/<logall_json>no<\/logall_json>/<logall_json>yes<\/logall_json>/' /var/ossec/etc/ossec.conf"

```
```bash
docker exec single-node-wazuh.manager-1 grep "logall" /var/ossec/etc/ossec.conf
```

둘 다 yes면 restart:
```bash
docker restart single-node-wazuh.manager-1 && sleep 30
```

그다음 Windows에서 Registry 키 다시 쓰고:
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabFinal4" -Value "C:\temp\evil.exe" -Force
```
```bash
docker exec single-node-wazuh.manager-1 grep -a '"eventID":"13"' /var/ossec/logs/archives/archives.json | tail -3
```

archives.json 자체가 아직 없다. restart 후 파일이 생성됐는지 확인:
```bash
ls -la /var/ossec/logs/archives/ 2>/dev/null || docker exec single-node-wazuh.manager-1 ls -la /var/ossec/logs/archives/
```

그리고 logall 설정이 실제로 반영됐는지:
```bash
docker exec single-node-wazuh.manager-1 grep "logall" /var/ossec/etc/ossec.conf
```

여전히 둘다 no → sed 명령이 실패한 것이기 때문에 직접 수정:
```bash
docker exec single-node-wazuh.manager-1 bash -c "
python3 -c \"
import re
with open('/var/ossec/etc/ossec.conf', 'r') as f:
    content = f.read()
content = content.replace('<logall>no</logall>', '<logall>yes</logall>')
content = content.replace('<logall_json>no</logall_json>', '<logall_json>yes</logall_json>')
with open('/var/ossec/etc/ossec.conf', 'w') as f:
    f.write(content)
print('done')
\""
```

확인 restart
```bash
docker exec single-node-wazuh.manager-1 grep "logall" /var/ossec/etc/ossec.conf && docker restart single-node-wazuh.manager-1
```

logall>yes, logall_json>yes 확인됐고 restart 됨.
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabFinal4" -Value "C:\temp\evil.exe" -Force

```
```bash
sleep 40 && docker exec single-node-wazuh.manager-1 grep -a '"eventID":"13"' /var/ossec/logs/archives/archives.json | tail -3
```

restart할 때마다 no로 돌아가고 있음을 확인 Docker volume이 ossec.conf를 덮어쓰고 있음. - 컨테이너가 재시작되면 원본 config가 마운트되어 복원돼고 있음.

docker-compose.yml에서 volume확인:
```bash
cat ~/single-node/docker-compose.yml | grep -A5 "ossec.conf\|volumes"

```

또는
```bash
docker inspect single-node-wazuh.manager-1 | python3 -m json.tool | grep -A2 "ossec.conf"
```

위 두 명령어를 통해 Host의 어느 파일에 컨테이너가 마운트되는지 찾아야 한다. 거기를 직접 수정해야 반영이된다.

Host volume을  찾기
```bash
docker inspect single-node-wazuh.manager-1 --format '{{json .Mounts}}' | python3 -m json.tool | grep -B2 -A2 "ossec.conf\|config"
```

이전 명령 결과가 안보임 다시 입력
```bash
docker inspect single-node-wazuh.manager-1 --format '{{json .Mounts}}' | python3 -m json.tool | grep -B2 -A2 "ossec.conf\|config"
```

우선 새 명령 결과가 안찍히고 있기 때문에 logall 문제는 잠깐 우회

archives없이도 디버깅 가능하기 때문에

Windows agent가 EventID13을 실제로 보내는지 agent 로그에서 직접 확인:
```bash
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50 | Select-String "13\|Sysmon\|registry\|error" -CaseSensitive:$false
```

agent 로그가 전혀 안찍히고 있음 . Sysmon/registry 관련 로그가 안찍히고 있음.

agent가 수집하고 있는 내용을 확인 .

raw로 확인.
```bash
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30
```

Windows agnet가 mnager을 연결을 못하고 있음을 확인함.
```bash
Unable to connect to '[192.168.190.128]:1514/tcp'
대상 컴퓨터에서 연결을 거부했으므로 연결하지 못했습니다
```

manager가 restart되면서 1514 포트가 잠깐 끊겼고, agent가 재연결을 못함. 그래서 EventID13 이 전송 자체가 되지 않음.

Rocky에서 manger상태를 확인
```bash
docker ps | grep wazuh.manager
docker exec single-node-wazuh.manager-1 ss -tlnp | grep 1514
```

1514가 LISTEN 상태면 Windows에서 agent 재시작:
```bash
Restart-Service -Name "Wazuh" -Force
Start-Sleep 10
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 10
```

"Connected to server" 뜨면 연결 복구. 그다음 Registry 키 다시 쓰고 결과 확인.

을 할려고 했어나 Manager포트는 열려있는데 Windows에서 못붙고 있음.

방화벽과 같은 네트워크 확인 필요.
```bash
sudo firewall-cmd --list-ports | grep 1514
sudo firewall-cmd --add-port=1514/tcp --permanent && sudo firewall-cmd --reload
```

windows에서 직접 연결 테스트
```bash
Test-NetConnection -ComputerName 192.168.190.128 -Port 1514
```

- PingSucceeded: True — IP는 닿아
- TcpTestSucceeded: False — 1514 포트가 막혀
- firewalld is not running — Rocky 방화벽은 꺼져있어

IPTABLE 확인

INPUT에는 규칙이 없고 DOCKER 체인에 172.18.0.3:1514 ACCEPT만 있음.

Docker 내부 라우팅은 되는데 외부에서 못 붙고 있음.

Docker내부 라우티은 되는데 외부에서 못붙고있음.

Docker가 host의 0.0.0.0:1541의 바인딩을 하고 있는지 확인:
```bash
sudo ss -tlnp | grep 1514
```

Rocky 쪽은 완전 정상

VMware 네트워크 설정 확인

Windows(192.168.190.131)에서 Rocky(192.168.190.128)로 TCP 연결이 안 되고 있기 때무에 VMware의 네트워크 어댑터 타입 문제일 수도 있다.
```bash
# Rocky IP로 ping은 되니까 네트워크는 연결됨
# 다른 포트도 막히는지 확인
Test-NetConnection -ComputerName 192.168.190.128 -Port 55000
```
```bash
# Windows에서 연결 시도가 Rocky까지 오는지 확인
sudo tcpdump -i any -n port 1514 -c 10
```

패킷은 Rocky까지 오고 있음.
```bash
192.168.190.131 → 172.18.0.3: Flags [S]  (SYN 옴)
172.18.0.3 → 192.168.190.131: Flags [R.]  (RST로 거절)
```

컨테이너(172.18.0.3)가 RST를 보내고 있음. 포트는 열려있는데 컨테이너 내부에서 거절하는 거고 있음.

Wazuh manger프로세스가 1514를 실제로 안 듣고 있음.
```bash
#컨테이너 안에서 확인

docker exec single-node-wazuh.manager-1 ss -tlnp | grep 1514
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "wazuh-remoted\|remoted" /var/ossec/logs/ossec.log | tail -5
```
```bash
07:21:05 wazuh-remoted: Started. Listening on port 1514/TCP
07:22:11 wazuh-remoted: SIGNAL (15) Terminated. Exit Cleaning...
```

remoted가 시작 후 1분 만에 죽어버리고 있다.

그래서 ss -tlnp | grep 1514 결과가 비어있음/

즉 아무도 1514를 듣고 있지 않음

원인 파악
```bash
docker exec single-node-wazuh.manager-1 grep -a "remoted\|ERROR\|CRITICAL" /var/ossec/logs/ossec.log | grep "07:2[12]" | head -20
```

전체 프로세스 상태:
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control statusㅏ
```

결과
```bash
yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep -a "wazuh-remoted\|remoted" /var/ossec/logs/ossec.log | tail -5
2026/04/24 07:19:28 wazuh-remoted: INFO: (1410): Reading authentication keys file.
2026/04/24 07:20:47 wazuh-remoted: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
2026/04/24 07:21:05 wazuh-remoted: INFO: Started (pid: 615). Listening on port 1514/TCP (secure).
2026/04/24 07:21:05 wazuh-remoted: INFO: (1410): Reading authentication keys file.
2026/04/24 07:22:11 wazuh-remoted: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
[yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep -a "remoted\|ERROR\|CRITICAL" /var/ossec/logs/ossec.log | grep "07:2[12]" | head -20
2026/04/24 07:21:05 wazuh-remoted: INFO: Started (pid: 615). Listening on port 1514/TCP (secure).
2026/04/24 07:21:05 wazuh-remoted: INFO: (1410): Reading authentication keys file.
2026/04/24 07:22:11 wazuh-remoted: INFO: (1225): SIGNAL [(15)-(Terminated)] Received. Exit Cleaning...
[yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
wazuh-clusterd not running...
wazuh-modulesd: Process 796 not used by Wazuh, removing...
wazuh-modulesd not running...
wazuh-monitord not running...
wazuh-logcollector not running...
wazuh-remoted not running...
wazuh-syscheckd not running...
wazuh-analysisd not running...
wazuh-maild not running...
wazuh-execd not running...
wazuh-db not running...
wazuh-authd not running...
wazuh-agentlessd not running...
wazuh-integratord not running...
wazuh-dbd not running...
wazuh-csyslogd not running...
wazuh-apid: Process 401 not used by Wazuh, removing...
wazuh-apid not running...
[yhc@localhost single-node]$
```

프로세스가 전부 죽어있음.

컨테이너는 떠있는데 내부 프로세스가 다 down된 상태

ossec.conf를 python으로 수정할 때 파일이 깨졌을 가능성

컨테이너 재시작으로 init이 다시 돌아야 한다.
```bash
docker restart single-node-wazuh.manager-1 && sleep 40 && docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status

```

핵심 프로세스는 다시 살아남.
```bash
Restart-Service -Name "Wazuh" -Force
Start-Sleep 15
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 5
```

alerts.json 파일 자체가 없어. Docker 경로로 접근해야 한다.
```bash
docker exec single-node-wazuh.manager-1 grep -a "100220" /var/ossec/logs/alerts/alerts.json | tail -5
```

alerts.json  확인 .

Windows agent 연결되었는지 먼저 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "100220\|T1547" /var/ossec/logs/alerts/alerts.json | tail -3
```

결과
```bash
[yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep -a "100220\|T1547" /var/ossec/logs/alerts/alerts.json | tail -3
{"timestamp":"2026-04-24T05:37:56.724+0000","rule":{"level":6,"description":"Scripting file created under Windows Temp or User folder","id":"92200","mitre":{"id":["T1059","T1105"],"tactic":["Execution","Command and Control"],"technique":["Command and Scripting Interpreter","Ingress Tool Transfer"]},"firedtimes":1,"mail":false,"groups":["sysmon","sysmon_eid11_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777009076.2313609","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"11","version":"2","level":"4","task":"11","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T05:37:55.1798369Z","eventRecordID":"10674","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"File created:\r\nRuleName: T1547_Startup_Folder_LNK\r\nUtcTime: 2026-04-24 05:37:55.162\r\nProcessGuid: {4fb3ada3-40b8-69df-8c07-000000000500}\r\nProcessId: 8528\r\nImage: C:\\Windows\\system32\\conhost.exe\r\nTargetFilename: C:\\Users\\yhc\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Windows PowerShell\\Windows PowerShell.lnk\r\nCreationUtcTime: 2026-04-10 08:34:12.912\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Startup_Folder_LNK","utcTime":"2026-04-24 05:37:55.162","processGuid":"{4fb3ada3-40b8-69df-8c07-000000000500}","processId":"8528","image":"C:\\\\Windows\\\\system32\\\\conhost.exe","targetFilename":"C:\\\\Users\\\\yhc\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Windows PowerShell\\\\Windows PowerShell.lnk","creationUtcTime":"2026-04-10 08:34:12.912","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T05:38:28.112+0000","rule":{"level":6,"description":"Scripting file created under Windows Temp or User folder","id":"92200","mitre":{"id":["T1059","T1105"],"tactic":["Execution","Command and Control"],"technique":["Command and Scripting Interpreter","Ingress Tool Transfer"]},"firedtimes":2,"mail":false,"groups":["sysmon","sysmon_eid11_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777009108.2324322","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"11","version":"2","level":"4","task":"11","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T05:38:26.5924751Z","eventRecordID":"10679","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"File created:\r\nRuleName: T1547_Startup_Folder_LNK\r\nUtcTime: 2026-04-24 05:38:26.567\r\nProcessGuid: {4fb3ada3-40b8-69df-8c07-000000000500}\r\nProcessId: 8528\r\nImage: C:\\Windows\\system32\\conhost.exe\r\nTargetFilename: C:\\Users\\yhc\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Windows PowerShell\\Windows PowerShell.lnk\r\nCreationUtcTime: 2026-04-10 08:34:12.912\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Startup_Folder_LNK","utcTime":"2026-04-24 05:38:26.567","processGuid":"{4fb3ada3-40b8-69df-8c07-000000000500}","processId":"8528","image":"C:\\\\Windows\\\\system32\\\\conhost.exe","targetFilename":"C:\\\\Users\\\\yhc\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Windows PowerShell\\\\Windows PowerShell.lnk","creationUtcTime":"2026-04-10 08:34:12.912","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T07:40:46.234+0000","rule":{"level":3,"description":"Successful sudo to ROOT executed.","id":"5402","mitre":{"id":["T1548.003"],"tactic":["Privilege Escalation","Defense Evasion"],"technique":["Sudo and Sudo Caching"]},"firedtimes":10,"mail":false,"groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7","AC.6"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"001","name":"localhost.localdomain","ip":"127.0.0.1"},"manager":{"name":"wazuh.manager"},"id":"1777016446.3083500","full_log":"Apr 24 16:40:45 localhost sudo:      yhc : TTY=pts/2 ; PWD=/home/yhc/wazuh-docker/single-node ; USER=root ; COMMAND=/bin/grep -a 100220 /var/ossec/logs/alerts/alerts.json","predecoder":{"program_name":"sudo","timestamp":"Apr 24 16:40:45","hostname":"localhost"},"decoder":{"parent":"sudo","name":"sudo","ftscomment":"First time user executed the sudo command"},"data":{"srcuser":"yhc","dstuser":"root","tty":"pts/2","pwd":"/home/yhc/wazuh-docker/single-node","command":"/bin/grep -a 100220 /var/ossec/logs/alerts/alerts.json"},"location":"/var/log/secure"}
```

100220이 아직 없고 . alerts에는 EventID11(파일생성)과 SUDO 로그만 존재
```bash
docker exec single-node-wazuh.manager-1 grep -a "eventID.*13" /var/ossec/logs/alerts/alerts.json | tail -3
```
```bash
,"parentCommandLine":"powershell \\\"$null = secedit /export /cfg $env:temp/secexport.cfg; $(gc $env:temp/secexport.cfg | Select-String \\\\\\\"LSAAnonymousNameLookup\\\\\\\").ToString().Split(\\\\\\\"=\\\\\\\")[1].Trim()\\\"","parentUser":"NT AUTHORITY\\\\SYSTEM"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T07:47:59.541+0000","rule":{"level":3,"description":"Windows Logon Success","id":"60106","mitre":{"id":["T1078"],"tactic":["Defense Evasion","Persistence","Privilege Escalation","Initial Access"],"technique":["Valid Accounts"]},"firedtimes":14,"mail":false,"groups":["windows","windows_security","authentication_success"],"pci_dss":["10.2.5"],"gpg13":["7.1","7.2"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777016879.3146163","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2026-04-24T07:47:58.1803113Z","eventRecordID":"15982","processID":"692","threadID":"4696","channel":"Security","computer":"DESKTOP-5408CBA","severityValue":"AUDIT_SUCCESS","message":"\"계정이 성공적으로 로그온되었습니다.\r\n\r\n주체:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tDESKTOP-5408CBA$\r\n\t계정 도메인:\t\tWORKGROUP\r\n\t로그온 ID:\t\t0x3E7\r\n\r\n로그온 정보:\r\n\t로그온 유형:\t\t5\r\n\t제한된 관리 모드:\t-\r\n\t가상 계정:\t\t아니요\r\n\t상승된 토큰:\t\t예\r\n\r\n가장 수준:\t\t가장\r\n\r\n새 로그온:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tSYSTEM\r\n\t계정 도메인:\t\tNT AUTHORITY\r\n\t로그온 ID:\t\t0x3E7\r\n\t연결된 로그온 ID:\t\t0x0\r\n\t네트워크 계정 이름:\t-\r\n\t네트워크 계정 도메인:\t-\r\n\t로그온 GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\n프로세스 정보:\r\n\t프로세스 ID:\t\t0x29c\r\n\t프로세스 이름:\t\tC:\\Windows\\System32\\services.exe\r\n\r\n네트워크 정보:\r\n\t워크스테이션 이름:\t-\r\n\t원본 네트워크 주소:\t-\r\n\t원본 포트:\t\t-\r\n\r\n인증 세부 정보:\r\n\t로그온 프로세스:\t\tAdvapi  \r\n\t인증 패키지:\tNegotiate\r\n\t전송된 서비스:\t-\r\n\t패키지 이름(NTLM 전용):\t-\r\n\t키 길이:\t\t0\r\n\r\n이 이벤트는 로그온 세션이 만들어질 때 액세스했던 컴퓨터에 생성됩니다.\r\n\r\n주체 필드는 로그온을 요청한 로컬 시스템의 계정을 나타냅니다. 이것은 주로 서버 서비스와 같은 서비스 또는 Winlogon.exe나 Services.exe와 같은 로컬 프로세스입니다.\r\n\r\n로그온 유형 필드는 발생한 로그온의 종류를 나타냅니다. 가장 일반적인 유형은 2(대화형)와 3(네트워크)입니다.\r\n\r\n새 로그온 필드는 새 로그온을 만든 계정, 즉 로그온된 계정을 나타냅니다.\r\n\r\n네트워크 필드는 원격 로그온 요청이 시작된 위치를 나타냅니다. 워크스테이션 이름은 항상 사용할 수 있는 것은 아니며 어떤 경우에는 비워 둘 수 있습니다.\r\n\r\n가장 수준 필드는 로그온 세션의 프로세스에서 가장할 수 있는 범위를 나타냅니다.\r\n\r\n인증 정보 필드는 이 특정 로그온 요청에 대한 자세한 정보를 제공합니다.\r\n\t- 로그온 GUID는 이 이벤트를 KDC 이벤트와 연관시키는 데 사용할 수 있는 고유 식별자입니다.\r\n\t - 전송된 서비스는 이 로그온 요청과 관련된 중간 서비스를 나타냅니다.\r\n\t - 패키지 이름은 NTLM 프로토콜 간에 사용된 하위 프로토콜을 나타냅니다.\r\n\t - 키 길이는 생성된 세션 키의 길이를 나타냅니다. 이 값은 요청된 세션 키가 없는 경우 0이 됩니다.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-5408CBA$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-18","targetUserName":"SYSTEM","targetDomainName":"NT AUTHORITY","targetLogonId":"0x3e7","logonType":"5","logonProcessName":"Advapi","authenticationPackageName":"Negotiate","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x29c","processName":"C:\\\\Windows\\\\System32\\\\services.exe","impersonationLevel":"%%1833","virtualAccount":"%%1843","targetLinkedLogonId":"0x0","elevatedToken":"%%1842"}}},"location":"EventChannel"}
[yhc@localhost single-node]$ 
```

agent는 연결 → (DESKTOP-5408CBA 이벤트들어 오고 있음)

EventID13이 여전히 없음.

Windows에서 직접 확인:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.Id -eq 13} | Select-Object TimeCreated, Message | FL
```

Sysmon에 EventID13을 실제로 생성했는지. Windows 이벤트 뷰어 레벨에서 확인

EventID 13이 Windows 이벤트 로그에도 없음.

Sysmon이 Registry 이벤트를 캡쳐 자체를 안 하고 있음.

sysmon64.exe -c에서 RegistryEvent 설정이 있는데 Sysmon 서비스가 실제로 그 config를 로드했는지 확인.
```powershell
# Sysmon 서비스 상태
Get-Service sysmon64

# config 파일 다시 강제 적용
C:\Windows\sysmon64.exe -c "C:\Users\yhc\Desktop\sysmon_persistence.xml"

```

그다음 Registry 키 다시 작성:
```powershell
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test2 /t REG_SZ /d C:\evil.exe /f
```
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Where-Object {$_.Id -eq 13} | FL
```

결과
```powershell
PS C:\Windows\system32> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.Id -eq 13} | Select-Object TimeCreated, Message | FL
PS C:\Windows\system32> # Sysmon 서비스 상태
PS C:\Windows\system32> Get-Service sysmon64
Status   Name               DisplayName
------   ----               -----------
Running  Sysmon64           sysmon64
PS C:\Windows\system32>
PS C:\Windows\system32> # config 파일 다시 강제 적용
PS C:\Windows\system32> C:\Windows\sysmon64.exe -c "C:\Users\yhc\Desktop\sysmon_persistence.xml"
System Monitor v15.20 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2026 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com
Loading configuration file with schema version 4.90
Sysmon schema version: 4.91
Configuration file validated.
Configuration updated.
PS C:\Windows\system32>
```

config업데이트 됨. 그리고 트리거 하고 바로 확인:
```powershell
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test2 /t REG_SZ /d C:\evil.exe /f
```
```powershell
Start-Sleep 3
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Where-Object {$_.Id -eq 13} | FL TimeCreated, Message
```

결과
```powershell
Loading configuration file with schema version 4.90
Sysmon schema version: 4.91
Configuration file validated.
Configuration updated.
PS C:\Windows\system32> reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test2 /t REG_SZ /d C:\evil.exe /f
작업을 완료했습니다.
PS C:\Windows\system32> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Where-Object {$_.Id -eq 13} | FL
TimeCreated  : 2026-04-24 오후 4:54:21
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: T1543_Service_Registry
               EventType: SetValue
               UtcTime: 2026-04-24 07:54:21.499
               ProcessGuid: {4fb3ada3-2160-69eb-7f0f-000000000500}
               ProcessId: 4080
               Image: C:\Windows\system32\backgroundTaskHost.exe
               TargetObject: HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-3385978295-689239366-777767380-1001\Microsoft.Windows.Search_cw5n1h2txyewy
               Details: Binary Data
               User: DESKTOP-5408CBA\yhc
TimeCreated  : 2026-04-24 오후 4:54:18
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: T1543_Service_Registry
               EventType: SetValue
               UtcTime: 2026-04-24 07:54:18.515
               ProcessGuid: {4fb3ada3-2164-69eb-800f-000000000500}
               ProcessId: 8204
               Image: C:\Windows\system32\backgroundTaskHost.exe
               TargetObject: HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-3385978295-689239366-777767380-1001\MicrosoftWindows.Client.CBS_cw5n1h2txyewy
               Details: Binary Data
               User: DESKTOP-5408CBA\yhc
PS C:\Windows\system32>
```

EventID13이 생성됙 있는데 CurrentVersion\Run 이 아니라 Services\bam 키이다.

Sysmoin config의 exclude 규칙이 reg add 로 쓴 Run 키를 걸러냈거나.  reg add 가 다른 방식으로 작동함.

Run키 직접 확인:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 | Where-Object {$_.Id -eq 13 -and $_.Message -like "*CurrentVersion\Run*"} | FL TimeCreated, Message
```

결과
```powershell
PS C:\Windows\system32> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 | Where-Object {$_.Id -eq 13 -and $_.Message -like "*CurrentVersion\Run*"} | FL TimeCreated, Message
TimeCreated : 2026-04-24 오후 4:54:14
Message     : Registry value set:
              RuleName: T1547_Run_Key_Create
              EventType: SetValue
              UtcTime: 2026-04-24 07:54:14.718
              ProcessGuid: {4fb3ada3-21a6-69eb-860f-000000000500}
              ProcessId: 8308
              Image: C:\Windows\system32\reg.exe
              TargetObject: HKU\S-1-5-21-3385978295-689239366-777767380-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Test2
              Details: C:\evil.exe
              User: DESKTOP-5408CBA\yhc
PS C:\Windows\system32> New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Test3" -Value "C:\evil.exe" -Force
Test3        : C:\evil.exe
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion
PSChildName  : Run
PSDrive      : HKCU
PSProvider   : Microsoft.PowerShell.Core\Registry
PS C:\Windows\system32> Start-Sleep 3
PS C:\Windows\system32> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Where-Object {$_.Id -eq 13 -and $_.Message -like "*Run*"} | FL TimeCreated, Message
TimeCreated : 2026-04-24 오후 4:54:55
Message     : Registry value set:
              RuleName: T1547_Run_Key_Create
              EventType: SetValue
              UtcTime: 2026-04-24 07:54:55.468
              ProcessGuid: {4fb3ada3-f54f-69ea-9a0b-000000000500}
              ProcessId: 2052
              Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
              TargetObject: HKU\S-1-5-21-3385978295-689239366-777767380-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Test3
              Details: C:\evil.exe
              User: DESKTOP-5408CBA\yhc
TimeCreated : 2026-04-24 오후 4:54:48
Message     : Registry value set:
              RuleName: T1543_Service_Registry
              EventType: SetValue
              UtcTime: 2026-04-24 07:54:48.530
              ProcessGuid: {4fb3ada3-2167-69eb-810f-000000000500}
              ProcessId: 4032
              Image: C:\Windows\System32\RuntimeBroker.exe
              TargetObject: HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-3385978295-689239366-777767380-1001\MicrosoftWindows.Client.CBS_cw5n1h2txyewy
              Details: Binary Data
              User: DESKTOP-5408CBA\yhc
TimeCreated : 2026-04-24 오후 4:54:14
Message     : Registry value set:
              RuleName: T1547_Run_Key_Create
              EventType: SetValue
              UtcTime: 2026-04-24 07:54:14.718
              ProcessGuid: {4fb3ada3-21a6-69eb-860f-000000000500}
              ProcessId: 8308
              Image: C:\Windows\system32\reg.exe
              TargetObject: HKU\S-1-5-21-3385978295-689239366-777767380-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Test2
              Details: C:\evil.exe
              User: DESKTOP-5408CBA\yhc
```

Sysmon은 완벽하게 캠쳐하고 있음. Test2. Test3 둘 다 EventID 13으로 잡혔음.

이제 Rocky에서 alerts에 들어왔는지 확인:
```powershell
docker exec single-node-wazuh.manager-1 grep -a "T1547_Run_Key\|Test2\|Test3" /var/ossec/logs/alerts/alerts.json | tail -5
```
```powershell
[yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep -a "T1547_Run_Key\|Test2\|Test3" /var/ossec/logs/alerts/alerts.json | tail -5
{"timestamp":"2026-04-24T07:54:16.074+0000","rule":{"level":10,"description":"Value added to registry key has Base64-like pattern","id":"92041","mitre":{"id":["T1027","T1112"],"tactic":["Defense Evasion"],"technique":["Obfuscated Files or Information","Modify Registry"]},"firedtimes":1,"mail":false,"groups":["sysmon","sysmon_eid1_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777017256.3163557","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"1","version":"5","level":"4","task":"1","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T07:54:14.7151150Z","eventRecordID":"13174","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Process Create:\r\nRuleName: -\r\nUtcTime: 2026-04-24 07:54:14.690\r\nProcessGuid: {4fb3ada3-21a6-69eb-860f-000000000500}\r\nProcessId: 8308\r\nImage: C:\\Windows\\System32\\reg.exe\r\nFileVersion: 10.0.19041.1 (WinBuild.160101.0800)\r\nDescription: Registry Console Tool\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: reg.exe\r\nCommandLine: \"C:\\Windows\\system32\\reg.exe\" add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Test2 /t REG_SZ /d C:\\evil.exe /f\r\nCurrentDirectory: C:\\Windows\\system32\\\r\nUser: DESKTOP-5408CBA\\yhc\r\nLogonGuid: {4fb3ada3-405f-69df-f1cf-e30000000000}\r\nLogonId: 0xE3CFF1\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D\r\nParentProcessGuid: {4fb3ada3-f54f-69ea-9a0b-000000000500}\r\nParentProcessId: 2052\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \r\nParentUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"utcTime":"2026-04-24 07:54:14.690","processGuid":"{4fb3ada3-21a6-69eb-860f-000000000500}","processId":"8308","image":"C:\\\\Windows\\\\System32\\\\reg.exe","fileVersion":"10.0.19041.1 (WinBuild.160101.0800)","description":"Registry Console Tool","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","originalFileName":"reg.exe","commandLine":"\\\"C:\\\\Windows\\\\system32\\\\reg.exe\\\" add HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Test2 /t REG_SZ /d C:\\\\evil.exe /f","currentDirectory":"C:\\\\Windows\\\\system32\\\\","user":"DESKTOP-5408CBA\\\\yhc","logonGuid":"{4fb3ada3-405f-69df-f1cf-e30000000000}","logonId":"0xe3cff1","terminalSessionId":"1","integrityLevel":"High","hashes":"SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D","parentProcessGuid":"{4fb3ada3-f54f-69ea-9a0b-000000000500}","parentProcessId":"2052","parentImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","parentCommandLine":"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"","parentUser":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T07:54:16.108+0000","rule":{"level":6,"description":"Registry entry to be executed on next logon was modified using command line application reg.exe","id":"92302","mitre":{"id":["T1547.001"],"tactic":["Persistence","Privilege Escalation"],"technique":["Registry Run Keys / Startup Folder"]},"firedtimes":1,"mail":false,"groups":["sysmon","sysmon_eid13_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777017256.3169359","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T07:54:14.7250183Z","eventRecordID":"13176","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-24 07:54:14.718\r\nProcessGuid: {4fb3ada3-21a6-69eb-860f-000000000500}\r\nProcessId: 8308\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Test2\r\nDetails: C:\\evil.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-24 07:54:14.718","processGuid":"{4fb3ada3-21a6-69eb-860f-000000000500}","processId":"8308","image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Test2","details":"C:\\\\evil.exe","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
[yhc@localhost single-node]$ 
```

EventID 13이 alerts에 들어왔지만 rule92302가 먼저 잡음.

Wazuh 기본 룰셋에 이미 sysmon_eid13_detections 그룹 룰이 있어서 100220보다 먼저 매칭

100220이 안 뜨는 이유는 92302가 이미 EventID 13을 소비해버려서 체이닝이 안되고 있음.

100220의 if_sid가 185011인데, 실제로는 92302가 먼저 발동

해결책은 100220의 부모를 92302로 바꾸거나, 아예 독립 룰로 만들기 .
```powershell
docker exec single-node-wazuh.manager-1 bash -c "python3 -c \"
with open('/var/ossec/etc/rules/local_rules.xml', 'r') as f:
    content = f.read()
content = content.replace('<if_sid>185011</if_sid>', '<if_sid>92302</if_sid>')
with open('/var/ossec/etc/rules/local_rules.xml', 'w') as f:
    f.write(content)
print('done')
\""
```
```powershell
docker exec single-node-wazuh.manager-1 grep "if_sid" /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'
```

if_sid>92302 확인. HUP도 됐음.
```powershell

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test4 /t REG_SZ /d C:\evil.exe /f
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

100220이 아직 안 뜨고 sudo 로그만 확인됨. rule 5420가 “100220” 문자열을 포함하고 있어서 나옴.

Test4 트리거가 되었는지 확인
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test4\|92302" /var/ossec/logs/alerts/alerts.json | tail -3
```

결과
```bash
yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep "if_sid" /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'
    <if_sid>18101</if_sid>
    <if_sid>92302</if_sid>
[yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep -a "100220" /var/ossec/logs/alerts/alerts.json | tail -3
{"timestamp":"2026-04-24T07:40:46.234+0000","rule":{"level":3,"description":"Successful sudo to ROOT executed.","id":"5402","mitre":{"id":["T1548.003"],"tactic":["Privilege Escalation","Defense Evasion"],"technique":["Sudo and Sudo Caching"]},"firedtimes":10,"mail":false,"groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7","AC.6"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"001","name":"localhost.localdomain","ip":"127.0.0.1"},"manager":{"name":"wazuh.manager"},"id":"1777016446.3083500","full_log":"Apr 24 16:40:45 localhost sudo:      yhc : TTY=pts/2 ; PWD=/home/yhc/wazuh-docker/single-node ; USER=root ; COMMAND=/bin/grep -a 100220 /var/ossec/logs/alerts/alerts.json","predecoder":{"program_name":"sudo","timestamp":"Apr 24 16:40:45","hostname":"localhost"},"decoder":{"parent":"sudo","name":"sudo","ftscomment":"First time user executed the sudo command"},"data":{"srcuser":"yhc","dstuser":"root","tty":"pts/2","pwd":"/home/yhc/wazuh-docker/single-node","command":"/bin/grep -a 100220 /var/ossec/logs/alerts/alerts.json"},"location":"/var/log/secure"}
[yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep -a "Test4\|92302" /var/ossec/logs/alerts/alerts.json | tail -3
{"timestamp":"2026-04-24T07:54:16.108+0000","rule":{"level":6,"description":"Registry entry to be executed on next logon was modified using command line application reg.exe","id":"92302","mitre":{"id":["T1547.001"],"tactic":["Persistence","Privilege Escalation"],"technique":["Registry Run Keys / Startup Folder"]},"firedtimes":1,"mail":false,"groups":["sysmon","sysmon_eid13_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777017256.3169359","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T07:54:14.7250183Z","eventRecordID":"13176","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-24 07:54:14.718\r\nProcessGuid: {4fb3ada3-21a6-69eb-860f-000000000500}\r\nProcessId: 8308\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Test2\r\nDetails: C:\\evil.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-24 07:54:14.718","processGuid":"{4fb3ada3-21a6-69eb-860f-000000000500}","processId":"8308","image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Test2","details":"C:\\\\evil.exe","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T07:58:29.592+0000","rule":{"level":10,"description":"Value added to registry key has Base64-like pattern","id":"92041","mitre":{"id":["T1027","T1112"],"tactic":["Defense Evasion"],"technique":["Obfuscated Files or Information","Modify Registry"]},"firedtimes":2,"mail":false,"groups":["sysmon","sysmon_eid1_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777017509.3174191","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"1","version":"5","level":"4","task":"1","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T07:58:28.2426996Z","eventRecordID":"13238","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Process Create:\r\nRuleName: -\r\nUtcTime: 2026-04-24 07:58:28.224\r\nProcessGuid: {4fb3ada3-22a4-69eb-8c0f-000000000500}\r\nProcessId: 4476\r\nImage: C:\\Windows\\System32\\reg.exe\r\nFileVersion: 10.0.19041.1 (WinBuild.160101.0800)\r\nDescription: Registry Console Tool\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: reg.exe\r\nCommandLine: \"C:\\Windows\\system32\\reg.exe\" add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Test4 /t REG_SZ /d C:\\evil.exe /f\r\nCurrentDirectory: C:\\Windows\\system32\\\r\nUser: DESKTOP-5408CBA\\yhc\r\nLogonGuid: {4fb3ada3-405f-69df-f1cf-e30000000000}\r\nLogonId: 0xE3CFF1\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D\r\nParentProcessGuid: {4fb3ada3-f54f-69ea-9a0b-000000000500}\r\nParentProcessId: 2052\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \r\nParentUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"utcTime":"2026-04-24 07:58:28.224","processGuid":"{4fb3ada3-22a4-69eb-8c0f-000000000500}","processId":"4476","image":"C:\\\\Windows\\\\System32\\\\reg.exe","fileVersion":"10.0.19041.1 (WinBuild.160101.0800)","description":"Registry Console Tool","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","originalFileName":"reg.exe","commandLine":"\\\"C:\\\\Windows\\\\system32\\\\reg.exe\\\" add HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Test4 /t REG_SZ /d C:\\\\evil.exe /f","currentDirectory":"C:\\\\Windows\\\\system32\\\\","user":"DESKTOP-5408CBA\\\\yhc","logonGuid":"{4fb3ada3-405f-69df-f1cf-e30000000000}","logonId":"0xe3cff1","terminalSessionId":"1","integrityLevel":"High","hashes":"SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D","parentProcessGuid":"{4fb3ada3-f54f-69ea-9a0b-000000000500}","parentProcessId":"2052","parentImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","parentCommandLine":"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"","parentUser":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T07:58:29.629+0000","rule":{"level":6,"description":"Registry entry to be executed on next logon was modified using command line application reg.exe","id":"92302","mitre":{"id":["T1547.001"],"tactic":["Persistence","Privilege Escalation"],"technique":["Registry Run Keys / Startup Folder"]},"firedtimes":2,"mail":false,"groups":["sysmon","sysmon_eid13_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777017509.3179993","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T07:58:28.2456728Z","eventRecordID":"13240","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-24 07:58:28.233\r\nProcessGuid: {4fb3ada3-22a4-69eb-8c0f-000000000500}\r\nProcessId: 4476\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Test4\r\nDetails: C:\\evil.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-24 07:58:28.233","processGuid":"{4fb3ada3-22a4-69eb-8c0f-000000000500}","processId":"4476","image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Test4","details":"C:\\\\evil.exe","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
[yhc@localhost single-node]$ 
```

Test4도 92302로 잡혔는데 100220이 여전히 없음.

HUP이 실제로 반영이 되었는지 확인.

analysisd 재시작
```bash
docker restart single-node-wazuh.manager-1 && sleep 40
```

Windows에서 Test5 트리거
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test5" /var/ossec/logs/alerts/alerts.json | tail -3
```

92302가 이미 T1547.001을 level 6으로 잡고 있어. 100220의 목적(Run 키 수정 탐지)이 이미 달성
```bash
docker restart single-node-wazuh.manager-1 && sleep 40 && docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status | grep remoted

```

remoted 살아있음.

local_rules.xml 확인:
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```

XML 정상

if_sid>92302 확인

가설:

100220의 field 매칭이 실패

alerts에서 Test4 이벤트의 실제 필드명이 win.eventdata.targetObject가 아니라 targetObject로 들어오고 있음.

logtest로 92302 이벤트 ID를 직접 시뮬레이션해서 field 이름 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test4" /var/ossec/logs/alerts/alerts.json | python3 -m json.tool 2>/dev/null | grep -i "target\|eventdata"
```

Test4가 alerts에 없어 — restart 후 새 이벤트가 없음.
```bash
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test6 /t REG_SZ /d C:\evil.exe /f
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test6" /var/ossec/logs/alerts/alerts.json | python3 -m json.tool 2>/dev/null | grep -i "target\|eventdata"
```

08:10:40 — 최근 이벤트를 확인하고 agent연결이 살아있음을 확인함

Test6 트리거 후 alerts에 92302는 들어왔는지:
```bash
docker exec single-node-wazuh.manager-1 grep -a "92302" /var/ossec/logs/alerts/alerts.json | tail -1 | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['timestamp'], d['data']['win']['eventdata'].get('targetObject',''))"
```

targetObject에 Current Version\\Run\Test5 92302는 잡히고 있는데 100220이 체이닝이 안되고 있음.

field매칭 문제. 실제 데이터는  win.eventdata.targetObject Wazuh가 chile rule에서 이 필드를 못읽고 있음.

룰을 filed 대신 match로 바꾸기:
```bash
docker exec single-node-wazuh.manager-1 bash -c "python3 -c \"
with open('/var/ossec/etc/rules/local_rules.xml', 'r') as f:
    content = f.read()
content = content.replace(
    '<field name=\"win.eventdata.targetObject\" type=\"pcre2\">(?i)CurrentVersion\\\\.Run</field>',
    '<match>CurrentVersion.Run</match>'
)
with open('/var/ossec/etc/rules/local_rules.xml', 'w') as f:
    f.write(content)
print('done')
\""
```

확인
```bash
docker exec single-node-wazuh.manager-1 grep "match\|field" /var/ossec/etc/rules/local_rules.xml
```

replace가 먹히지 않음 field줄이 그대로.. 백슬레시 이스케이프 문제.

직접 파일 다시 직접 작성
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << ENDOFFILE
<group name="sysmon,windows,">
  <rule id="185011" level="3" overwrite="yes">
    <if_sid>18101</if_sid>
    <match>Microsoft-Windows-Sysmon/Operational: INFORMATION(13)</match>
    <description>Sysmon - Event 13</description>
    <group>sysmon_event_13,</group>
  </rule>
  <rule id="100220" level="12">
    <if_sid>92302</if_sid>
    <match>CurrentVersion</match>
    <description>T1547 - Run key modified by $(win.eventdata.image)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
ENDOFFILE'
```

권한 고치고 HUP
```bash
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml && docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'
```

$(win.eventdata.image) 가 bash에서 실행되려 해서 오류

description에서 $ 때문
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```

파일내용을 확일해보니 match> CurrentVersion 들어갔고 권한도 됨. HUP도 됐으니 바로 트리거 : `
```bash
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test7 /t REG_SZ /d C:\evil.exe /f
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

sudo로그만 나옴,

Test7이 92302로 들어왔는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test7" /var/ossec/logs/alerts/alerts.json | tail -1
```

Test7은 92302로 잡혔지만 100220이 체이닝 되고 있지 않음.

firedtimes: 2 — 92302가 이전에도 발동했던 룰임.

Wazuh는 if_sid 체이닝할 때 같은 이벤트 내에서 부모가 먼저 발동해야 하는데, 이미 발동한 룰 ID를 if_sid로 참조하는 방식이 안 되는 케이스가 있어서

if_group 으로 수정:
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << ENDOFFILE
<group name="sysmon,windows,">
  <rule id="100220" level="12">
    <if_group>sysmon_eid13_detections</if_group>
    <match>CurrentVersion</match>
    <description>T1547 - Run key modified</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
ENDOFFILE'
```
```bash
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml && docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'
```
```bash
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test8 /t REG_SZ /d C:\evil.exe /f
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "100220\|Test8" /var/ossec/logs/alerts/alerts.json | tail -3
```

결과
```bash
yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep -a "100220\|Test8" /var/ossec/logs/alerts/alerts.json | tail -3
{"timestamp":"2026-04-24T07:40:46.234+0000","rule":{"level":3,"description":"Successful sudo to ROOT executed.","id":"5402","mitre":{"id":["T1548.003"],"tactic":["Privilege Escalation","Defense Evasion"],"technique":["Sudo and Sudo Caching"]},"firedtimes":10,"mail":false,"groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7","AC.6"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"001","name":"localhost.localdomain","ip":"127.0.0.1"},"manager":{"name":"wazuh.manager"},"id":"1777016446.3083500","full_log":"Apr 24 16:40:45 localhost sudo:      yhc : TTY=pts/2 ; PWD=/home/yhc/wazuh-docker/single-node ; USER=root ; COMMAND=/bin/grep -a 100220 /var/ossec/logs/alerts/alerts.json","predecoder":{"program_name":"sudo","timestamp":"Apr 24 16:40:45","hostname":"localhost"},"decoder":{"parent":"sudo","name":"sudo","ftscomment":"First time user executed the sudo command"},"data":{"srcuser":"yhc","dstuser":"root","tty":"pts/2","pwd":"/home/yhc/wazuh-docker/single-node","command":"/bin/grep -a 100220 /var/ossec/logs/alerts/alerts.json"},"location":"/var/log/secure"}
{"timestamp":"2026-04-24T08:17:55.167+0000","rule":{"level":10,"description":"Value added to registry key has Base64-like pattern","id":"92041","mitre":{"id":["T1027","T1112"],"tactic":["Defense Evasion"],"technique":["Obfuscated Files or Information","Modify Registry"]},"firedtimes":3,"mail":false,"groups":["sysmon","sysmon_eid1_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777018675.3268785","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"1","version":"5","level":"4","task":"1","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T08:17:53.7814144Z","eventRecordID":"13515","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Process Create:\r\nRuleName: -\r\nUtcTime: 2026-04-24 08:17:53.772\r\nProcessGuid: {4fb3ada3-2731-69eb-a90f-000000000500}\r\nProcessId: 11068\r\nImage: C:\\Windows\\System32\\reg.exe\r\nFileVersion: 10.0.19041.1 (WinBuild.160101.0800)\r\nDescription: Registry Console Tool\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: reg.exe\r\nCommandLine: \"C:\\Windows\\system32\\reg.exe\" add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Test8 /t REG_SZ /d C:\\evil.exe /f\r\nCurrentDirectory: C:\\Windows\\system32\\\r\nUser: DESKTOP-5408CBA\\yhc\r\nLogonGuid: {4fb3ada3-405f-69df-f1cf-e30000000000}\r\nLogonId: 0xE3CFF1\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D\r\nParentProcessGuid: {4fb3ada3-f54f-69ea-9a0b-000000000500}\r\nParentProcessId: 2052\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \r\nParentUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"utcTime":"2026-04-24 08:17:53.772","processGuid":"{4fb3ada3-2731-69eb-a90f-000000000500}","processId":"11068","image":"C:\\\\Windows\\\\System32\\\\reg.exe","fileVersion":"10.0.19041.1 (WinBuild.160101.0800)","description":"Registry Console Tool","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","originalFileName":"reg.exe","commandLine":"\\\"C:\\\\Windows\\\\system32\\\\reg.exe\\\" add HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Test8 /t REG_SZ /d C:\\\\evil.exe /f","currentDirectory":"C:\\\\Windows\\\\system32\\\\","user":"DESKTOP-5408CBA\\\\yhc","logonGuid":"{4fb3ada3-405f-69df-f1cf-e30000000000}","logonId":"0xe3cff1","terminalSessionId":"1","integrityLevel":"High","hashes":"SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D","parentProcessGuid":"{4fb3ada3-f54f-69ea-9a0b-000000000500}","parentProcessId":"2052","parentImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","parentCommandLine":"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"","parentUser":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T08:17:55.182+0000","rule":{"level":6,"description":"Registry entry to be executed on next logon was modified using command line application reg.exe","id":"92302","mitre":{"id":["T1547.001"],"tactic":["Persistence","Privilege Escalation"],"technique":["Registry Run Keys / Startup Folder"]},"firedtimes":3,"mail":false,"groups":["sysmon","sysmon_eid13_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777018675.3274591","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T08:17:53.7857881Z","eventRecordID":"13517","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-24 08:17:53.780\r\nProcessGuid: {4fb3ada3-2731-69eb-a90f-000000000500}\r\nProcessId: 11068\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Test8\r\nDetails: C:\\evil.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-24 08:17:53.780","processGuid":"{4fb3ada3-2731-69eb-a90f-000000000500}","processId":"11068","image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Test8","details":"C:\\\\evil.exe","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
[yhc@localhost single-node]$ 

```

Test8이 92302로 잡혔는데 아직도 100220이 뜨지 않고 있음.

즉 if_group 이 아직도 적용되고 있지 않음.

Wazuh는 하나의 이벤트에 대해 룰 하나만 최종 발동됙기 때문에 100220이 체이닝을 추가로 발동하는 것이 아니라 대체를 해야한다.

92302를 overwrite해서 100220 조건을 거기 직접 넣거나, 아니면 100220을 완전 독립 룰로 만들어야 한다.
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << ENDOFFILE
<group name="sysmon,windows,">
  <rule id="100220" level="12">
    <if_group>sysmon_eid13_detections</if_group>
    <field name="win.eventdata.targetObject">CurrentVersion.Run</field>
    <description>T1547 - Run key modified</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
ENDOFFILE'
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'
```

field는 match와 달리 decoded field를 직접 참조

targetObject 값에 CurrentVersion.Run 이 있기때문이다.
```bash
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test9 /t REG_SZ /d C:\evil.exe /f
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test9\|100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

결과
```bash
[yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep -a "Test9\|100220" /var/ossec/logs/alerts/alerts.json | tail -3
{"timestamp":"2026-04-24T07:40:46.234+0000","rule":{"level":3,"description":"Successful sudo to ROOT executed.","id":"5402","mitre":{"id":["T1548.003"],"tactic":["Privilege Escalation","Defense Evasion"],"technique":["Sudo and Sudo Caching"]},"firedtimes":10,"mail":false,"groups":["syslog","sudo"],"pci_dss":["10.2.5","10.2.2"],"gpg13":["7.6","7.8","7.13"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7","AC.6"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"001","name":"localhost.localdomain","ip":"127.0.0.1"},"manager":{"name":"wazuh.manager"},"id":"1777016446.3083500","full_log":"Apr 24 16:40:45 localhost sudo:      yhc : TTY=pts/2 ; PWD=/home/yhc/wazuh-docker/single-node ; USER=root ; COMMAND=/bin/grep -a 100220 /var/ossec/logs/alerts/alerts.json","predecoder":{"program_name":"sudo","timestamp":"Apr 24 16:40:45","hostname":"localhost"},"decoder":{"parent":"sudo","name":"sudo","ftscomment":"First time user executed the sudo command"},"data":{"srcuser":"yhc","dstuser":"root","tty":"pts/2","pwd":"/home/yhc/wazuh-docker/single-node","command":"/bin/grep -a 100220 /var/ossec/logs/alerts/alerts.json"},"location":"/var/log/secure"}
{"timestamp":"2026-04-24T08:19:47.373+0000","rule":{"level":10,"description":"Value added to registry key has Base64-like pattern","id":"92041","mitre":{"id":["T1027","T1112"],"tactic":["Defense Evasion"],"technique":["Obfuscated Files or Information","Modify Registry"]},"firedtimes":4,"mail":false,"groups":["sysmon","sysmon_eid1_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777018787.3277543","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"1","version":"5","level":"4","task":"1","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T08:19:45.9891051Z","eventRecordID":"13548","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Process Create:\r\nRuleName: -\r\nUtcTime: 2026-04-24 08:19:45.968\r\nProcessGuid: {4fb3ada3-27a1-69eb-ab0f-000000000500}\r\nProcessId: 10804\r\nImage: C:\\Windows\\System32\\reg.exe\r\nFileVersion: 10.0.19041.1 (WinBuild.160101.0800)\r\nDescription: Registry Console Tool\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: reg.exe\r\nCommandLine: \"C:\\Windows\\system32\\reg.exe\" add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Test9 /t REG_SZ /d C:\\evil.exe /f\r\nCurrentDirectory: C:\\Windows\\system32\\\r\nUser: DESKTOP-5408CBA\\yhc\r\nLogonGuid: {4fb3ada3-405f-69df-f1cf-e30000000000}\r\nLogonId: 0xE3CFF1\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D\r\nParentProcessGuid: {4fb3ada3-f54f-69ea-9a0b-000000000500}\r\nParentProcessId: 2052\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \r\nParentUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"utcTime":"2026-04-24 08:19:45.968","processGuid":"{4fb3ada3-27a1-69eb-ab0f-000000000500}","processId":"10804","image":"C:\\\\Windows\\\\System32\\\\reg.exe","fileVersion":"10.0.19041.1 (WinBuild.160101.0800)","description":"Registry Console Tool","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","originalFileName":"reg.exe","commandLine":"\\\"C:\\\\Windows\\\\system32\\\\reg.exe\\\" add HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Test9 /t REG_SZ /d C:\\\\evil.exe /f","currentDirectory":"C:\\\\Windows\\\\system32\\\\","user":"DESKTOP-5408CBA\\\\yhc","logonGuid":"{4fb3ada3-405f-69df-f1cf-e30000000000}","logonId":"0xe3cff1","terminalSessionId":"1","integrityLevel":"High","hashes":"SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D","parentProcessGuid":"{4fb3ada3-f54f-69ea-9a0b-000000000500}","parentProcessId":"2052","parentImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","parentCommandLine":"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"","parentUser":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T08:19:47.386+0000","rule":{"level":6,"description":"Registry entry to be executed on next logon was modified using command line application reg.exe","id":"92302","mitre":{"id":["T1547.001"],"tactic":["Persistence","Privilege Escalation"],"technique":["Registry Run Keys / Startup Folder"]},"firedtimes":4,"mail":false,"groups":["sysmon","sysmon_eid13_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777018787.3283349","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T08:19:46.0000929Z","eventRecordID":"13550","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-24 08:19:45.999\r\nProcessGuid: {4fb3ada3-27a1-69eb-ab0f-000000000500}\r\nProcessId: 10804\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Test9\r\nDetails: C:\\evil.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-24 08:19:45.999","processGuid":"{4fb3ada3-27a1-69eb-ab0f-000000000500}","processId":"10804","image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Test9","details":"C:\\\\evil.exe","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
[yhc@localhost single-node]$ 
```

Test9도 92302만 뜨고 100220이 나오지 않음.

Wazuh if_group은 이전 이벤트의 그룹을 참조하는 게 아니다. — 같은 이벤트가 부모 룰에 의해 그 그룹으로 분류됐을 때 child가 추가로 발동하는 구조인데, 실제로는 부모보다 높은 level의 child가 부모를 대체해야 한다.

92302의 group이 sysmon_eid13_detections 이지만 923902가 먼저 발동하고 나면 같은 이벤트에 대해 추가 룰이 발동안하기 때문에 100220이 안뜸.

해결책 :92302를 overwrite해서 level을 올리고 조건을 추가
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << ENDOFFILE
<group name="sysmon,windows,">
  <rule id="92302" level="12" overwrite="yes">
    <if_group>sysmon_eid13_detections</if_group>
    <field name="win.eventdata.targetObject">CurrentVersion.Run</field>
    <description>T1547 - Run key modified</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,sysmon_eid13_detections,</group>
  </rule>
</group>
ENDOFFILE'
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'
```
```bash
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test10 /t REG_SZ /d C:\evil.exe /f
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test10\|\"id\":\"92302\"" /var/ossec/logs/alerts/alerts.json | tail -3
```

결과
```bash
hc@localhost single-node]$ docker exec single-node-wazuh.manager-1 grep -a "Test10\|\"id\":\"92302\"" /var/ossec/logs/alerts/alerts.json | tail -3
{"timestamp":"2026-04-24T08:22:01.888+0000","rule":{"level":6,"description":"Registry entry to be executed on next logon was modified using command line application reg.exe","id":"92302","mitre":{"id":["T1547.001"],"tactic":["Persistence","Privilege Escalation"],"technique":["Registry Run Keys / Startup Folder"]},"firedtimes":5,"mail":false,"groups":["sysmon","sysmon_eid13_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777018921.3294147","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T08:22:00.5129485Z","eventRecordID":"13572","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-24 08:22:00.499\r\nProcessGuid: {4fb3ada3-2828-69eb-ac0f-000000000500}\r\nProcessId: 10776\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Test9\r\nDetails: C:\\evil.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-24 08:22:00.499","processGuid":"{4fb3ada3-2828-69eb-ac0f-000000000500}","processId":"10776","image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Test9","details":"C:\\\\evil.exe","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T08:22:19.844+0000","rule":{"level":10,"description":"Value added to registry key has Base64-like pattern","id":"92041","mitre":{"id":["T1027","T1112"],"tactic":["Defense Evasion"],"technique":["Obfuscated Files or Information","Modify Registry"]},"firedtimes":6,"mail":false,"groups":["sysmon","sysmon_eid1_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777018939.3297099","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"1","version":"5","level":"4","task":"1","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T08:22:18.4583132Z","eventRecordID":"13575","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Process Create:\r\nRuleName: -\r\nUtcTime: 2026-04-24 08:22:18.435\r\nProcessGuid: {4fb3ada3-283a-69eb-ad0f-000000000500}\r\nProcessId: 6316\r\nImage: C:\\Windows\\System32\\reg.exe\r\nFileVersion: 10.0.19041.1 (WinBuild.160101.0800)\r\nDescription: Registry Console Tool\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: reg.exe\r\nCommandLine: \"C:\\Windows\\system32\\reg.exe\" add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Test10 /t REG_SZ /d C:\\evil.exe /f\r\nCurrentDirectory: C:\\Windows\\system32\\\r\nUser: DESKTOP-5408CBA\\yhc\r\nLogonGuid: {4fb3ada3-405f-69df-f1cf-e30000000000}\r\nLogonId: 0xE3CFF1\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D\r\nParentProcessGuid: {4fb3ada3-f54f-69ea-9a0b-000000000500}\r\nParentProcessId: 2052\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \r\nParentUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"utcTime":"2026-04-24 08:22:18.435","processGuid":"{4fb3ada3-283a-69eb-ad0f-000000000500}","processId":"6316","image":"C:\\\\Windows\\\\System32\\\\reg.exe","fileVersion":"10.0.19041.1 (WinBuild.160101.0800)","description":"Registry Console Tool","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","originalFileName":"reg.exe","commandLine":"\\\"C:\\\\Windows\\\\system32\\\\reg.exe\\\" add HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Test10 /t REG_SZ /d C:\\\\evil.exe /f","currentDirectory":"C:\\\\Windows\\\\system32\\\\","user":"DESKTOP-5408CBA\\\\yhc","logonGuid":"{4fb3ada3-405f-69df-f1cf-e30000000000}","logonId":"0xe3cff1","terminalSessionId":"1","integrityLevel":"High","hashes":"SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D","parentProcessGuid":"{4fb3ada3-f54f-69ea-9a0b-000000000500}","parentProcessId":"2052","parentImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","parentCommandLine":"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"","parentUser":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T08:22:19.856+0000","rule":{"level":6,"description":"Registry entry to be executed on next logon was modified using command line application reg.exe","id":"92302","mitre":{"id":["T1547.001"],"tactic":["Persistence","Privilege Escalation"],"technique":["Registry Run Keys / Startup Folder"]},"firedtimes":6,"mail":false,"groups":["sysmon","sysmon_eid13_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777018939.3302905","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T08:22:18.4640004Z","eventRecordID":"13577","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-24 08:22:18.452\r\nProcessGuid: {4fb3ada3-283a-69eb-ad0f-000000000500}\r\nProcessId: 6316\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Test10\r\nDetails: C:\\evil.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-24 08:22:18.452","processGuid":"{4fb3ada3-283a-69eb-ad0f-000000000500}","processId":"6316","image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Test10","details":"C:\\\\evil.exe","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
[yhc@localhost single-node]$ 
```

overwrite도 안 먹힘.

92302가 여전히 level6로 뜨고 있음.

HUP이 실제로 반영이 안 되고 있음.

Docker volume이 계속 덮어쓰는 문제가 있음.

docker-compose.yml에서 ossec.conf처럼 rules도 volume mount가 있는지 확인:
```bash
grep -A3 "rules\|local_rules" ~/wazuh-docker/single-node/docker-compose.yml
```

rules volume mount가 없음.

overwriter가 실제로 로드 되었는지 확인.
```bash
docker exec single-node-wazuh.manager-1 grep -a "overwrite\|92302" /var/ossec/logs/ossec.log | tail -5
```

HUP이 analysisd를 못 찾고 있음.

prep확인:
```bash
docker exec single-node-wazuh.manager-1 pgrep -a wazuh-analysisd
```

pid 512

HUP를 직접 보내기:
```bash
docker exec single-node-wazuh.manager-1 kill -HUP 512
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "overwrite\|Loaded" /var/ossec/logs/ossec.log | tail -5
```

kill이 컨테이너에 없어. bash로 감싸야 한다.:
```bash
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP 512'
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "overwrite\|Loaded" /var/ossec/logs/ossec.log | tail -5
```

HUP 됐는데 "overwrite" 로그가 없음.  analysisd가 룰 리로드 로그를 안남기고 있음.

트리거하고 92302가 level 12로 뜨는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "\"id\":\"92302\"" /var/ossec/logs/alerts/alerts.json | tail -1 | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print('level:', d['rule']['level'])"
```

level 6 그대이다. overwriter가 완전히 무시되고 있음.

Wazuh Docker에서 rules가 어디서 오는지 확인:
```bash
docker exec single-node-wazuh.manager-1 find /var/ossec/ruleset -name "*.xml" | xargs grep -l "92302" 2>/dev/null
```

ruleset에  없음.

다른 경로로:
```bash
docker exec single-node-wazuh.manager-1 find / -name "*.xml" 2>/dev/null | xargs grep -l "92302" 2>/dev/null
```

92302가 어떤 XML 파일에도 없다. 그것은 이 룰이 컴파일된 바이너리 ruleset에 내장되어있음을 의미한다.

Wazuh 4.9에서 일부 룰이 .xml 파일이 아니라 내부적으로 처리된다.

전략 전환: 92302 overwrite 포기하고, 100220을 완전히 독립적인 룰로 만들되 if_sid 없이 decoder 조건만으로 매칭:
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << ENDOFFILE
<group name="sysmon,windows,">
  <rule id="100220" level="12">
    <decoded_as>windows_eventchannel</decoded_as>
    <field name="win.system.eventID">^13$</field>
    <field name="win.eventdata.targetObject">CurrentVersion.Run</field>
    <description>T1547 - Run key modified</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
ENDOFFILE'
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'
```
```bash
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Test11 /t REG_SZ /d C:\evil.exe /f
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test11\|100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

결과
```bash
041","mitre":{"id":["T1027","T1112"],"tactic":["Defense Evasion"],"technique":["Obfuscated Files or Information","Modify Registry"]},"firedtimes":7,"mail":false,"groups":["sysmon","sysmon_eid1_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777019386.3344632","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"1","version":"5","level":"4","task":"1","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T08:29:44.6504554Z","eventRecordID":"13681","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Process Create:\r\nRuleName: -\r\nUtcTime: 2026-04-24 08:29:44.639\r\nProcessGuid: {4fb3ada3-29f8-69eb-ba0f-000000000500}\r\nProcessId: 412\r\nImage: C:\\Windows\\System32\\reg.exe\r\nFileVersion: 10.0.19041.1 (WinBuild.160101.0800)\r\nDescription: Registry Console Tool\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: reg.exe\r\nCommandLine: \"C:\\Windows\\system32\\reg.exe\" add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Test11 /t REG_SZ /d C:\\evil.exe /f\r\nCurrentDirectory: C:\\Windows\\system32\\\r\nUser: DESKTOP-5408CBA\\yhc\r\nLogonGuid: {4fb3ada3-405f-69df-f1cf-e30000000000}\r\nLogonId: 0xE3CFF1\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D\r\nParentProcessGuid: {4fb3ada3-f54f-69ea-9a0b-000000000500}\r\nParentProcessId: 2052\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \r\nParentUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"utcTime":"2026-04-24 08:29:44.639","processGuid":"{4fb3ada3-29f8-69eb-ba0f-000000000500}","processId":"412","image":"C:\\\\Windows\\\\System32\\\\reg.exe","fileVersion":"10.0.19041.1 (WinBuild.160101.0800)","description":"Registry Console Tool","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","originalFileName":"reg.exe","commandLine":"\\\"C:\\\\Windows\\\\system32\\\\reg.exe\\\" add HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Test11 /t REG_SZ /d C:\\\\evil.exe /f","currentDirectory":"C:\\\\Windows\\\\system32\\\\","user":"DESKTOP-5408CBA\\\\yhc","logonGuid":"{4fb3ada3-405f-69df-f1cf-e30000000000}","logonId":"0xe3cff1","terminalSessionId":"1","integrityLevel":"High","hashes":"SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D","parentProcessGuid":"{4fb3ada3-f54f-69ea-9a0b-000000000500}","parentProcessId":"2052","parentImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","parentCommandLine":"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"","parentUser":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T08:29:46.033+0000","rule":{"level":6,"description":"Registry entry to be executed on next logon was modified using command line application reg.exe","id":"92302","mitre":{"id":["T1547.001"],"tactic":["Persistence","Privilege Escalation"],"technique":["Registry Run Keys / Startup Folder"]},"firedtimes":7,"mail":false,"groups":["sysmon","sysmon_eid13_detections","windows"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777019386.3350434","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-24T08:29:44.6901866Z","eventRecordID":"13683","processID":"2692","threadID":"3792","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-24 08:29:44.686\r\nProcessGuid: {4fb3ada3-29f8-69eb-ba0f-000000000500}\r\nProcessId: 412\r\nImage: C:\\Windows\\system32\\reg.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Test11\r\nDetails: C:\\evil.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-24 08:29:44.686","processGuid":"{4fb3ada3-29f8-69eb-ba0f-000000000500}","processId":"412","image":"C:\\\\Windows\\\\system32\\\\reg.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Test11","details":"C:\\\\evil.exe","user":"DESKTOP-5408CBA\\\\yhc"}}},"location":"EventChannel"}
[yhc@localhost single-node]$ 
```

또 다시 92302가 먼저 적용이됨.

92302가 이 이벤트를 완전히 소비해서 100220이 평가될 기회 지체가 없었음.

Wazuh는 이벤트당 룰 하나만 발동이된기 때문에 92302가 먼저 매칭되면 끝이다.

해결책: 92302가 들어있는 원본 파일을 찾아서 직접 수정.
```bash
docker exec single-node-wazuh.manager-1 find / -path /proc -prune -o -name "*.xml" -print 2>/dev/null | xargs grep -l "sysmon_eid13_detections" 2>/dev/null
```

sysmon_eid13_detections 그룹도 어떤 파일에도 없다. 92302는 완전히 컴파일된 내장 룰이다.

결론 : Wazuh 4.9에서 92302는 바이러니에 내장이 되어있어서 overwrite도 안 되고 체이닝도 안됨

그래서 근본적으로 Wazuh 4.9에서 100220을 92302보다 먼저 평가되도록 만드어야한다. Wazuh는 룰 ID 순서가 아니고 파일 로드 순서로 평가.

ossec.conf에서 rules 로드 순서 확인:
```bash

docker exec single-node-wazuh.manager-1 grep -A2 "rule_dir\|rule_include\|ruleset" /var/ossec/etc/ossec.conf | head -30

```

- ruleset/rules — 기본 룰 (92302 여기 있음)
- etc/rules — 사용자 룰 (local_rules.xml 여기 있음)

사용자 룰이 나중에 로드돼서 같은 이벤트에 대해 기본 룰이 먼저 이겨버리고 있음.

ruleset/rules에서 sysmon 관련 파일 :
```bash

docker exec single-node-wazuh.manager-1 ls /var/ossec/ruleset/rules/ | grep -i sysmon

```

0860-sysmon_id_13.xml — 여기에 92302가 있음
```bash

docker exec single-node-wazuh.manager-1 grep -n "92302\|sysmon_eid13" /var/ossec/ruleset/rules/0860-sysmon_id_13.xml | head -10

```

0860-sysmon_id_13.xml line 31에 92302가 있음.

이 파일을 직접 수정해서 92302에 CurrentVersion.Run 조건 없는 이벤트는 통과시키고, 100220이 추가로 잡도록 만들기

아니면 더 간단하게 92302자체에 LEVEL을 올리고 조건 추가:
```bash
docker exec single-node-wazuh.manager-1 sed -n '25,50p' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml

```

92302의 부모는 92300

(if_sid>92300)

92300이 EventID 13 기본 룰이고, 92302는 reg.exe로 수정한 경우의 child이다.

100220을 92300의 child로 만들기. 92302와 동급으로 경쟁.

reg.exe가 아닌 다른 프로세스(powershell 등)로 Run 키 수정하면 92302 대신 100220이 발동해:
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << ENDOFFILE
<group name="sysmon,windows,">
  <rule id="100220" level="12">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.targetObject">CurrentVersion.Run</field>
    <description>T1547 - Run key modified</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
ENDOFFILE'
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'

```
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Test12" -Value "C:\evil.exe" -Force
```

Test12 실행확인
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test12\|100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

sudo 로그만 확인됨,

TEST12가 확인 안됨.

92300이 뭔지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -n "92300" /var/ossec/ruleset/rules/0860-sysmon_id_13.xml | head -5
```

92300은 level 0 - 이것 때문에 문제가 발생함.

파일 전체 구조 확인:
```bash
docker exec single-node-wazuh.manager-1 sed -n '1,35p' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```
```bash
[yhc@localhost single-node]$ docker exec single-node-wazuh.manager-1 sed -n '1,35p' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
<!--
  Copyright (C) 2015, Wazuh Inc.
-->
<!--
  Sysmon Event 13 rules ID: 92300 - 92399
-->
<group name="sysmon,sysmon_eid13_detections,windows,">
  <rule id="92300" level="0">
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
  <rule id="92302" level="6">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)reg\.exe</field>
    <options>no_full_log</options>
    <description>Registry entry to be executed on next logon was modified using command line application reg.exe</description>
[yhc@localhost single-node]$
```

92300이 sysmon_event_13 그룹을 받아서 level 0으로 처리하고, 92301/92302가 child로 발동하는 구조

sysmon_event_13 그룹이 핵심

100220을 sysmon_event_13 그룹의 child로 만들면 92300과 동급으로 경쟁

PowerShell로 트리거하면 92302(reg.exe 조건)가 안 걸리니까 100220이 발동해야 한다.
```bash
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << ENDOFFILE
<group name="sysmon,windows,">
  <rule id="100220" level="12">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion\\\\Run</field>
    <description>T1547 - Run key modified</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
</group>
ENDOFFILE'
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'

```
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Test13" -Value "C:\evil.exe" -Force
```

TEST13 실행확인
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test13\|100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

Test13이 아직 alerts에 없음.

sysmon_event_13 그룹이 어디에서 오는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -rn "sysmon_event_13" /var/ossec/ruleset/rules/ | head -5
```

sysmon_event_13 그룹은 0330-sysmon_rules.xml과 0595-win-sysmon_rules.xml에서 생성돼고, 0860이 그걸 if_group으로 참조하는 구조임.
```bash
docker restart single-node-wazuh.manager-1 && sleep 40

```

PowerShell로 Test14 트리거하고 확인
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Test14" -Value "C:\evil.exe" -Force
```
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test14\|100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

Test14도 없음. Windows agent가 재연결 됐는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "DESKTOP-5408CBA" /var/ossec/logs/alerts/alerts.json | tail -1 | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['timestamp'])"
```

08:41:01 — agent 연결

Test14 트리거가 안 됨.
```bash
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Test14" -Value "C:\evil.exe"

```
```bash
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Where-Object {$_.Id -eq 13 -and $_.Message -like "*Test14*"} | FL TimeCreated
```

Sysmon이 Test14 EventID 13을 캡처

근데 Wazuh alerts에 없음.
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test14" /var/ossec/logs/alerts/alerts.json | tail -3
```

Sysmon은 잡았는데 Wazuh alerts 에는 없음.

92300이 level0 라서 alerts에 안 찍히는 것.

100220이 발동하면 level12라서 찍혀야하는데 없음.

logall켜져 있는지 확인 - archives에 test14가 있는지 확인 :
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test14" /var/ossec/logs/archives/archives.json | tail -3
```

restart후 logall설정이 날아감.

ossec.conf volume 문제

지금 상황 정리하면:

1. logall 설정이 restart마다 리셋됨
1. 100220 룰이 발동하는지 확인 자체가 안 됨

다른 방법으로 확인 — wazuh-analysisd 로그에서 직접:
```bash
docker exec single-node-wazuh.manager-1 grep -a "100220" /var/ossec/logs/ossec.log | tail -5
```

현재 local_rules.xml 실제로 로드되었는지:
```bash
docker exec single-node-wazuh.manager-1 grep "logall" /var/ossec/etc/ossec.conf
```

현재 문제는

1. logall이 restart마다 리셋
1. 100220이 발동안함.

해결책은  — 0860-sysmon_id_13.xml 원본 파일을 직접 수정해서 100220 조건을 거기 넣기

우선 92302블록 정확한 라인 확인:
```bash
docker exec single-node-wazuh.manager-1 sed -n '28,40p' /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

그냥 docker cp 방식 :
```bash
docker cp single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml ~/0860-sysmon_id_13.xml
```

VS Code에서 92302 블록 바로 위에 이걸 삽입:
```bash
<rule id="100220" level="12">
  <if_sid>92300</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell</field>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion\\Run</field>
  <description>T1547 - Run key modified via PowerShell</description>
  <mitre><id>T1547.001</id></mitre>
  <group>persistence,registry,autorun,</group>
</rule>
```

저장 후 :
```bash
docker cp ~/0860-sysmon_id_13.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml
docker restart single-node-wazuh.manager-1 && sleep 40
```
```bash
docker cp single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml ~/0860-sysmon_id_13.xml
vi ~/0860-sysmon_id_13.xml
```

vi에서 /92302 입력 후 이동

거기 바로 위에 100220 블록 삽입
```bash
<rule id="100220" level="12">
    <if_sid>92300</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell</field>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion\\Run</field>
    <description>T1547 - Run key modified via PowerShell</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,registry,autorun,</group>
  </rule>
```
```bash
docker cp ~/0860-sysmon_id_13.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0860-sysmon_id_13.xml && docker restart single-node-wazuh.manager-1 && sleep 40
```
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Test15" -Value "C:\evil.exe" -Force
```

Test15 실행
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test15\|100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

sudo 로그

TEST15 alerts가 없음.
```bash
docker exec single-node-wazuh.manager-1 grep -n "100220" /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```
```bash
docker exec single-node-wazuh.manager-1 grep -n "100220" /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

00220이 line 31에 들어가 있지만, Test15가 alerts에 없음

agent가 Test15를 실제로 보냈는지 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "Test15" /var/ossec/logs/alerts/alerts.json
```

windows에서 angent로그 확인:
```bash
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 5
```

Agent 방금 재연결 — 17:55:59 Connected, 17:56:00 Agent is now online. Test15는 연결 끊겼을 때 트리거해서 못 보넨 것이다.
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Test15" -Value "C:\evil.exe" -Force

```
```bash
docker exec single-node-wazuh.manager-1 grep -a "100220\|Test15" /var/ossec/logs/alerts/alerts.json | tail -3
```

또 sudo만. Test15 자체가 alerts에 없음 .

windows에서 실행이 되었는지 확인:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Where-Object {$_.Id -eq 13 -and $_.Message -like "*Test15*"} | FL TimeCreated
```

Sysmon도 Test15를 못잡음.

New-ItemProperty가 이미 존재하는 키라서 실패.

이미 Test15가 있어서 -Force가 있어도 EventID 13이 생성 안되었을 수 있음.
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilPS1" -Value "C:\evil.exe" -Force

```

EvilPS1 실행되었음.
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilPS1\|100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

EvilPS1도 없음.

Sysmon이 잡았는지 확인:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.Id -eq 13 -and $_.Message -like "*EvilPS1*"} | FL TimeCreated
```

Sysmon config exclude 룰에 PowerShell이 걸려있는지 확인:
```bash
C:\Windows\sysmon64.exe -c | Select-String "powershell\|exclude" -CaseSensitive:$false
```

Sysmon config 정상 RegistryEvent onmatch: include에 CurrentVersion\Run 이 있음.

EvilPS1이 Sysmon에 안 잡힌 이유 — 이미 같은 키가 존재해서 SetValue가 아니라 그냥 무시됐을 수 있음.
```bash
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilPS1" -ErrorAction SilentlyContinue
Start-Sleep 1
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilPS2" -Value "C:\evil.exe" -Force
Start-Sleep 2
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Where-Object {$_.Id -eq 13 -and $_.Message -like "*EvilPS2*"} | FL TimeCreated
```

Sysmon이 EvilPS2 EventID 13을 잡음
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilPS2\|100220" /var/ossec/logs/alerts/alerts.json | tail -3
```

아직도sudo만 잡힘

Wazuh가 이 이벤트를 92300(level 0)으로 처리하고 alerts에 안 남기고 , 100220이 발동해도 확인할 방법이 없음 — archives.json이 없기때문이다.

해결책:
```bash
docker exec single-node-wazuh.manager-1 bash -c "python3 -c \"
with open('/var/ossec/etc/ossec.conf', 'r') as f:
    c = f.read()
c = c.replace('<logall>no</logall>', '<logall>yes</logall>')
c = c.replace('<logall_json>no</logall_json>', '<logall_json>yes</logall_json>')
with open('/var/ossec/etc/ossec.conf', 'w') as f:
    f.write(c)
\""
```

restart 없이 HUP만 :
```bash
docker exec single-node-wazuh.manager-1 bash -c 'kill -HUP $(pgrep wazuh-analysisd)'
```

logall이 켜지면 100220이 발동하는지 아닌지 archives에서 확인 가능.

restart 안 하면 설정 안 날아감.

EvilPS2는 Sysmon이 잡음.

문제는 Wazuh alerts에 안 찍히고 있는 것. 다음을 동시에 구동시킴.
```bash
docker exec single-node-wazuh.manager-1 bash -c 'tail -f /var/ossec/logs/alerts/alerts.json' &
```
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilPS3" -Value "C:\evil.exe" -Force
```
```bash
[yhc@localhost ~]$ docker exec single-node-wazuh.manager-1 bash -c 'tail -f /var/ossec/logs/alerts/alerts.json' &
[1] 216434
[yhc@localhost ~]$ {"timestamp":"2026-04-24T08:51:08.493+0000","rule":{"level":5,"description":"Name resolution for the name wpad timed out","id":"61109","firedtimes":2,"mail":false,"groups":["windows","windows_system"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777020668.3391418","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-DNS-Client","providerGuid":"{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}","eventID":"1014","version":"0","level":"3","task":"1014","opcode":"0","keywords":"0x4000000010000000","systemTime":"2026-04-24T08:51:07.0783404Z","eventRecordID":"1260","processID":"1880","threadID":"10672","channel":"System","computer":"DESKTOP-5408CBA","severityValue":"WARNING","message":"\"구성된 DNS 서버 중 응답하는 서버가 없어 wpad 이름을 확인하는 동안 시간이 초과되었습니다.\""},"eventdata":{"queryName":"wpad","addressLength":"128","address":"02000000C0A8BE02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T08:51:08.979+0000","rule":{"level":5,"description":"unix_chkpwd: Password check failed.","id":"5557","mitre":{"id":["T1110.001"],"tactic":["Credential Access"],"technique":["Password Guessing"]},"firedtimes":2,"mail":false,"groups":["pam","syslog","authentication_failed"],"pci_dss":["10.2.4","10.2.5"],"gpg13":["4.3"],"gdpr":["IV_35.7.d","IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7"],"tsc":["CC6.1","CC6.8","CC7.2","CC7.3"]},"agent":{"id":"001","name":"localhost.localdomain","ip":"127.0.0.1"},"manager":{"name":"wazuh.manager"},"id":"1777020668.3393460","full_log":"Apr 24 17:51:08 localhost unix_chkpwd[213822]: password check failed for user (yhc)","predecoder":{"program_name":"unix_chkpwd","timestamp":"Apr 24 17:51:08","hostname":"localhost"},"decoder":{"name":"unix_chkpwd"},"data":{"srcuser":"yhc"},"location":"/var/log/secure"}
{"timestamp":"2026-04-24T08:51:09.020+0000","rule":{"level":5,"description":"syslog: User authentication failure.","id":"2501","firedtimes":2,"mail":false,"groups":["syslog","access_control","authentication_failed"],"pci_dss":["10.2.4","10.2.5"],"gpg13":["7.8"],"gdpr":["IV_35.7.d","IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7"],"tsc":["CC6.1","CC6.8","CC7.2","CC7.3"]},"agent":{"id":"001","name":"localhost.localdomain","ip":"127.0.0.1"},"manager":{"name":"wazuh.manager"},"id":"1777020669.3393897","full_log":"Apr 24 17:51:08 localhost gdm-password]: pam_unix(gdm-password:auth): authentication failure; logname=yhc uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=yhc","predecoder":{"timestamp":"Apr 24 17:51:08","hostname":"localhost"},"decoder":{},"location":"/var/log/secure"}
{"timestamp":"2026-04-24T08:56:01.725+0000","rule":{"level":3,"description":"Windows Logon Success","id":"60106","mitre":{"id":["T1078"],"tactic":["Defense Evasion","Persistence","Privilege Escalation","Initial Access"],"technique":["Valid Accounts"]},"firedtimes":1,"mail":false,"groups":["windows","windows_security","authentication_success"],"pci_dss":["10.2.5"],"gpg13":["7.1","7.2"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777020961.3394419","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2026-04-24T08:56:00.2264195Z","eventRecordID":"16027","processID":"692","threadID":"4696","channel":"Security","computer":"DESKTOP-5408CBA","severityValue":"AUDIT_SUCCESS","message":"\"계정이 성공적으로 로그온되었습니다.\r\n\r\n주체:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tDESKTOP-5408CBA$\r\n\t계정 도메인:\t\tWORKGROUP\r\n\t로그온 ID:\t\t0x3E7\r\n\r\n로그온 정보:\r\n\t로그온 유형:\t\t5\r\n\t제한된 관리 모드:\t-\r\n\t가상 계정:\t\t아니요\r\n\t상승된 토큰:\t\t예\r\n\r\n가장 수준:\t\t가장\r\n\r\n새 로그온:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tSYSTEM\r\n\t계정 도메인:\t\tNT AUTHORITY\r\n\t로그온 ID:\t\t0x3E7\r\n\t연결된 로그온 ID:\t\t0x0\r\n\t네트워크 계정 이름:\t-\r\n\t네트워크 계정 도메인:\t-\r\n\t로그온 GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\n프로세스 정보:\r\n\t프로세스 ID:\t\t0x29c\r\n\t프로세스 이름:\t\tC:\\Windows\\System32\\services.exe\r\n\r\n네트워크 정보:\r\n\t워크스테이션 이름:\t-\r\n\t원본 네트워크 주소:\t-\r\n\t원본 포트:\t\t-\r\n\r\n인증 세부 정보:\r\n\t로그온 프로세스:\t\tAdvapi  \r\n\t인증 패키지:\tNegotiate\r\n\t전송된 서비스:\t-\r\n\t패키지 이름(NTLM 전용):\t-\r\n\t키 길이:\t\t0\r\n\r\n이 이벤트는 로그온 세션이 만들어질 때 액세스했던 컴퓨터에 생성됩니다.\r\n\r\n주체 필드는 로그온을 요청한 로컬 시스템의 계정을 나타냅니다. 이것은 주로 서버 서비스와 같은 서비스 또는 Winlogon.exe나 Services.exe와 같은 로컬 프로세스입니다.\r\n\r\n로그온 유형 필드는 발생한 로그온의 종류를 나타냅니다. 가장 일반적인 유형은 2(대화형)와 3(네트워크)입니다.\r\n\r\n새 로그온 필드는 새 로그온을 만든 계정, 즉 로그온된 계정을 나타냅니다.\r\n\r\n네트워크 필드는 원격 로그온 요청이 시작된 위치를 나타냅니다. 워크스테이션 이름은 항상 사용할 수 있는 것은 아니며 어떤 경우에는 비워 둘 수 있습니다.\r\n\r\n가장 수준 필드는 로그온 세션의 프로세스에서 가장할 수 있는 범위를 나타냅니다.\r\n\r\n인증 정보 필드는 이 특정 로그온 요청에 대한 자세한 정보를 제공합니다.\r\n\t- 로그온 GUID는 이 이벤트를 KDC 이벤트와 연관시키는 데 사용할 수 있는 고유 식별자입니다.\r\n\t - 전송된 서비스는 이 로그온 요청과 관련된 중간 서비스를 나타냅니다.\r\n\t - 패키지 이름은 NTLM 프로토콜 간에 사용된 하위 프로토콜을 나타냅니다.\r\n\t - 키 길이는 생성된 세션 키의 길이를 나타냅니다. 이 값은 요청된 세션 키가 없는 경우 0이 됩니다.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-5408CBA$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-18","targetUserName":"SYSTEM","targetDomainName":"NT AUTHORITY","targetLogonId":"0x3e7","logonType":"5","logonProcessName":"Advapi","authenticationPackageName":"Negotiate","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x29c","processName":"C:\\\\Windows\\\\System32\\\\services.exe","impersonationLevel":"%%1833","virtualAccount":"%%1843","targetLinkedLogonId":"0x0","elevatedToken":"%%1842"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T08:56:01.754+0000","rule":{"level":3,"description":"Windows Logon Success","id":"60106","mitre":{"id":["T1078"],"tactic":["Defense Evasion","Persistence","Privilege Escalation","Initial Access"],"technique":["Valid Accounts"]},"firedtimes":2,"mail":false,"groups":["windows","windows_security","authentication_success"],"pci_dss":["10.2.5"],"gpg13":["7.1","7.2"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777020961.3402174","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2026-04-24T08:56:00.6134051Z","eventRecordID":"16029","processID":"692","threadID":"4696","channel":"Security","computer":"DESKTOP-5408CBA","severityValue":"AUDIT_SUCCESS","message":"\"계정이 성공적으로 로그온되었습니다.\r\n\r\n주체:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tDESKTOP-5408CBA$\r\n\t계정 도메인:\t\tWORKGROUP\r\n\t로그온 ID:\t\t0x3E7\r\n\r\n로그온 정보:\r\n\t로그온 유형:\t\t5\r\n\t제한된 관리 모드:\t-\r\n\t가상 계정:\t\t아니요\r\n\t상승된 토큰:\t\t예\r\n\r\n가장 수준:\t\t가장\r\n\r\n새 로그온:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tSYSTEM\r\n\t계정 도메인:\t\tNT AUTHORITY\r\n\t로그온 ID:\t\t0x3E7\r\n\t연결된 로그온 ID:\t\t0x0\r\n\t네트워크 계정 이름:\t-\r\n\t네트워크 계정 도메인:\t-\r\n\t로그온 GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\n프로세스 정보:\r\n\t프로세스 ID:\t\t0x29c\r\n\t프로세스 이름:\t\tC:\\Windows\\System32\\services.exe\r\n\r\n네트워크 정보:\r\n\t워크스테이션 이름:\t-\r\n\t원본 네트워크 주소:\t-\r\n\t원본 포트:\t\t-\r\n\r\n인증 세부 정보:\r\n\t로그온 프로세스:\t\tAdvapi  \r\n\t인증 패키지:\tNegotiate\r\n\t전송된 서비스:\t-\r\n\t패키지 이름(NTLM 전용):\t-\r\n\t키 길이:\t\t0\r\n\r\n이 이벤트는 로그온 세션이 만들어질 때 액세스했던 컴퓨터에 생성됩니다.\r\n\r\n주체 필드는 로그온을 요청한 로컬 시스템의 계정을 나타냅니다. 이것은 주로 서버 서비스와 같은 서비스 또는 Winlogon.exe나 Services.exe와 같은 로컬 프로세스입니다.\r\n\r\n로그온 유형 필드는 발생한 로그온의 종류를 나타냅니다. 가장 일반적인 유형은 2(대화형)와 3(네트워크)입니다.\r\n\r\n새 로그온 필드는 새 로그온을 만든 계정, 즉 로그온된 계정을 나타냅니다.\r\n\r\n네트워크 필드는 원격 로그온 요청이 시작된 위치를 나타냅니다. 워크스테이션 이름은 항상 사용할 수 있는 것은 아니며 어떤 경우에는 비워 둘 수 있습니다.\r\n\r\n가장 수준 필드는 로그온 세션의 프로세스에서 가장할 수 있는 범위를 나타냅니다.\r\n\r\n인증 정보 필드는 이 특정 로그온 요청에 대한 자세한 정보를 제공합니다.\r\n\t- 로그온 GUID는 이 이벤트를 KDC 이벤트와 연관시키는 데 사용할 수 있는 고유 식별자입니다.\r\n\t - 전송된 서비스는 이 로그온 요청과 관련된 중간 서비스를 나타냅니다.\r\n\t - 패키지 이름은 NTLM 프로토콜 간에 사용된 하위 프로토콜을 나타냅니다.\r\n\t - 키 길이는 생성된 세션 키의 길이를 나타냅니다. 이 값은 요청된 세션 키가 없는 경우 0이 됩니다.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-5408CBA$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-18","targetUserName":"SYSTEM","targetDomainName":"NT AUTHORITY","targetLogonId":"0x3e7","logonType":"5","logonProcessName":"Advapi","authenticationPackageName":"Negotiate","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x29c","processName":"C:\\\\Windows\\\\System32\\\\services.exe","impersonationLevel":"%%1833","virtualAccount":"%%1843","targetLinkedLogonId":"0x0","elevatedToken":"%%1842"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T08:56:03.446+0000","rule":{"level":3,"description":"Windows Logon Success","id":"60106","mitre":{"id":["T1078"],"tactic":["Defense Evasion","Persistence","Privilege Escalation","Initial Access"],"technique":["Valid Accounts"]},"firedtimes":3,"mail":false,"groups":["windows","windows_security","authentication_success"],"pci_dss":["10.2.5"],"gpg13":["7.1","7.2"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777020963.3409929","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2026-04-24T08:56:02.0587419Z","eventRecordID":"16031","processID":"692","threadID":"4696","channel":"Security","computer":"DESKTOP-5408CBA","severityValue":"AUDIT_SUCCESS","message":"\"계정이 성공적으로 로그온되었습니다.\r\n\r\n주체:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tDESKTOP-5408CBA$\r\n\t계정 도메인:\t\tWORKGROUP\r\n\t로그온 ID:\t\t0x3E7\r\n\r\n로그온 정보:\r\n\t로그온 유형:\t\t5\r\n\t제한된 관리 모드:\t-\r\n\t가상 계정:\t\t아니요\r\n\t상승된 토큰:\t\t예\r\n\r\n가장 수준:\t\t가장\r\n\r\n새 로그온:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tSYSTEM\r\n\t계정 도메인:\t\tNT AUTHORITY\r\n\t로그온 ID:\t\t0x3E7\r\n\t연결된 로그온 ID:\t\t0x0\r\n\t네트워크 계정 이름:\t-\r\n\t네트워크 계정 도메인:\t-\r\n\t로그온 GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\n프로세스 정보:\r\n\t프로세스 ID:\t\t0x29c\r\n\t프로세스 이름:\t\tC:\\Windows\\System32\\services.exe\r\n\r\n네트워크 정보:\r\n\t워크스테이션 이름:\t-\r\n\t원본 네트워크 주소:\t-\r\n\t원본 포트:\t\t-\r\n\r\n인증 세부 정보:\r\n\t로그온 프로세스:\t\tAdvapi  \r\n\t인증 패키지:\tNegotiate\r\n\t전송된 서비스:\t-\r\n\t패키지 이름(NTLM 전용):\t-\r\n\t키 길이:\t\t0\r\n\r\n이 이벤트는 로그온 세션이 만들어질 때 액세스했던 컴퓨터에 생성됩니다.\r\n\r\n주체 필드는 로그온을 요청한 로컬 시스템의 계정을 나타냅니다. 이것은 주로 서버 서비스와 같은 서비스 또는 Winlogon.exe나 Services.exe와 같은 로컬 프로세스입니다.\r\n\r\n로그온 유형 필드는 발생한 로그온의 종류를 나타냅니다. 가장 일반적인 유형은 2(대화형)와 3(네트워크)입니다.\r\n\r\n새 로그온 필드는 새 로그온을 만든 계정, 즉 로그온된 계정을 나타냅니다.\r\n\r\n네트워크 필드는 원격 로그온 요청이 시작된 위치를 나타냅니다. 워크스테이션 이름은 항상 사용할 수 있는 것은 아니며 어떤 경우에는 비워 둘 수 있습니다.\r\n\r\n가장 수준 필드는 로그온 세션의 프로세스에서 가장할 수 있는 범위를 나타냅니다.\r\n\r\n인증 정보 필드는 이 특정 로그온 요청에 대한 자세한 정보를 제공합니다.\r\n\t- 로그온 GUID는 이 이벤트를 KDC 이벤트와 연관시키는 데 사용할 수 있는 고유 식별자입니다.\r\n\t - 전송된 서비스는 이 로그온 요청과 관련된 중간 서비스를 나타냅니다.\r\n\t - 패키지 이름은 NTLM 프로토콜 간에 사용된 하위 프로토콜을 나타냅니다.\r\n\t - 키 길이는 생성된 세션 키의 길이를 나타냅니다. 이 값은 요청된 세션 키가 없는 경우 0이 됩니다.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-5408CBA$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-18","targetUserName":"SYSTEM","targetDomainName":"NT AUTHORITY","targetLogonId":"0x3e7","logonType":"5","logonProcessName":"Advapi","authenticationPackageName":"Negotiate","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x29c","processName":"C:\\\\Windows\\\\System32\\\\services.exe","impersonationLevel":"%%1833","virtualAccount":"%%1843","targetLinkedLogonId":"0x0","elevatedToken":"%%1842"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T08:56:07.081+0000","rule":{"level":3,"description":"Wazuh server started.","id":"502","firedtimes":1,"mail":false,"groups":["ossec"],"pci_dss":["10.6.1"],"gpg13":["10.1"],"gdpr":["IV_35.7.d"],"hipaa":["164.312.b"],"nist_800_53":["AU.6"],"tsc":["CC7.2","CC7.3"]},"agent":{"id":"000","name":"wazuh.manager"},"manager":{"name":"wazuh.manager"},"id":"1777020967.3417684","full_log":"ossec: Manager started.","decoder":{"name":"ossec"},"location":"wazuh-monitord"}
{"timestamp":"2026-04-24T09:01:49.848+0000","rule":{"level":5,"description":"Name resolution for the name wpad timed out","id":"61109","firedtimes":1,"mail":false,"groups":["windows","windows_system"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777021309.3417931","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-DNS-Client","providerGuid":"{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}","eventID":"1014","version":"0","level":"3","task":"1014","opcode":"0","keywords":"0x4000000010000000","systemTime":"2026-04-24T09:01:48.4223678Z","eventRecordID":"1261","processID":"1880","threadID":"8820","channel":"System","computer":"DESKTOP-5408CBA","severityValue":"WARNING","message":"\"구성된 DNS 서버 중 응답하는 서버가 없어 wpad 이름을 확인하는 동안 시간이 초과되었습니다.\""},"eventdata":{"queryName":"wpad","addressLength":"128","address":"02000000C0A8BE02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T09:03:18.672+0000","rule":{"level":3,"description":"Windows Logon Success","id":"60106","mitre":{"id":["T1078"],"tactic":["Defense Evasion","Persistence","Privilege Escalation","Initial Access"],"technique":["Valid Accounts"]},"firedtimes":1,"mail":false,"groups":["windows","windows_security","authentication_success"],"pci_dss":["10.2.5"],"gpg13":["7.1","7.2"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777021398.3419971","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2026-04-24T09:03:14.4474922Z","eventRecordID":"16033","processID":"692","threadID":"1952","channel":"Security","computer":"DESKTOP-5408CBA","severityValue":"AUDIT_SUCCESS","message":"\"계정이 성공적으로 로그온되었습니다.\r\n\r\n주체:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tDESKTOP-5408CBA$\r\n\t계정 도메인:\t\tWORKGROUP\r\n\t로그온 ID:\t\t0x3E7\r\n\r\n로그온 정보:\r\n\t로그온 유형:\t\t5\r\n\t제한된 관리 모드:\t-\r\n\t가상 계정:\t\t아니요\r\n\t상승된 토큰:\t\t예\r\n\r\n가장 수준:\t\t가장\r\n\r\n새 로그온:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tSYSTEM\r\n\t계정 도메인:\t\tNT AUTHORITY\r\n\t로그온 ID:\t\t0x3E7\r\n\t연결된 로그온 ID:\t\t0x0\r\n\t네트워크 계정 이름:\t-\r\n\t네트워크 계정 도메인:\t-\r\n\t로그온 GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\n프로세스 정보:\r\n\t프로세스 ID:\t\t0x29c\r\n\t프로세스 이름:\t\tC:\\Windows\\System32\\services.exe\r\n\r\n네트워크 정보:\r\n\t워크스테이션 이름:\t-\r\n\t원본 네트워크 주소:\t-\r\n\t원본 포트:\t\t-\r\n\r\n인증 세부 정보:\r\n\t로그온 프로세스:\t\tAdvapi  \r\n\t인증 패키지:\tNegotiate\r\n\t전송된 서비스:\t-\r\n\t패키지 이름(NTLM 전용):\t-\r\n\t키 길이:\t\t0\r\n\r\n이 이벤트는 로그온 세션이 만들어질 때 액세스했던 컴퓨터에 생성됩니다.\r\n\r\n주체 필드는 로그온을 요청한 로컬 시스템의 계정을 나타냅니다. 이것은 주로 서버 서비스와 같은 서비스 또는 Winlogon.exe나 Services.exe와 같은 로컬 프로세스입니다.\r\n\r\n로그온 유형 필드는 발생한 로그온의 종류를 나타냅니다. 가장 일반적인 유형은 2(대화형)와 3(네트워크)입니다.\r\n\r\n새 로그온 필드는 새 로그온을 만든 계정, 즉 로그온된 계정을 나타냅니다.\r\n\r\n네트워크 필드는 원격 로그온 요청이 시작된 위치를 나타냅니다. 워크스테이션 이름은 항상 사용할 수 있는 것은 아니며 어떤 경우에는 비워 둘 수 있습니다.\r\n\r\n가장 수준 필드는 로그온 세션의 프로세스에서 가장할 수 있는 범위를 나타냅니다.\r\n\r\n인증 정보 필드는 이 특정 로그온 요청에 대한 자세한 정보를 제공합니다.\r\n\t- 로그온 GUID는 이 이벤트를 KDC 이벤트와 연관시키는 데 사용할 수 있는 고유 식별자입니다.\r\n\t - 전송된 서비스는 이 로그온 요청과 관련된 중간 서비스를 나타냅니다.\r\n\t - 패키지 이름은 NTLM 프로토콜 간에 사용된 하위 프로토콜을 나타냅니다.\r\n\t - 키 길이는 생성된 세션 키의 길이를 나타냅니다. 이 값은 요청된 세션 키가 없는 경우 0이 됩니다.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-5408CBA$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-18","targetUserName":"SYSTEM","targetDomainName":"NT AUTHORITY","targetLogonId":"0x3e7","logonType":"5","logonProcessName":"Advapi","authenticationPackageName":"Negotiate","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x29c","processName":"C:\\\\Windows\\\\System32\\\\services.exe","impersonationLevel":"%%1833","virtualAccount":"%%1843","targetLinkedLogonId":"0x0","elevatedToken":"%%1842"}}},"location":"EventChannel"}
{"timestamp":"2026-04-24T09:03:18.680+0000","rule":{"level":3,"description":"Windows Logon Success","id":"60106","mitre":{"id":["T1078"],"tactic":["Defense Evasion","Persistence","Privilege Escalation","Initial Access"],"technique":["Valid Accounts"]},"firedtimes":2,"mail":false,"groups":["windows","windows_security","authentication_success"],"pci_dss":["10.2.5"],"gpg13":["7.1","7.2"],"gdpr":["IV_32.2"],"hipaa":["164.312.b"],"nist_800_53":["AU.14","AC.7"],"tsc":["CC6.8","CC7.2","CC7.3"]},"agent":{"id":"003","name":"DESKTOP-5408CBA","ip":"192.168.190.131"},"manager":{"name":"wazuh.manager"},"id":"1777021398.3427726","decoder":{"name":"windows_eventchannel"},"data":{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","providerGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","eventID":"4624","version":"2","level":"0","task":"12544","opcode":"0","keywords":"0x8020000000000000","systemTime":"2026-04-24T09:03:14.6376931Z","eventRecordID":"16035","processID":"692","threadID":"1952","channel":"Security","computer":"DESKTOP-5408CBA","severityValue":"AUDIT_SUCCESS","message":"\"계정이 성공적으로 로그온되었습니다.\r\n\r\n주체:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tDESKTOP-5408CBA$\r\n\t계정 도메인:\t\tWORKGROUP\r\n\t로그온 ID:\t\t0x3E7\r\n\r\n로그온 정보:\r\n\t로그온 유형:\t\t5\r\n\t제한된 관리 모드:\t-\r\n\t가상 계정:\t\t아니요\r\n\t상승된 토큰:\t\t예\r\n\r\n가장 수준:\t\t가장\r\n\r\n새 로그온:\r\n\t보안 ID:\t\tS-1-5-18\r\n\t계정 이름:\t\tSYSTEM\r\n\t계정 도메인:\t\tNT AUTHORITY\r\n\t로그온 ID:\t\t0x3E7\r\n\t연결된 로그온 ID:\t\t0x0\r\n\t네트워크 계정 이름:\t-\r\n\t네트워크 계정 도메인:\t-\r\n\t로그온 GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\n프로세스 정보:\r\n\t프로세스 ID:\t\t0x29c\r\n\t프로세스 이름:\t\tC:\\Windows\\System32\\services.exe\r\n\r\n네트워크 정보:\r\n\t워크스테이션 이름:\t-\r\n\t원본 네트워크 주소:\t-\r\n\t원본 포트:\t\t-\r\n\r\n인증 세부 정보:\r\n\t로그온 프로세스:\t\tAdvapi  \r\n\t인증 패키지:\tNegotiate\r\n\t전송된 서비스:\t-\r\n\t패키지 이름(NTLM 전용):\t-\r\n\t키 길이:\t\t0\r\n\r\n이 이벤트는 로그온 세션이 만들어질 때 액세스했던 컴퓨터에 생성됩니다.\r\n\r\n주체 필드는 로그온을 요청한 로컬 시스템의 계정을 나타냅니다. 이것은 주로 서버 서비스와 같은 서비스 또는 Winlogon.exe나 Services.exe와 같은 로컬 프로세스입니다.\r\n\r\n로그온 유형 필드는 발생한 로그온의 종류를 나타냅니다. 가장 일반적인 유형은 2(대화형)와 3(네트워크)입니다.\r\n\r\n새 로그온 필드는 새 로그온을 만든 계정, 즉 로그온된 계정을 나타냅니다.\r\n\r\n네트워크 필드는 원격 로그온 요청이 시작된 위치를 나타냅니다. 워크스테이션 이름은 항상 사용할 수 있는 것은 아니며 어떤 경우에는 비워 둘 수 있습니다.\r\n\r\n가장 수준 필드는 로그온 세션의 프로세스에서 가장할 수 있는 범위를 나타냅니다.\r\n\r\n인증 정보 필드는 이 특정 로그온 요청에 대한 자세한 정보를 제공합니다.\r\n\t- 로그온 GUID는 이 이벤트를 KDC 이벤트와 연관시키는 데 사용할 수 있는 고유 식별자입니다.\r\n\t - 전송된 서비스는 이 로그온 요청과 관련된 중간 서비스를 나타냅니다.\r\n\t - 패키지 이름은 NTLM 프로토콜 간에 사용된 하위 프로토콜을 나타냅니다.\r\n\t - 키 길이는 생성된 세션 키의 길이를 나타냅니다. 이 값은 요청된 세션 키가 없는 경우 0이 됩니다.\""},"eventdata":{"subjectUserSid":"S-1-5-18","subjectUserName":"DESKTOP-5408CBA$","subjectDomainName":"WORKGROUP","subjectLogonId":"0x3e7","targetUserSid":"S-1-5-18","targetUserName":"SYSTEM","targetDomainName":"NT AUTHORITY","targetLogonId":"0x3e7","logonType":"5","logonProcessName":"Advapi","authenticationPackageName":"Negotiate","logonGuid":"{00000000-0000-0000-0000-000000000000}","keyLength":"0","processId":"0x29c","processName":"C:\\\\Windows\\\\System32\\\\services.exe","impersonationLevel":"%%1833","virtualAccount":"%%1843","targetLinkedLogonId":"0x0","elevatedToken":"%%1842"}}},"location":"EventChannel"}
```

alerts 실시간으로 들어오고 있고, Windows 이벤트도 오고 있음. 근데 EventID 13이 없음.

지금 tail -f 살아있는 상태에서 Windows에서 트리거
```bash
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilPS3" -Value "C:\evil.exe" -Force
```

하지만 Rocky에서는 아무런 변화가 없음.

EventID 13이 agent에서 manager로 전송 자체가 안 되고 있음.

Sysmon은 잡는데 agent가 안 보내는 것.

Windows agent ossec.conf에서 Sysmon 채널 설정 확인:
```bash
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String -Pattern "Sysmon|eventchannel" -Context 2,2
```

결과
```bash
PS C:\Windows\system32> New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilPS3" -Value "C:\evil.exe" -Force
EvilPS3      : C:\evil.exe
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion
PSChildName  : Run
PSDrive      : HKCU
PSProvider   : Microsoft.PowerShell.Core\Registry
PS C:\Windows\system32> Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String -Pattern "Sysmon|eventchannel" -Context 2,2
    <localfile>
      <location>Application</location>
>     <log_format>eventchannel</log_format>
    </localfile>
    <localfile>
      <location>Security</location>
>     <log_format>eventchannel</log_format>
      <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and
        EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and
    <localfile>
      <location>System</location>
>     <log_format>eventchannel</log_format>
    </localfile>
    </logging>
  <localfile>
>   <location>Microsoft-Windows-Sysmon/Operational</location>
>   <log_format>eventchannel</log_format>
  </localfile>
  </ossec_config>
PS C:\Windows\system32>
```

Sysmon 설정은 있지만, EvilPS3 트리거 했는데 Rocky tail -f에는 아무것도 없음.

agent가 EventID 13을 필터링하고 있음.

Security 채널에 query 필터가 있는 것처럼 Sysmon에도 있는지 전체 확인:
```bash
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String -Pattern "Sysmon" -Context 5,5
```

결과
```bash
PS C:\Windows\system32> Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String -Pattern "Sysmon" -Context 5,5
    <!-- Choose between plain or json format (or both) for internal logs -->
    <logging>
      <log_format>plain</log_format>
    </logging>
  <localfile>
>   <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  </ossec_config>
  <!-- END of Default Configuration. -->
PS C:\Windows\system32>
```

필터가 없음

agent가 실제로 EventID13 을 받고 있는지 Windows 이벤트 뷰어 레벨에서 확인.

agetn가 eventchannel을 읽을 때 bookmark 위치 문제일 수도 있음.
```bash
Restart-Service -Name "Wazuh" -Force
Start-Sleep 10
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EvilPS4" -Value "C:\evil.exe" -Force
```

결과
```bash
9956\r\nP7: 00001c20\r\nP8: c0000005\r\nP9: 00000008\r\nP10: \r\n\r\n첨부 파일:\r\n\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER99DD.tmp.dmp\r\n\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER9AD8.tmp.WERInternalMetadata.xml\r\n\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER9B28.tmp.xml\r\n\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER9B26.tmp.csv\r\n\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER9B46.tmp.txt\r\n\r\n이 파일은 다음에서 사용할 수 있습니다.\r\n\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\AppCrash_wazuh-agent.exe_ccdd5fa2cbeb5e4c0ac7b90543886bbdf7d94a0_3931ca8a_bc9c964c-cbbd-49ef-a5c5-45ad1ca7a1c1\r\n\r\n분석 기호: \r\n해결 방법 재확인: 0\r\n보고서 ID: a2876b6f-9f4a-4774-8fcc-dbb013193a5d\r\n보고서 상태: 268566528\r\n해시된 패킷: f8ca1f12935573aab76b1efd6b38e43a\r\nCab Guid: 0\""},"eventdata":{"data":"1687476559154832442, 5, BEX, 사용할 수 없음, 0, wazuh-agent.exe, 4.9.0.0, 66d199cc, syscollector.dll_unloaded, 4.9.0.0, 66d19956, 00001c20, c0000005, 00000008,   \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER99DD.tmp.dmp  \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER9AD8.tmp.WERInternalMetadata.xml  \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER9B28.tmp.xml  \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER9B26.tmp.csv  \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER9B46.tmp.txt, \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\ReportArchive\\\\AppCrash_wazuh-agent.exe_ccdd5fa2cbeb5e4c0ac7b90543886bbdf7d94a0_3931ca8a_bc9c964c-cbbd-49ef-a5c5-45ad1ca7a1c1, 0, a2876b6f-9f4a-4774-8fcc-dbb013193a5d, 268566528, f8ca1f12935573aab76b1efd6b38e43a, 0"}}},"location":"EventChannel"}
```

wazuh-agent.exe가 크래시함, syscollector.dll_unloaded  -agent가 죽으면서 Sysmon이벤트를 못보내고 있음.

Windows에서 agent 상태 확인:
```bash
Get-Service -Name "Wazuh"
```

결과
```bash
EvilPS4      : C:\evil.exe
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion
PSChildName  : Run
PSDrive      : HKCU
PSProvider   : Microsoft.PowerShell.Core\Registry
PS C:\Windows\system32> Get-Service -Name "Wazuh"
Status   Name               DisplayName
------   ----               -----------
Running  WazuhSvc           Wazuh
PS C:\Windows\system32>
```

서비스는 Running

크래시 후 재시작 됨

결과
```bash
:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER9B46.tmp.txt\r\n\r\n이 파일은 다음에서 사용할 수 있습니다.\r\n\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\AppCrash_wazuh-agent.exe_ccdd5fa2cbeb5e4c0ac7b90543886bbdf7d94a0_3931ca8a_bc9c964c-cbbd-49ef-a5c5-45ad1ca7a1c1\r\n\r\n분석 기호: \r\n해결 방법 재확인: 0\r\n보고서 ID: a2876b6f-9f4a-4774-8fcc-dbb013193a5d\r\n보고서 상태: 268566528\r\n해시된 패킷: f8ca1f12935573aab76b1efd6b38e43a\r\nCab Guid: 0\""},"eventdata":{"data":"1687476559154832442, 5, BEX, 사용할 수 없음, 0, wazuh-agent.exe, 4.9.0.0, 66d199cc, syscollector.dll_unloaded, 4.9.0.0, 66d19956, 00001c20, c0000005, 00000008,   \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER99DD.tmp.dmp  \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER9AD8.tmp.WERInternalMetadata.xml  \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER9B28.tmp.xml  \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER9B26.tmp.csv  \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\Temp\\\\WER9B46.tmp.txt, \\\\\\\\?\\\\C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\WER\\\\ReportArchive\\\\AppCrash_wazuh-agent.exe_ccdd5fa2cbeb5e4c0ac7b90543886bbdf7d94a0_3931ca8a_bc9c964c-cbbd-49ef-a5c5-45ad1ca7a1c1, 0, a2876b6f-9f4a-4774-8fcc-dbb013193a5d, 268566528, f8ca1f12935573aab76b1efd6b38e43a, 0"}}},"location":"EventChannel"}
```

EvilPS4 관련 이벤트는 없고 agent 크래시 이벤트만 들어오고 있음.

syscollector.dll_unloaded 크래시는 Wazuh 4.9.0 agent의 알려진 버그

agent가 주기적으로 죽었다가 재시작되면서 그 사이에 발생한 Sysmon 이벤트를 놓치는 현상

agent 재설치 (4.9.1 이상) — 근본 해결

2. 지금 당장 workaround — syscollector 비활성화:

Windows C:\Program Files (x86)\ossec-agent\ossec.conf에서:
```bash
<wodle name="syscollector">
  <disabled>yes</disabled>
</wodle>
```

를 추가하고 재시작

아니면  agent 4.9.1 이상으로 재설치:
```bash
Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*wazuh*"} | Select-Object Name, Version
#최신 버전 다운로드
New-Item -ItemType Directory -Path "C:\temp" -Force
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -OutFile "C:\temp\wazuh-agent.msi"
#다운로드 되면 재설치
msiexec /i "C:\temp\wazuh-agent.msi" /q WAZUH_MANAGER="192.168.190.128" WAZUH_REGISTRATION_SERVER="192.168.190.128"
```

### 테스트 — 탐지 시뮬레이션
> ⚠️ Windows 10 VM(피해자 시스템)에서만 실행. 호스트나 Rocky 서버에서 실행 금지.

테스트 A — Run 키 등록 (T1547, rule 100201 트리거)
```powershell
# 관리자 PowerShell
# 테스트용 가짜 악성코드 경로 등록
$regPath = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
$testName = "SOCLabTest_Persistence"
$testValue = "C:\\Windows\\Temp\\totally_legit.exe"

New-ItemProperty -Path $regPath -Name $testName -Value $testValue -PropertyType String -Force
Write-Host "[+] Run key added: $testName = $testValue"

# 확인
Get-ItemProperty -Path $regPath | Select-Object $testName

# 테스트 후 정리
Remove-ItemProperty -Path $regPath -Name $testName
Write-Host "[+] Cleaned up"
```

테스트 B — 시작 프로그램 폴더 .lnk 생성 (T1547, rule 100210 트리거)
```powershell
$startupPath = "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
$lnkPath = "$startupPath\\SOCLabTest.lnk"

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($lnkPath)
$shortcut.TargetPath = "C:\\Windows\\Temp\\test.exe"
$shortcut.Save()

Write-Host "[+] LNK created: $lnkPath"

# 테스트 후 정리
Remove-Item $lnkPath -Force
Write-Host "[+] Cleaned up"
```

테스트 C — 신규 서비스 등록 (T1543, rule 100220/100221 트리거)
```powershell
# sc.exe로 가짜 서비스 등록
sc.exe create SOCLabTestSvc binPath= "C:\\Windows\\Temp\\fake_service.exe" start= auto
Write-Host "[+] Service created"

# EventID 7045 발생 확인:
# 이벤트 뷰어 → Windows 로그 → 시스템 → ID 7045 필터링

# 테스트 후 정리
sc.exe delete SOCLabTestSvc
Write-Host "[+] Service deleted"
```

테스트 D — 서비스 레지스트리 직접 변조 (T1543, rule 100222 트리거)
```powershell
# 실제 공격자가 sc.exe 없이 직접 레지스트리를 변조하는 시나리오
# (기존 서비스의 ImagePath를 변경하는 것은 위험하므로 신규 키로 테스트)
$svcRegPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SOCLabFakeSvc"
New-Item -Path $svcRegPath -Force | Out-Null
New-ItemProperty -Path $svcRegPath -Name "ImagePath" -Value "C:\\Temp\\evil.exe" -PropertyType String -Force
New-ItemProperty -Path $svcRegPath -Name "Start" -Value 2 -PropertyType DWord -Force
New-ItemProperty -Path $svcRegPath -Name "Type" -Value 16 -PropertyType DWord -Force

Write-Host "[+] Service registry key created directly"

# 정리
Remove-Item -Path $svcRegPath -Recurse -Force
Write-Host "[+] Cleaned up"
```

1. 탐지 결과 확인

Wazuh CLI에서 실시간 확인 (Rocky Linux)
```bash
# 실시간 알럿 스트리밍
sudo tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool | grep -A 20 '"rule"'

# Rule ID 기준 필터링
sudo tail -f /var/ossec/logs/alerts/alerts.json | \\
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        alert = json.loads(line)
        rule_id = str(alert.get('rule', {}).get('id', ''))
        if rule_id.startswith('1002'):
            print(f\\"[ALERT] Rule {rule_id} | Level {alert['rule']['level']} | {alert['rule']['description']}\\")
    except:
        pass
"
```

Kibana에서 확인
```plain text
# Discover 쿼리
rule.id: 100200 OR rule.id: 100201 OR rule.id: 100202 OR rule.id: 100210 OR rule.id: 100220 OR rule.id: 100221 OR rule.id: 100222

# MITRE 기반 조회
rule.mitre.id: T1547.001 OR rule.mitre.id: T1543.003
```

예상 알럿 출력 예시
```json
{
  "rule": {
    "id": "100201",
    "level": 12,
    "description": "T1547 — Value written to Run/RunOnce key | Image: C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe | Details: C:\\\\Windows\\\\Temp\\\\totally_legit.exe",
    "groups": ["persistence", "registry", "autorun", "high_fidelity"],
    "mitre": { "id": ["T1547.001"] }
  },
  "agent": { "name": "windows10-victim" },
  "data": {
    "win": {
      "eventdata": {
        "eventType": "SetValue",
        "targetObject": "HKU\\\\...\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\SOCLabTest_Persistence",
        "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
      }
    }
  }
}
```

1. 포트폴리오 문서화 포인트

항목	내용

탐지 기법	Sysmon EventID 12/13 (레지스트리), 7045 (서비스), 11 (파일 생성)

MITRE 매핑	T1547.001 (Run Keys), T1547.004 (Winlogon), T1543.003 (Windows Service)

Rule Chaining	동일 프로세스의 다중 Persistence 기법 5분 내 탐지 (Rule 100230)

False Positive 대응	services.exe / TrustedInstaller.exe / MsMpEng.exe 화이트리스트

한계 및 개선점	메모리 기반 Fileless Persistence는 레지스트리/파일 이벤트 없으므로 미탐 가능 → 향후 Sysmon EventID 10 (ProcessAccess) 연계 필요

1. 트러블슈팅

Sysmon 이벤트가 Wazuh에서 안 보일 때
```bash
# Windows agent에서 수집 채널 확인
# C:\\Program Files (x86)\\ossec-agent\\ossec.conf 에 아래 있어야 함
# <localfile>
#   <log_format>eventchannel</log_format>
#   <location>Microsoft-Windows-Sysmon/Operational</location>
# </localfile>

# Rocky에서 agent 연결 상태 확인
sudo /var/ossec/bin/agent_control -l
```

Rule 100220이 안 트리거될 때 (7045 기본 rule 60103 확인)
```bash
# Wazuh 기본 ruleset에 60103이 있는지 확인
grep -r "60103" /var/ossec/ruleset/rules/
# 없으면 wazuh-manager 버전 확인 — 4.9.0에선 win_rules.xml에 존재
```

노이즈가 너무 많을 때
```bash
# SYSTEM\\CurrentControlSet\\Services 는 정상 업데이트 때도 대량 발생
# Rule 100222의 negate 조건에 정상 프로세스 추가
# <field name="win.eventdata.image" type="pcre2" negate="yes">
#   (?i)(services\\.exe|svchost\\.exe|TrustedInstaller\\.exe|MsMpEng\\.exe|WmiPrvSE\\.exe)
# </field>
```

룰파일
```text
<!--
  Wazuh Custom Rules — Persistence Detection
  파일 위치 (Rocky Linux 관리 서버):
    /var/ossec/etc/rules/local_rules.xml

  대응 MITRE ATT&CK:
    T1547 — Boot or Logon Autostart Execution (레지스트리 Run 키)
    T1543 — Create or Modify System Process (Windows Service 등록)

  Sysmon 이벤트 매핑:
    EventID 12 : RegistryEvent Object Create/Delete
    EventID 13 : RegistryEvent Value Set
    EventID 14 : RegistryEvent Key/Value Rename
    EventID 11 : FileCreate (시작 프로그램 폴더 .lnk)
  Windows System 이벤트:
    EventID 7045 : A new service was installed
    EventID 4698 : Scheduled task created (보너스)
-->

<group name="persistence,sysmon,windows,">

  <!-- ================================================================
       SECTION 1 : T1547 — Registry Run Key (Sysmon EventID 12/13)
       ================================================================ -->

  <!-- 기본 Run 키 감지 (심각도 medium) -->
  <rule id="100200" level="10">
    <if_group>sysmon_event_12</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">
      (?i)\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run
    </field>
    <description>T1547 — Autorun registry key created or deleted | Image: $(win.eventdata.image)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
    <group>persistence,registry,autorun,</group>
  </rule>

  <!-- Run 키에 값 쓰기 (EventID 13 — 실제 페이로드 등록 순간) -->
  <rule id="100201" level="12">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">
      (?i)\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\RunOnce?
    </field>
    <description>T1547 — Value written to Run/RunOnce key | Image: $(win.eventdata.image) | Details: $(win.eventdata.details)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
    <group>persistence,registry,autorun,high_fidelity,</group>
  </rule>

  <!-- Winlogon 키 변조 — 고위험 (Shell/Userinit 값 변조 시 부팅 시 실행) -->
  <rule id="100202" level="14">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">
      (?i)\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\(Shell|Userinit)
    </field>
    <description>T1547 — HIGH: Winlogon Shell/Userinit registry value modified | Image: $(win.eventdata.image)</description>
    <mitre>
      <id>T1547.004</id>
    </mitre>
    <group>persistence,registry,winlogon,critical,</group>
  </rule>

  <!-- BootExecute 변조 — 매우 고위험 (부팅 극초기 실행) -->
  <rule id="100203" level="15">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">
      (?i)\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute
    </field>
    <description>T1547 — CRITICAL: BootExecute registry value modified | Image: $(win.eventdata.image)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
    <group>persistence,registry,bootexecute,critical,</group>
  </rule>

  <!-- ================================================================
       SECTION 2 : T1547 — Startup Folder .lnk (Sysmon EventID 11)
       ================================================================ -->

  <rule id="100210" level="10">
    <if_group>sysmon_event_11</if_group>
    <field name="win.eventdata.targetFilename" type="pcre2">
      (?i)\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.+\.lnk$
    </field>
    <description>T1547 — LNK shortcut created in Startup folder | Image: $(win.eventdata.image) | File: $(win.eventdata.targetFilename)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
    <group>persistence,startup_folder,</group>
  </rule>

  <!-- ================================================================
       SECTION 3 : T1543 — Windows Service 등록 (EventID 7045)
       Wazuh는 Windows System 이벤트로그에서 7045를 직접 수집
       ================================================================ -->

  <!-- 신규 서비스 설치 기본 탐지 -->
  <rule id="100220" level="12">
    <if_sid>60103</if_sid>
    <!-- 60103 = Wazuh 기본 rule for Windows EventID 7045 -->
    <description>T1543 — New Windows service installed: $(win.system.message)</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
    <group>persistence,service_install,</group>
  </rule>

  <!-- 서비스가 SYSTEM 권한 + 자동 시작으로 등록된 경우 — 고위험 -->
  <rule id="100221" level="14">
    <if_sid>60103</if_sid>
    <field name="win.system.message" type="pcre2">
      (?i)(Service Type|Start Type).*kernel|auto.*(start|begin)
    </field>
    <description>T1543 — HIGH: Kernel-level or auto-start service installed | Service: $(win.system.message)</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
    <group>persistence,service_install,kernel_service,</group>
  </rule>

  <!-- 서비스 레지스트리 직접 변조 (Sysmon EventID 13) -->
  <rule id="100222" level="13">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">
      (?i)\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+\\(ImagePath|Start|Type)$
    </field>
    <field name="win.eventdata.image" type="pcre2" negate="yes">
      (?i)(services\.exe|svchost\.exe|TrustedInstaller\.exe|MsMpEng\.exe)
    </field>
    <description>T1543 — Service registry key modified directly by non-system process | Image: $(win.eventdata.image) | Key: $(win.eventdata.targetObject)</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
    <group>persistence,service_registry,high_fidelity,</group>
  </rule>

  <!-- ================================================================
       SECTION 4 : Rule Chaining — 연속 이벤트 상관 분석
       동일 프로세스가 5분 내 Run키 + 서비스 등록을 동시에 시도하면
       Persistence 다중 기법 사용 = 더 높은 위협
       ================================================================ -->

  <!-- Step 1: Run 키 쓰기 후 서비스 레지스트리 변조가 같은 Image에서 발생 -->
  <rule id="100230" level="15" timeframe="300" frequency="2">
    <if_matched_sid>100201</if_matched_sid>
    <same_field>win.eventdata.image</same_field>
    <description>T1547+T1543 — CRITICAL: Same process modified Run key AND service registry within 5 min | Image: $(win.eventdata.image)</description>
    <mitre>
      <id>T1547.001</id>
      <id>T1543.003</id>
    </mitre>
    <group>persistence,multi_technique,chained_alert,critical,</group>
  </rule>

</group>
```
```text
<Sysmon schemaversion="4.90">
  <EventFiltering>

    <!-- ============================================================
         EventID 12 / 13 / 14 : Registry Monitoring (T1547)
         - 12 : RegistryEvent (Object Create and Delete)
         - 13 : RegistryEvent (Value Set)
         - 14 : RegistryEvent (Key and Value Rename)
         Target: Run / RunOnce / Services 등 Autorun 관련 키
         ============================================================ -->

    <RuleGroup name="Registry_Persistence" groupRelation="or">

      <RegistryEvent onmatch="include">
        <!-- Run / RunOnce 키 생성·삭제 감시 (EventID 12) -->
        <Rule name="T1547_Run_Key_Create" groupRelation="or">
          <TargetObject condition="contains">SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
          <TargetObject condition="contains">SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
          <TargetObject condition="contains">SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run</TargetObject>
        </Rule>

        <!-- Run 키 값 쓰기 감시 (EventID 13) -->
        <Rule name="T1547_Run_Key_Set" groupRelation="or">
          <TargetObject condition="contains">SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
          <TargetObject condition="contains">SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
        </Rule>

        <!-- 시작프로그램 관련 레지스트리 추가 경로 -->
        <Rule name="T1547_Startup_Registry" groupRelation="or">
          <TargetObject condition="contains">SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon</TargetObject>
          <TargetObject condition="contains">SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject>
          <TargetObject condition="contains">SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</TargetObject>
          <TargetObject condition="contains">SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</TargetObject>
        </Rule>
      </RegistryEvent>

    </RuleGroup>

    <!-- ============================================================
         EventID 7045 : NEW SERVICE INSTALLED (T1543)
         Sysmon 자체가 아닌 Windows System 이벤트로그(Security/System)
         에서 7045를 수집하지만, Sysmon config에서도 서비스 관련
         레지스트리 경로를 함께 잡는 것이 권장됨
         ============================================================ -->

    <RuleGroup name="Service_Persistence" groupRelation="or">

      <RegistryEvent onmatch="include">
        <!-- 서비스 레지스트리 경로 변조 감시 -->
        <Rule name="T1543_Service_Registry" groupRelation="or">
          <TargetObject condition="contains">SYSTEM\CurrentControlSet\Services</TargetObject>
        </Rule>
      </RegistryEvent>

    </RuleGroup>

    <!-- ============================================================
         EventID 11 : FileCreate — 시작 프로그램 폴더 .lnk 생성 감시
         ============================================================ -->

    <RuleGroup name="Startup_Folder_Create" groupRelation="or">

      <FileCreate onmatch="include">
        <Rule name="T1547_Startup_Folder_LNK" groupRelation="or">
          <TargetFilename condition="contains">Microsoft\Windows\Start Menu\Programs\Startup</TargetFilename>
          <TargetFilename condition="end with">.lnk</TargetFilename>
        </Rule>
      </FileCreate>

    </RuleGroup>

    <!-- ============================================================
         노이즈 제거 — 정상적인 시스템/업데이트 프로세스 제외
         실제 환경에 맞게 추가 조정 필요
         ============================================================ -->

    <RuleGroup name="Registry_Noise_Exclude" groupRelation="or">

      <RegistryEvent onmatch="exclude">
        <Rule name="Exclude_System_Processes" groupRelation="or">
          <Image condition="is">C:\Windows\System32\svchost.exe</Image>
          <Image condition="is">C:\Windows\System32\services.exe</Image>
          <Image condition="is">C:\Windows\regedit.exe</Image>
          <!-- Windows Defender 업데이트 제외 -->
          <Image condition="contains">MsMpEng.exe</Image>
          <!-- Windows Installer 제외 -->
          <Image condition="contains">msiexec.exe</Image>
        </Rule>
      </RegistryEvent>

    </RuleGroup>

  </EventFiltering>
</Sysmon>

```
