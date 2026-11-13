# T1547 Persistence 탐지 — 탐지 성공

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 생략했습니다.

```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```
```bash
localhost terraform-soc]$ docker exec single-node-wazuh.manager-1 cat /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
<!--
  Copyright (C) 2015, Wazuh Inc.
-->

<!--
  Sysmon Event 13 rules ID: 92300 - 92399
-->

<group name="sysmon,sysmon_eid13_detections,windows,">

 <rule id="92300" level="3">
  <if_sid>61600</if_sid>
  <field name="win.system.eventID" type="pcre2">^13$</field>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</field>
  <description>T1547.001 - Registry Run key modified</description>
  <mitre><id>T1547.001</id></mitre>
  <group>sysmon_event_13,</group>
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
    <if_sid>61600</if_sid>
        <field name="win.system.eventID" type="pcre2">^13$</field>
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
    <if_sid>61600</if_sid>
        <field name="win.system.eventID" type="pcre2">^13$</field>
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
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```
```bash
<rule id="92300" level="3">
  <if_sid>61600</if_sid>
  <field name="win.system.eventID">^13$</field>
  <field name="win.eventdata.targetObject">(?i)SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</field>
```

860 파일 (92300 룰) — 실제로는 잘 작성됨

100220도 0860 안에 있고, win.eventdata.image 필드명 쓰고 있음.

핵심 문제: TIL-3에서 archives.json 확인했을 때 실제 decoder 출력
```bash

"image": "...",  ← win.eventdata.image 아님
"targetObject": "..."  ← win.eventdata.targetObject 아님

```

0860 안의 100220은 win.eventdata.image 쓰고 있음 → 필드명 불일치.

local_rules.xml의 100221도 if_sid 없이 decoded_as만 씀 → 61600이 먼저 잡아버리면 100221은 평가 안 됨.

archives에서 실제 필드명 재확인:
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday" /var/ossec/logs/archives/archives.json | tail -1 | python3 -m json.tool 2>/dev/null | grep -E '"image|"targetObject|"eventID'
```

rchives에 EvilToday 이벤트 자체가 없다. 그러므로 파이프라인의 앞단에서 문제가 발생함.

확인

1. archives.json이 오늘 업데이트되고 있는지:
```bash
docker exec single-node-wazuh.manager-1 ls -la /var/ossec/logs/archives/archives.json
```

2.logall_json이 실제로 활성화됐는지:
```bash
docker exec single-node-wazuh.manager-1 grep -A1 "logall" /var/ossec/etc/ossec.conf
```

3. agent 003 (Windows)이 현재 연결 상태인지:
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

정상 상태 확인

alerts에 없음.

archives 먼저 확인 - 이벤트가 manager까지 도달했는지 체크
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday5" /var/ossec/logs/archives/archives.json | wc -l
```

archives에 존재 확인

룰 매칭 문제일 가능성이 있기 때무에 실제 필드명 확인하자.
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday5" /var/ossec/logs/archives/archives.json | python3 -m json.tool | grep -E '"image|"targetObject|"eventID'
```

필드명 확인

- "eventID": "13" ✅
- "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" ✅
- "targetObject": "HKU\\...\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilToday5" ✅

데이터는 완벽하게 도달하고 있지만 현재 문제는 0860의 룰이 win.system.eventID , win.eventdata.targetObject 로 참조하는데, 실제 decoded 필드는 evnetID , image , targetID 이라서 문제가 발생함.

즉, win  prefix가 문제.

0860 파일의 92300을 확인해보면:
```bash
<field name="win.system.eventID">^13$</field>
<field name="win.eventdata.targetObject">(?i)SOFTWARE\\Microsoft...
```

근데 필드는 win 이 없이 발생함. 이게 decoder 버전 차이일 가능성이 있다.

logtest로 확인:
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

여기이 넣을 값은:
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```
```bash
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-27T03:24:39.2284368Z","eventRecordID":"25251","processID":"2776","threadID":"4020","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-27 03:24:39.227\r\nProcessGuid: {4fb3ada3-d0f1-69ed-3c01-000000000600}\r\nProcessId: 3672\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilToday5\r\nDetails: calc.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-27 03:24:39.227","processGuid":"{4fb3ada3-d0f1-69ed-3c01-000000000600}","processId":"3672","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\EvilToday5","details":"calc.exe","user":"DESKTOP-5408CBA\\\\yhc"}}}

```
```bash
*Phase 1: Completed pre-decoding.
	full event: '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"13","version":"2","level":"4","task":"13","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-04-27T03:24:39.2284368Z","eventRecordID":"25251","processID":"2776","threadID":"4020","channel":"Microsoft-Windows-Sysmon/Operational","computer":"DESKTOP-5408CBA","severityValue":"INFORMATION","message":"\"Registry value set:\r\nRuleName: T1547_Run_Key_Create\r\nEventType: SetValue\r\nUtcTime: 2026-04-27 03:24:39.227\r\nProcessGuid: {4fb3ada3-d0f1-69ed-3c01-000000000600}\r\nProcessId: 3672\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetObject: HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilToday5\r\nDetails: calc.exe\r\nUser: DESKTOP-5408CBA\\yhc\""},"eventdata":{"ruleName":"T1547_Run_Key_Create","eventType":"SetValue","utcTime":"2026-04-27 03:24:39.227","processGuid":"{4fb3ada3-d0f1-69ed-3c01-000000000600}","processId":"3672","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetObject":"HKU\\\\S-1-5-21-3385978295-689239366-777767380-1001\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\EvilToday5","details":"calc.exe","user":"DESKTOP-5408CBA\\\\yhc"}}}'

**Phase 2: Completed decoding.
	name: 'json'
	win.eventdata.details: 'calc.exe'
	win.eventdata.eventType: 'SetValue'
	win.eventdata.image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
	win.eventdata.processGuid: '{4fb3ada3-d0f1-69ed-3c01-000000000600}'
	win.eventdata.processId: '3672'
	win.eventdata.ruleName: 'T1547_Run_Key_Create'
	win.eventdata.targetObject: 'HKU\\S-1-5-21-3385978295-689239366-777767380-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilToday5'
	win.eventdata.user: 'DESKTOP-5408CBA\\yhc'
	win.eventdata.utcTime: '2026-04-27 03:24:39.227'
	win.system.channel: 'Microsoft-Windows-Sysmon/Operational'
	win.system.computer: 'DESKTOP-5408CBA'
	win.system.eventID: '13'
	win.system.eventRecordID: '25251'
	win.system.keywords: '0x8000000000000000'
	win.system.level: '4'
	win.system.message: '"Registry value set:
RuleName: T1547_Run_Key_Create
EventType: SetValue
UtcTime: 2026-04-27 03:24:39.227
ProcessGuid: {4fb3ada3-d0f1-69ed-3c01-000000000600}
ProcessId: 3672
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetObject: HKU\S-1-5-21-3385978295-689239366-777767380-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilToday5
Details: calc.exe
User: DESKTOP-5408CBA\yhc"'
	win.system.opcode: '0'
	win.system.processID: '2776'
	win.system.providerGuid: '{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'
	win.system.providerName: 'Microsoft-Windows-Sysmon'
	win.system.severityValue: 'INFORMATION'
	win.system.systemTime: '2026-04-27T03:24:39.2284368Z'
	win.system.task: '13'
	win.system.threadID: '4020'
	win.system.version: '2'

```

Phase 2필드명 확인:

- win.system.eventID: '13' ✅
- win.eventdata.image: 'C:\\Windows\\...\\powershell.exe' ✅
- win.eventdata.targetObject: 'HKU\\...\\CurrentVersion\\Run\\EvilToday5' ✅

Phase3가 실행되지 않음 - 룰매칭이 이루어지지 않음.

logtest는 windows_eventchannel decoder를 타지 않아서 Phase 3가 안 나오는 구조적 한계

실제 alerts로 직접 검증- 92300이 발동한 적이 있는지 확인
```bash
docker exec single-node-wazuh.manager-1 grep -a '"id":"92300"' /var/ossec/logs/alerts/alerts.json | wc -l
```

92300이 한 번도 발동 안 했지만, Phase 2에서 필드명은 맞아.

문제는 61600이 발동 안 하는 것이다. 92300은 if_sid>61600에 의존하는데, 61600이 level 0이라 alerts에 안 찍히지만 발동은 해야한다.

61600 파일 위치 확인
```bash
docker exec single-node-wazuh.manager-1 grep -rn '"61600"\|id="61600"' /var/ossec/ruleset/rules/
```

매칭조건 확인
```bash
docker exec single-node-wazuh.manager-1 sed -n '15,25p' /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
```
```bash
<rule id="61600" level="0">
  <if_sid>60004</if_sid>
  <field name="win.system.severityValue">^INFORMATION$</field>
```

버그: ^INFORMATIONS$ — S

실제 이벤트의 severityValue는 "INFORMATION"인데 룰은 ^INFORMATIONS$로 매칭

61600이 한 번도 발동 안 한 원인

수정
```bash
docker cp single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0595-win-sysmon_rules.xml ~/0595-win-sysmon_rules.xml
sed -i 's/\^INFORMATIONS\$/^INFORMATION$/' ~/0595-win-sysmon_rules.xml
docker cp ~/0595-win-sysmon_rules.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
docker restart single-node-wazuh.manager-1

```

analysisd running

EvilToday6으로 테스트
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday6" /var/ossec/logs/alerts/alerts.json
```

archives에는 있는데 이벤트에 도달하지 못함.

룰 매칭 실패

sed 수정 실패

호스트 파일은 ^INFORMATION$로 정상 수정됐지만 컨테이너 안은 여전히 ^INFORMATIONS$ .

docker cp가 실패했거나 재시작 시 volume이 덮어썼기 때문이다. 이미 4장에서 발생한 오

마운트 경로 확인:

Rules 디렉토리는 볼륨 마운트 없다.  docker cp가 제대로 안 들어간 것 같음.
```bash
docker cp ~/0595-win-sysmon_rules.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
docker exec single-node-wazuh.manager-1 chmod 660 /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml

# 반영 확인
docker exec single-node-wazuh.manager-1 grep "INFORMATION" /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
```

정상 반영됨
```bash
docker restart single-node-wazuh.manager-1
sleep 40
docker exec single-node-wazuh.manager-1 grep "INFORMATION" /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
```

재시작 후 파일 수정 유지확인

테스트

INFORMATIONS 버그가 원인이 맞는데 수정이 제대로 안 됨

60004가 61600의 부모인데, 60004 조건도 확인

60004는 정상. win.system.channel이 ^Microsoft-Windows-Sysmon/Operational$ 매칭

60004의 부모가 60000 체인 전체 확인:
```bash
docker exec single-node-wazuh.manager-1 grep -A5 'id="60000"' /var/ossec/ruleset/rules/0575-win-base_rules.xml
```
```bash
60000: decoded_as=windows_eventchannel + providerName=".+"
→ 60004: channel=Microsoft-Windows-Sysmon/Operational
→ 61600: severityValue=^INFORMATION$  ← 여기서 막힘
→ 92300: eventID=13 + targetObject
→ 100220: image=powershell
```


## T1547.001 FIM 탐지 구현 완료
> 날짜: 2026-04-27

결과: ✅ 성공

방식: Wazuh FIM (File Integrity Monitoring) — 레지스트리 모니터링

### 핵심 발견

Wazuh 공식 T1547 탐지 방식은 Sysmon EventID 13이 아닌 FIM임.

공식 블로그: https://wazuh.com/blog/detecting-windows-persistence-techniques-with-wazuh/

FIM이 HKLM\Software\Microsoft\Windows\CurrentVersion\Run 키를 모니터링하고

변경 시 자동으로 alert 발생.

### 발동된 Alert
```json
{
  "rule": {
    "id": "752",
    "level": 5,
    "description": "Registry Value Entry Added to the System",
    "mitre": { "id": ["T1112"] }
  },
  "syscheck": {
    "path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "FIMTest2",
    "event": "added"
  },
  "agent": { "name": "DESKTOP-5408CBA" }
}
```

관련 rule ID:

- 750 — Registry Value Integrity Checksum Changed (수정)
- 751 — Registry Value Entry Deleted (삭제)
- 752 — Registry Value Entry Added (추가) ← T1547 탐지

### 설정 확인

#### Windows agent ossec.conf (기본 설정, 수정 불필요)
```xml
<syscheck>
  <frequency>300</frequency>  <!-- 테스트용, 운영 시 43200 -->
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
</syscheck>
```

주의: windows_registry는 realtime 미지원. frequency 주기로 스캔.

운영 환경에서는 <frequency>43200</frequency> (12시간) 권장.

### 공격 시뮬레이션
```powershell
# Run 키 추가 (T1547.001 시뮬레이션)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
  -Name "MalwareTest" -Value "calc.exe" -PropertyType String -Force

# 정리
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
  -Name "MalwareTest" -Force
```

frequency 주기 후 alert 자동 발생.

### FIM vs Sysmon EventID 13 비교

### 미해결

Sysmon EventID 13 rule 미발동 문제는 GitHub에 문의 중.

- Issue URL: (올린 후 추가)
- 해결되면 FIM + Sysmon 이중 탐지로 고도화 예정
