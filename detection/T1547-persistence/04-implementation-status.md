# T1547 Persistence 탐지 — 구현 현황(부분 완성)

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## T1547 Persistence 탐지 — 구현 현황 (부분완성)
> 날짜: 2026-04-24 ~ 2026-04-26

MITRE: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

환경: Rocky Linux 9 (Wazuh 4.9.0 Docker) / Windows 10 (Sysmon v15.20 + Wazuh Agent 4.9.2)

### 구현 목표
```plain text
공격자 PowerShell
    ↓ HKCU\...\CurrentVersion\Run 키 생성
Sysmon EventID 13 (Registry SetValue)
    ↓
Wazuh Agent 전송
    ↓
Wazuh Manager Rule 매칭
    ↓
Alert 발생 (level 12, T1547.001)
```

### 완료된 것

#### ✅ 1. Sysmon 설정 — EventID 12/13 감시

sysmon_persistence.xml 적용. Run 키 변조 감시 활성화.
```xml
<RegistryEvent onmatch="include">
  <Compound Rule T1547_Run_Key_Create combine using Or>
    <TargetObject filter: contains value: 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'>
  </Compound>
</RegistryEvent>
<RegistryEvent onmatch="exclude">
  <Compound Rule Exclude_System_Processes>
    <Image filter: is value: 'C:\Windows\System32\svchost.exe'>
    <Image filter: is value: 'C:\Windows\System32\services.exe'>
  </Compound>
</RegistryEvent>
```

검증:
```powershell
# 공격 시뮬레이션
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
  -Name "EvilTest" -Value "calc.exe" -PropertyType String -Force

# Sysmon 캡처 확인
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 `
  | Where-Object {$_.Id -eq 13}
# → EventID 13 캡처 확인 ✅
```

#### ✅ 2. Wazuh Agent 4.9.2 설치 및 연결

- 4.9.0 → 4.9.2 업그레이드 (syscollector.dll 크래시 버그 해결)
- Windows ossec.conf Sysmon eventchannel 설정
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

검증:
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
# ID: 003, Name: DESKTOP-5408CBA, Active ✅
```

#### ✅ 3. EventID 13 → Manager archives 전송

EventID 13 이벤트가 Wazuh Manager까지 정상 전달됨.

archives.json 수신 확인:
```json
{
  "timestamp": "2026-04-26T09:43:46.191+0000",
  "agent": {"id": "003", "name": "DESKTOP-5408CBA"},
  "decoder": {"name": "windows_eventchannel"},
  "data": {
    "win": {
      "system": {"eventID": "13"},
      "eventdata": {
        "ruleName": "T1547_Run_Key_Create",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "targetObject": "HKU\\S-1-5-21-...\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilTest"
      }
    }
  }
}
```

#### ✅ 4. 파이프라인 디버깅 방법론 확립

각 단계별 확인 명령어:

### 미완료 — Rule Alert 발동

#### 현재 rule 구조
```plain text
windows_eventchannel decoder
    ↓
61600 (Sysmon 기본, level 0)
    ↓
61615 / 185011 (EventID 13 분류, level 0) → sysmon_event_13 그룹 부여
    ↓
92300 (Run 키 필터, level 3) ← 0860-sysmon_id_13.xml
    ↓ ← 여기서 매칭 실패
100220 (PowerShell 탐지, level 12)
```

#### 시도한 것들

#### 현재 적용된 rule (0860-sysmon_id_13.xml)
```xml
<rule id="92300" level="3">
  <if_sid>61600</if_sid>
  <field name="win.system.eventID" type="pcre2">^13$</field>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</field>
  <description>T1547.001 - Registry Run key modified</description>
  <mitre><id>T1547.001</id></mitre>
  <group>sysmon_event_13,</group>
</rule>

<rule id="100220" level="12">
  <if_sid>92300</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell</field>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)CurrentVersion\\Run</field>
  <description>T1547 - Run key modified via PowerShell</description>
  <mitre><id>T1547.001</id></mitre>
  <group>persistence,registry,autorun,</group>
</rule>
```

#### 다음 시도 (내일 30분)
```bash
# analysisd 디버그 로그로 rule 매칭 과정 직접 확인
# ossec.conf에 추가
<logging>
  <log_level>2</log_level>
</logging>

docker restart single-node-wazuh.manager-1 && sleep 40

# 테스트 후
docker exec single-node-wazuh.manager-1 grep -a "EvilTodayN" /var/ossec/logs/ossec.log | tail -30
# → 어느 rule이 이벤트를 처리하는지 직접 확인 가능
```

### 핵심 발견 및 교훈
