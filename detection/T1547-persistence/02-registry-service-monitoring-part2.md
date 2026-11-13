# T1547 Persistence 탐지 2

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

### 날짜: 2026-04-25

태그: Wazuh Sysmon T1547 Windows MITRE ATT&CK Detection Engineering
> Sysmon EventID 13으로 레지스트리 Run 키 변조(T1547.001)를 탐지하는 Wazuh 커스텀 룰 100220 검증

✅ 완료 항목

🔧 Wazuh Agent 4.9.2 업그레이드

항목	내용

이전 버전	4.9.0

업그레이드 버전	4.9.2

업그레이드 이유	syscollector.dll_unloaded 크래시 버그 — agent가 주기적으로 죽으면서 이벤트 누락

방법	MSI silent install (/qn /l*v)

핵심 명령:
```powershell
msiexec /i "C:\\temp\\wazuh-agent.msi" `
  WAZUH_MANAGER="192.168.190.128" `
  WAZUH_REGISTRATION_SERVER="192.168.190.128" `
  /qn /l*v "C:\\temp\\wazuh-install.log"
```

🔍 파이프라인 디버깅 — 근본 원인 분석

오늘 디버깅한 탐지 파이프라인:
```plain text
PowerShell
  └─▶ Registry Run Key SetValue
        └─▶ Sysmon EventID 13
              └─▶ Wazuh Agent (eventchannel)
                    └─▶ Wazuh Manager (archives.json)
                          └─▶ Rule 100220 발동 (alerts.json)
```

발견한 문제 3가지:

문제 1: ossec.conf에 Sysmon 채널 미설정

증상: agent가 Sysmon 이벤트를 수집하지 않음

원인: localfile eventchannel 블록 누락

해결:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

문제 2: Rule 필드명 오류

증상: archives에 이벤트는 오는데 alert가 발동하지 않음

원인: 룰에 win.eventdata.image로 작성했으나 실제 decoder 출력은 image

확인 방법: archives.json에서 실제 필드 구조 추출
```bash
docker exec single-node-wazuh.manager-1 grep -a "EvilToday3" \\
  /var/ossec/logs/archives/archives.json | tail -1 | \\
  python3 -m json.tool | grep -E "image|targetObject"
```

### 실제 필드: image, targetObject (프리픽스 없음)

문제 3: Sysmon EventID 13 간헐적 전송 실패 (미해결)

증상: Sysmon은 EventID 13을 캡처하는데 archives에 미도달

특이사항: EventID 12(CreateKey)는 정상 전송됨

가설: eventchannel reader 타이밍 또는 드라이버 버퍼 이슈

다음 시도: Windows 재부팅 후 재테스트

📋 디버깅 체크리스트 (습득)

파이프라인 각 단계별 검증 방법 확립:

① Sysmon 캡처 확인 (Windows):
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
  Where-Object {$_.Id -eq 13 -and $_.Message -like "*키워드*"} | FL TimeCreated
```

② Agent 연결 확인 (Windows):
```powershell
Get-Content "C:\\Program Files (x86)\\ossec-agent\\ossec.log" | Select-Object -Last 10
```

③ Manager 수신 확인 (Rocky):
```bash
# archives에서 이벤트 도달 여부
docker exec single-node-wazuh.manager-1 grep -a "키워드" \\
  /var/ossec/logs/archives/archives.json | wc -l

# alerts 발동 여부
docker exec single-node-wazuh.manager-1 grep -a "키워드\\|룰ID" \\
  /var/ossec/logs/alerts/alerts.json | tail -5
```

④ logall 활성화 (디버깅 시 임시 사용):
```bash
docker exec single-node-wazuh.manager-1 \\
  sed -i 's/<logall>no<\\/logall>/<logall>yes<\\/logall>/' \\
  /var/ossec/etc/ossec.conf
```

### 📁 수정된 파일 목록

파일	위치	변경 내용

ossec.conf	Windows agent	Sysmon eventchannel localfile 추가

0860-sysmon_id_13.xml	Manager 컨테이너	Rule 100220 필드명 수정 (win.eventdata.image → image)

ossec.conf	Manager 컨테이너	logall/logall_json 임시 활성화

🛡️ 현재 Rule 100220 상태
```xml
<rule id="100220" level="12">
  <if_sid>92300</if_sid>
  <field name="image" type="pcre2">(?i)powershell</field>
  <field name="targetObject" type="pcre2">(?i)CurrentVersion\\\\Run</field>
  <description>T1547 - Run key modified via PowerShell</description>
  <mitre><id>T1547.001</id></mitre>
  <group>persistence,registry,autorun,</group>
</rule>
```

### 파일 반영: ✅ (/var/ossec/ruleset/rules/0860-sysmon_id_13.xml line 31)

실제 발동: ❌ (이벤트 전송 문제로 미확인)

### ⏭️ 다음 세션 TODO

Windows 재부팅 → Sysmon + Wazuh agent 재시작

Sysmon EventID 13 전송 안정성 재확인

Rule 100220 발동 최종 확인

발동 확인 후 → Active Response 연동 작업 시작

logall 비활성화 (프로덕션 설정 복원)

💡 오늘 배운 것

Wazuh rule 필드명은 decoder 출력 기준이다. win.eventdata.* 프리픽스는 Kibana/dashboard용이고 rule XML에서는 decoder가 내보내는 실제 필드명을 써야 한다.

archives.json이 alerts.json의 상위 단계다. alert가 안 뜨면 archives부터 확인해서 이벤트 도달 여부를 먼저 판단한다.

Sysmon은 커널 드라이버라 Restart-Service로 재시작 불가. config 재적용은 sysmon64.exe -c <xml> 사용.

EventID 13은 동일 키/값 재설정 시 발생하지 않는다. 테스트 전 기존 키를 삭제해야 신뢰할 수 있는 이벤트를 생성할 수 있다.

docker cp가 컨테이너 파일 수정의 정석이다. sed로 직접 수정하거나 bash heredoc은 특수문자 이슈 발생 가능.
