# XML 구조 오류 — Wazuh 룰 탐지 실패

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

#### 문제 상황

Kali Linux에서
```bash
sudo nmap -sS 192.168.190.128
```

Security Events 캡쳐 실패 - rule 10004가 없음

> 📷 Wazuh Threat Hunting 대시보드(24시간 918건, level 12 이상 0건, 인증 실패 14, 인증 성공 66). 상위 이벤트는 Windows 에이전트의 61104·60106(Windows Logon Success)이고, Nmap 스캔 관련 알림은 보이지 않음.

상황 파악 : Rocky Linux에서 로그 직접 확인
```bash
sudo tail -f /var/log/secure | grep PORTSCAN
```

> 📷 Kali에서 `sudo nmap -sS 192.168.190.128` 결과: 22/ssh, 443/https, 3306/mysql, 9200 열림(나머지 996개 closed). 0.76초 만에 스캔 완료.

> 📷 Threat Hunting Events에서 `rule.id: 100004` 검색 → "No results match your search criteria". 스캔은 했지만 커스텀 룰 알림이 없음.
```bash
sudo tail -20 /var/log/secure | grep PORTSCAN
```
```bash
docker exec single-node-wazuh.manager-1 tail -20 /var/ossec/logs/alerts/alerts.log | grep -i "100004\|PORTSCAN"
```

> 📷 `/var/log/secure`에는 iptables `PORTSCAN:` 커널 로그가 정상 기록됨(SRC=192.168.190.130 → DST=192.168.190.128, DPT=22·3306 등, 도커 브리지 172.18.0.x 내부 통신도 섞임). 그런데 매니저 `alerts.log`에서 100004/PORTSCAN을 grep하면 결과 없음.

/var/log/secure에 PORTSCAN 로그는 찍히는데 Wazuh alerts.log에는 없음.

Wazuh 에이전트가 /var/log/secure를 수집하고 있는지 확인:
```bash
sudo cat /var/ossec/etc/ossec.conf | grep -A3 "secure"

```

> 📷 에이전트 `ossec.conf`에서 `/var/log/secure` 항목을 확인하는 화면. location은 있음.

/var/log/secure 수집 설정 존재

log_format 확인
```bash
sudo cat /var/ossec/etc/ossec.conf | grep -A5 "secure"

```

> 📷 `grep -A5 "secure"` 결과: `/var/log/secure` localfile 블록에 **`<log_format>`이 없고** location만 있음. 바로 아래 audit.log 블록은 log_format=audit 정상.

/var/log/secure 블록에 log_format이 빠져있음
```bash
sudo sed -i 's|<location>/var/log/secure</location>|<log_format>syslog</log_format>\n    <location>/var/log/secure</location>|' /var/ossec/etc/ossec.conf

```

확인
```bash
sudo cat /var/ossec/etc/ossec.conf | grep -A5 "secure"
```

> 📷 `sed -i`로 location 앞에 `<log_format>syslog</log_format>`를 넣으려 했지만 다시 확인해 보니 그대로임(치환 패턴이 맞지 않아 반영 안 됨).

sed가 실패

직접 편집
```bash
sudo nano /var/ossec/etc/ossec.conf
```

/var/log/secure 부분을
```bash
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/secure</location>
</localfile>
```
```bash
sudo systemctl restart wazuh-agent
```

> 📷 nano로 연 ossec.conf: `/var/log/secure` 블록에 `<log_format>syslog</log_format>`가 **두 번 중복**으로 들어간 상태(여러 번 수정하다 생긴 XML 구조 오류).

og_format이 두 번 중복
```bash

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/secure</location>
</localfile>
```

복된 <log_format>syslog</log_format> 한 줄 삭제

> 📷 수정 후 ossec.conf: messages·secure는 각각 log_format=syslog 1개, audit.log는 audit — localfile 3개가 정상 구조.
```bash
sudo systemctl restart wazuh-agent
```

에이전트 상태확인
```bash
sudo systemctl status wazuh-agent | grep -i "active\|error"
```

에이전트가 로그를 읽는지 확인:
```bash
sudo tail -f /var/ossec/logs/ossec.log | grep -i "secure\|error"
```

> 📷 에이전트 재시작 후 Threat Hunting(939건): agent 003(localhost)에서 **100004 "Nmap port scan detected via iptables" (level 10, T1046, Discovery)** 4건 발동 확인.
```bash
Rule 100004 - Nmap port scan detected via iptables
T1046 - Discovery
Level 10
agent: localhost.localdomain (ID: 003)
```
