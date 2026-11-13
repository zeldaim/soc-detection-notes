# XML 구조 오류 — Wazuh 룰 탐지 실패

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 생략했습니다.

#### 문제 상황

Kali Linux에서
```bash
sudo nmap -sS 192.168.190.128
```

Security Events 캡쳐 실패 - rule 10004가 없음

상황 파악 : Rocky Linux에서 로그 직접 확인
```bash
sudo tail -f /var/log/secure | grep PORTSCAN
```
```bash
sudo tail -20 /var/log/secure | grep PORTSCAN
```
```bash
docker exec single-node-wazuh.manager-1 tail -20 /var/ossec/logs/alerts/alerts.log | grep -i "100004\|PORTSCAN"
```

/var/log/secure에 PORTSCAN 로그는 찍히는데 Wazuh alerts.log에는 없음.

Wazuh 에이전트가 /var/log/secure를 수집하고 있는지 확인:
```bash
sudo cat /var/ossec/etc/ossec.conf | grep -A3 "secure"

```

/var/log/secure 수집 설정 존재

log_format 확인
```bash
sudo cat /var/ossec/etc/ossec.conf | grep -A5 "secure"

```

/var/log/secure 블록에 log_format이 빠져있음
```bash
sudo sed -i 's|<location>/var/log/secure</location>|<log_format>syslog</log_format>\n    <location>/var/log/secure</location>|' /var/ossec/etc/ossec.conf

```

확인
```bash
sudo cat /var/ossec/etc/ossec.conf | grep -A5 "secure"
```

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

og_format이 두 번 중복
```bash

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/secure</location>
</localfile>
```

복된 <log_format>syslog</log_format> 한 줄 삭제
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
```bash
Rule 100004 - Nmap port scan detected via iptables
T1046 - Discovery
Level 10
agent: localhost.localdomain (ID: 003)
```
