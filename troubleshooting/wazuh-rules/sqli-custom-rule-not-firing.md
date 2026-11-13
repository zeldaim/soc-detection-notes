# Wazuh 커스텀 룰 미발동 — SQL Injection 탐지 실패

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## 환경: Rocky Linux 9 / Kali Linux / Wazuh 4.9.0 (Docker) / ELK Stack

소요시간: 약 2시간

### 📌 개요

Kali Linux에서 SQL injection 공격을 시뮬레이션한 후 Wazuh custom rule(100005)이 알럿을 생성하지 않는 문제가 발생했다. Apache access_log에는 공격 패턴이 정상적으로 기록되고 있었으나 Wazuh alerts.log에는 아무런 출력이 없었다.

### 🖥️ 환경 구성
```plain text
Kali Linux (192.168.190.130)  →  Rocky Linux 9 (192.168.190.128)
                                  ├── Apache httpd
                                  ├── Wazuh Agent
                                  └── Docker
                                       ├── wazuh-manager:4.9.0
                                       ├── wazuh-indexer:4.9.0
                                       └── wazuh-dashboard:4.9.0
```

### 🔍 증상 재현

#### 공격 시뮬레이션 (Kali)
```bash
curl "http://192.168.190.128/index.php?id=1'%20union%20select%201%2C2%2C3--"
curl "http://192.168.190.128/index.php?id=1'%20or%20'1'%27%3D'1"
curl "http://192.168.190.128/?search=admin'%20drop%20table%20users--"
```

#### Apache access_log 확인 (Rocky)
```bash
sudo grep -i "union\|select\|drop\|%27" /var/log/httpd/access_log
```
```plain text
192.168.190.130 - - [16/Apr/2026:11:21:49 +0900] "GET /?id=1%27%20union%20select%201%2C2%2C3-- HTTP/1.1" 403 7620
192.168.190.130 - - [16/Apr/2026:11:21:49 +0900] "GET /?id=1%27%20or%20%271%27%3D%271 HTTP/1.1" 403 7620
192.168.190.130 - - [16/Apr/2026:11:21:49 +0900] "GET /?search=admin%27%20drop%20table%20users-- HTTP/1.1" 403 7620
```

→ 공격 로그 정상 기록. HTTP 403으로 응답 ✅

> 📷 Rocky에서 `sudo grep -i "union\|select\|drop\|%27" /var/log/httpd/access_log` 결과: 192.168.190.130(Kali)에서 curl로 보낸 `?id=1' union select 1,2,3--`, `?id=1' or '1'='1`, `?search=admin' drop table users--` 요청이 모두 HTTP 403으로 기록됨.

#### Wazuh 알럿 확인 (Rocky)
```bash
docker exec single-node-wazuh.manager-1 \
  grep -i "100005\|SQL" /var/ossec/logs/alerts/alerts.log | tail -10
```

→ 출력 없음 ❌

> 📷 같은 access_log 9줄(11:21~11:58, 모두 403). 로그는 정상 수집 대상이지만 Wazuh 알림 검색 결과는 비어 있음.

### 🔎 원인 조사

#### Step 1. localfile 설정 확인

Wazuh가 Apache 로그를 수집하고 있는지 확인했다.
```bash
cat /var/ossec/etc/ossec.conf | grep -A3 "localfile"
```
```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/httpd/access_log</location>
</localfile>
```

→ Apache access_log 수집 설정 존재 ✅

#### Step 2. Custom rule 존재 여부 확인
```bash
docker exec single-node-wazuh.manager-1 \
  grep -r "SQL" /var/ossec/etc/rules/
```
```plain text
/var/ossec/etc/rules/local_rules.xml: <description>SQL Injection attempt detected</description>
```

→ local_rules.xml에 rule 100005 존재 ✅

> 📷 에이전트 `ossec.conf`의 localfile: /var/log/messages·/var/log/secure(syslog), audit.log(audit), **/var/log/httpd/access_log(apache)** 수집 설정 확인. 매니저 컨테이너에서 `grep -r "SQL"` → local_rules.xml에 "SQL Injection attempt detected" 룰 존재.

#### Step 3. Rule 내용 상세 확인
```bash
docker exec single-node-wazuh.manager-1 \
  cat /var/ossec/etc/rules/local_rules.xml
```
```xml
<group name="web,sqli,">
  <rule id="100005" level="10">
    <if_sid>31103</if_sid>
    <url>union|select|insert|drop|delete|update|cast|exec|declare|--|%27|%3B</url>
    <description>SQL Injection attempt detected</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>
</group>
```

#### Step 4. 부모 rule 31103 발동 여부 확인

Wazuh rule은 if_sid로 부모-자식 관계를 구성한다.

자식 rule(100005)은 부모 rule(31103)이 먼저 발동해야 실행된다.
```bash
docker exec single-node-wazuh.manager-1 \
  grep "31103" /var/ossec/logs/alerts/alerts.log | tail -5
```
```plain text
Rule: 31103 (level 7) -> 'SQL injection attempt.'
```

→ 부모 rule 31103 정상 발동 확인 ✅

### ⚠️ 원인 분석

부모 rule은 정상 발동하고 있었다.

처음에는 HTTP 403 응답코드 때문에 부모 rule 31103이 발동하지 않는다고 오진했다.

(Wazuh Apache rule 중 일부는 응답코드별로 분기되기 때문)

그러나 실제 원인은 달랐다.
> rule 수정 후 Wazuh manager를 재시작하지 않았거나,

재시작 후 새 트래픽을 발생시키지 않고 재시작 이전 로그를 확인한 것이 원인이었다.

Wazuh는 rule을 메모리에 로드해서 사용한다.

rule 파일을 수정해도 프로세스를 재시작하지 않으면 변경사항이 반영되지 않는다.

또한 재시작 이후 발생한 이벤트에만 수정된 rule이 적용되며,

재시작 이전 로그는 재처리되지 않는다.

추가로 local_rules.xml은 Rocky Linux 호스트가 아닌

Wazuh manager 컨테이너 내부에 위치한다는 점도 확인했다.
```bash
# 호스트에서 수정 시도 → 실패
sudo sed -i '...' /var/ossec/etc/rules/local_rules.xml
# sed: /var/ossec/etc/rules/local_rules.xml: 그런 파일이나 디렉토리가 없습니다
```

### ✅ 해결

#### 1. 컨테이너 진입
```bash
docker exec -it single-node-wazuh.manager-1 bash
```

#### 2. Rule 확인 및 재시작
```bash
cat /var/ossec/etc/rules/local_rules.xml
/var/ossec/bin/wazuh-control restart
exit
```

#### 3. 새 공격 트래픽 발생 (Kali)
```bash
curl "http://192.168.190.128/index.php?id=1'%20union%20select%201,2,3--"
```

#### 4. 알럿 확인
```bash
docker exec single-node-wazuh.manager-1 \
  grep "100005" /var/ossec/logs/alerts/alerts.log | tail -5
```
```plain text
Rule: 100005 (level 10) -> 'SQL Injection attempt detected'
```

### 📊 최종 결과

### 💡 핵심 교훈

#### 1. Wazuh rule 수정 후 필수 검증 순서
```plain text
rule 수정 → wazuh-control restart → 새 트래픽 발생 → alerts.log 확인
```

재시작 없이 확인하거나, 재시작 후 기존 로그를 확인하면 알럿이 보이지 않는다.

#### 2. Custom rule 미발동 시 디버깅 순서
```plain text
1. localfile 설정 확인         → Apache 로그 수집 여부
2. rule 파일 존재 여부 확인
3. if_sid 부모 rule 발동 여부  → alerts.log grep
4. 재시작 후 새 트래픽으로 재검증
```

#### 3. Docker 기반 Wazuh에서 파일 위치

호스트에서 직접 수정 불가. 반드시 docker exec -it 로 진입 후 수정.

#### 4. Wazuh rule if_sid 구조
```plain text
부모 rule (if_sid 대상)
└── 자식 rule (if_sid로 부모 지정)
    → 부모가 발동해야 자식도 발동
    → 부모 미발동 시 자식은 절대 실행되지 않음
```

custom rule이 안 뜰 때 자식 rule보다 부모 rule을 먼저 확인해야 한다.
