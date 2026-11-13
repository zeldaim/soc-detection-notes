# T1046 Nmap 포트스캔 탐지 — Wazuh 커스텀 룰

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 생략했습니다.

#### 1. 전체적인 탐지 과정
> Nmap은 패킷 레벨이라 로그가 안 생기므로 → iptables로 강제 로깅 → Wazuh 커스텀 룰로 탐지

1. 문제 인식
- Kali에서 Nmap 스캔 성공 ✅
- Rocky Linux /var/log/secure에는 SSH 브루트포스 로그만 있고 Nmap 로그 없음
- 이유: Nmap sS (SYN 스캔)은 패킷 레벨이라 sshd가 인식 못 함 → 로그 자체가 안 생김

2. 해결 방향 — iptables로 패킷 로깅

- sshd가 못 잡으니까 **커널(iptables)**이 직접 패킷을 잡아서 로그로 남기도록 설정
- PORTSCAN: 접두사로 /var/log/messages → /var/log/secure에 기록

3. Wazuh 커스텀 룰

- Wazuh가 기본적으로 /var/log/secure만 분석하는 게 아니라 이미 수집 중인 로그에서 패턴을 룰로 정의해서 탐지 가
- PORTSCAN 문자열을 match로 잡고, Rule 4100(Firewall rules grouped)의 자식 룰로 100004 정의

#### 2. 세부과정

2-1. Nmap 탐지 커스텀 룰 작성
```bash
cat >> /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="nmap,recon,">
  <rule id="100001" level="10">
    <if_sid>5706</if_sid>
    <description>Possible Nmap port scan detected</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <rule id="100002" level="12">
    <if_sid>5710</if_sid>
    <description>Multiple port scan attempts - possible Nmap SYN scan</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
EOF
```

<group name="nmap,recon,">

이 그룹 안의 룰들을 “nmap”와 “recon” 카테고리 분류

- Kibana/Wazuh 대시보드에서 필터링할 때 사용됨.

Rule 100001 — level 10
```bash
<rule id="100001" level="10">
  <if_sid>5706</if_sid>
  <description>Possible Nmap port scan detected</description>
```

5706은 Wazuh 내장 룰로, sshd 또는 시스템 로그에서 포트 스캔 징후 감지 시 발동.

Rule 100002 — level 12
```bash
<rule id="100002" level="12">
  <if_sid>5710</if_sid>
  <description>Multiple port scan attempts - possible Nmap SYN scan</description>
```

5710은 반복적·다수의 포트 접근 시도 감지 룰. SYN scan(nmap -sS)처럼 짧은 시간에 여러 포트를 두드리는 패턴을 잡아냄.
```bash
Kali에서 nmap 실행
    ↓
Rocky Linux 커널/sshd 로그에 포트 스캔 흔적 기록
    ↓
Wazuh Agent가 로그 수집 → Manager 전송
    ↓
기본 룰 5706 / 5710 발동
    ↓
커스텀 룰 100001 / 100002 체이닝 발동
    ↓
Wazuh 알럿 → Elasticsearch → Kibana 대시보드 시각화
```

#### 롤 작성 후 , Wazuh 매니저 재시작
```bash
/var/ossec/bin/wazuh-control restart
```

#### Kali에서 Nmap 스캔 다시 날려서 탐지되는지 확인

Kali 터미널에서:
```bash
nmap -sS 192.168.190.128
```

그다음 Rocky Linux에서 Wazuh 알람 확인:
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log | grep -i "nmap\|port scan\|100001\|100002"
```

#### 결과 - 탐지 실패

이유

Nmap -sS (SYN 스캔)은 패킷 레벨이라 /var/log/secure 에 기록이 안되는데,  Wazuh는 기본적으로 로그 파일을 분석하는데, 로그가 없으니 탐지가 안 되고 있음.

#### 해결 - iptables로 포트스캔 로깅

Rocky Linux에서 패킷 자체를 로그로 남기게 설정해서 Wazuh에서 탐지함.
```bash
sudo iptables -I INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j LOG --log-prefix "PORTSCAN: "

```

Nmap SYN 스캔 시 /var/log/messages 에 PORTSCAN: 로그 찍힘
```bash
nmap -sS 192.168.190.128
sudo tail -20 /var/log/messages | grep PORTSCAN
```

iptables 설정은 되고 PORTSCAN 로그 확인
```bash
SRC=192.168.190.130 DST=192.168.190.128 PROTO=TCP DPT=22
```

Kali(192.168.190.130)가 Rocky Linux(192.168.190.128) 22번 포트 스캔한 게 커널 레벨에서 탐지가 됨

2-2. Wazuh가 이 로그를 탐지하도록 룰 추가
```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```
```bash
cat >> /var/ossec/etc/rules/local_rules.xml << 'EOF'
  <rule id="100003" level="10">
    <if_sid>1002</if_sid>
    <match>PORTSCAN</match>
    <description>Nmap port scan detected via iptables</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
EOF
```
```bash
/var/ossec/bin/wazuh-control restart
```

Kali에서 다시 스캔날리고 nmap -sS 192.168.190.128

Rocky Linux에서 알람 확인:
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log | grep -i "PORTSCAN\|100003"
```

##### Nmap 스캔은 됐는데 Wazuh 알람이 뜨지 않음.

Wazuh가 /var/log/messages 를 모니터링하고 있는지 확인
```bash
sudo docker exec -it single-node-wazuh.manager-1 grep -i "messages" /var/ossec/etc/ossec.conf
```

/var/log/messages 모니터링 설정이 필요한 것 같음.

그래서 Wazuh 에이전트 설정에 추가해야함
```bash
sudo nano /var/ossec/etc/ossec.conf
```

<ossec_config> 안에 이 부분 추가:
```bash
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/messages</location>
</localfile>
```
```bash
sudo systemctl restart wazuh-agent
```

스캔을 날렸지만 실패!!!

Wazuh 에이전트가 /var/log/messages 를 실제로 읽고 있는지 확인
```bash
sudo tail -f /var/log/messages | grep PORTSCAN

```

/var/log/messages 에 PORTSCAN 로그 찍히고 있음.

iptable문제는 아니고 Wazuh 설정 문제인 것 같음.

Wazuh 에이전트가 이 파일을 안 읽음.

ossec.conf 에 추가가 제대로 됐는지 확인
```bash
sudo grep -A3 "messages" /var/ossec/etc/ossec.conf
```

ossec.conf에 /var/log/messages 설정있음 확인
```bash
sudo systemctl status wazuh-agent

```

시작됨~~

#### 에이전트는 매니저로 로그를 보내고 있는데, 매니저의 룰이 커널 로그 형식을 못 잡음

커널 로그는 형식이 특이해서 if_sid가 다름
```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```
```bash
cat /var/ossec/etc/rules/local_rules.xml
```

룰 확인 결과
```bash
<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->
<!-- Example -->
<group name="local,syslog,sshd,">
  <!--
  Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2
  -->
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
<group name="nmap,recon,">
  <rule id="100001" level="10">
    <if_sid>5706</if_sid>
    <description>Possible Nmap port scan detected</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
  <rule id="100002" level="12">
    <if_sid>5710</if_sid>
    <description>Multiple port scan attempts - possible Nmap SYN scan</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
  <rule id="100003" level="10">
    <if_sid>1002</if_sid>
    <match>PORTSCAN</match>
    <description>Nmap port scan detected via iptables</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
bash-5.2# ^C
```

룰 파일 구조가 잘못되어 있음

100001이 중복으로 두 번 있고, 100003 룰이 </group> 밖에 있어서 Wazuh가 읽지 못함
```bash
cat > /var/ossec/etc/rules/local_rules.xml << 'EOF'
<!-- Local rules -->
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>

<group name="nmap,recon,">
  <rule id="100002" level="10">
    <if_sid>5706</if_sid>
    <description>Possible Nmap port scan detected</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <rule id="100003" level="12">
    <if_sid>5710</if_sid>
    <description>Multiple port scan attempts - possible Nmap SYN scan</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <rule id="100004" level="10">
    <if_sid>1002</if_sid>
    <match>PORTSCAN</match>
    <description>Nmap port scan detected via iptables</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
EOF
```
```bash
/var/ossec/bin/wazuh-control restart
```

실패~~

매니저가 실제로 에이전트 로그를 받고 있는지 확인
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log
```

로그가 계속 생성됨.

SSH 브루트포스 알람이 계속 뜨고 있음.

문제는 /var/log/messages 의 PORTSCAN 로그가 journald 를 통해서 오고 있어서 형식이 달라서 if_sid를 바꿔야 한다. 그레서 if_sid 없이 match만으로 잡기 시
```bash
sudo docker exec -it single-node-wazuh.manager-1 bash

```
```bash
cat > /var/ossec/etc/rules/local_rules.xml << 'EOF'
<!-- Local rules -->
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>

<group name="nmap,recon,">
  <rule id="100004" level="10">
    <match>PORTSCAN</match>
    <description>Nmap port scan detected via iptables</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
EOF
```
```bash
/var/ossec/bin/wazuh-control restart
```

안됨

매니저가 PORTSCAN 문자열을 실제로 받고 있는지 확인:

PORTSCAN 관련 로그가 매니저에 도달하는지 먼저 확인
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log | grep -i "kernel\|iptables\|PORTSCAN"
```

PORTSCAN 로그가 매니저까지 도달을 못 하고 있음.

header_4:

근본 원인은 Wazuh 에이전트가 /var/log/messages를 읽고 있지만 매니저로 전송이 안 되는 것 같다.

에이전트 로그 직접 확인:
```bash
sudo tail -50 /var/ossec/logs/ossec.log | grep -i "messages\|error\|warn"
```

결과
```bash
tail -50 /var/ossec/logs/ossec.log | grep -i "messages\|error\|warn"
2026/04/14 12:07:56 wazuh-logcollector: INFO: (1950): Analyzing file: '/var/log/messages'.
[yhc@localhost python-soc]$
```

/var/log/messages 읽고 있지만 매니저로 안 가고 있음.

에이전트가 매니저(Docker)에 연결확인
```bash
sudo grep -i "connected\|server\|error" /var/ossec/logs/ossec.log | tail -20
```

Failed to get the message from the journal 에러가 계속 나오고 있어서 journald 읽기 권한 문제가 있음.

에이전트가 127.0.0.1:1514 로 연결하고 있는데, 이건 Docker 매니저가 아니라 로컬호스트로 연결

이전에 설정했던 로컬 Wazuh 에이전트가 Docker 매니저랑 헷갈리고 있음.

journald 대신 /var/log/messages 파일 직접 읽도록 설정
```bash
sudo grep -A5 "messages" /var/ossec/etc/ossec.conf
```

결과
```bash
@localhost python-soc]$ sudo grep -A5 "messages" /var/ossec/etc/ossec.conf
  <location>/var/log/messages</location>
</localfile>
  <client>
    <server>
      <address>127.0.0.1</address>
      <port>1514</port>
[yhc@localhost python-soc]$

```

에이전트가 127.0.0.1:1514 로 연결하는데, Docker 매니저는 0.0.0.0:1514 로 열려있음지만 문제는 안됨. 연결이 되어있는 것임.

진짜 문제는 journald 권한이야. Failed to get the message from the journal 에러 때문에 로그 수집이 안 되는 것이다.
```bash
sudo usermod -aG systemd-journal ossec
sudo systemctl restart wazuh-agent

```

Wazuh 에이전트가 다른 사용자로 실행 중
```bash
ps aux | grep wazuh
```

wazuh-agentd 가 wazuh 유저로 실행 중
```bash
sudo usermod -aG systemd-journal wazuh
sudo systemctl restart wazuh-agent

```
```bash
sudo tail -10 /var/ossec/logs/ossec.log
```

Monitoring journal entries 뜨고 에러 없어짐. 권한 문제 해결됨.

다시 테스트

아직 해결 안됨. 알람이 뜨지 않음

grep 없이 alerts.log 전체를 보면서 Kali 스캔 후 새로운 로그가 뜨는지 확인
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log
```

SSH 브루트포스 알람만 계속 오고 있고 PORTSCAN은 없음

에이전트가 /var/log/messages는 읽고 있지만 journald를 통해서 읽고 있어서 kernel 로그가 필터링되는 것 같음.

문제는 journald가 kernel 로그를 별도로 관리해서 /var/log/messages 파일로 안 넘어오는 거 같음

rsyslog 설정 확인:
```bash
sudo cat /etc/rsyslog.conf | grep -i "kern\|messages"
```

.info;mail.none;authpriv.none;cron.none → /var/log/messages

이 설정이 문제

kern.* 은 콘솔로만 가고, /var/log/messages에는 kern 로그가 빠져있음

kern 로그를 /var/log/messages에 추가
```bash
sudo nano /etc/rsyslog.conf

```

다음 줄을 찾은 후
```bash
*.info;mail.none;authpriv.none;cron.none    /var/log/messages
```

바꾸기
```bash
*.info;mail.none;authpriv.none;cron.none;kern.none    /var/log/messages

kern.*    /var/log/messages
```
```bash
sudo systemctl restart rsyslog
```

Kali 스캔 날리고 확인

PORTSCAN 로그가 /var/log/messages에 찍히고 있음

Wazuh가 이걸 잡는지 확인
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log | grep -i "PORTSCAN\|100004"
```

Wazuh 에이전트가 업데이트된 /var/log/messages를 읽고 있는지 확인:

sudo tail -5 /var/ossec/logs/ossec.log

Failed to get the message from the journal 에러

journald 읽기를 완전히 끄고 파일만 읽도록 설정
```bash
sudo nano /var/ossec/etc/ossec.conf
```
```bash
<localfile>
<log_format>journald</log_format>
```

이렇게 바꿈
```bash
udo grep -i "journald" /var/ossec/etc/ossec.conf
```

journald 설정 2개를 제거
```bash
sudo nano /var/ossec/etc/ossec.conf
```

다음 블록을 삭제
```bash
<localfile>
  <log_format>journald</log_format>
</localfile>

<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
</localfile>
```

저장 후
```bash
sudo systemctl restart wazuh-agent
sudo tail -5 /var/ossec/logs/ossec.log
```

Monitoring journal entries

journald 설정이 아직 남아있음

현재 상태 확인
```bash
sudo grep -B1 -A3 "journald" /var/ossec/etc/ossec.conf
```

두 가지 문제

- 첫 번째 블록: journald 포맷으로 /var/log/messages 읽으려 함 → syslog로 바꿔야 해
- 두 번째 블록: journald 자체를 읽으려 함 → 삭제해야 해
```bash
sudo nano /var/ossec/etc/ossec.conf
```

첫 번째 블록
```bash
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/messages</location>
</localfile>
```

두 번째 블록 이거 통째로 삭제
```bash
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
</localfile>
```
```bash
sudo systemctl restart wazuh-agent
sudo tail -5 /var/ossec/logs/ossec.log
```

Monitoring journal entries 에러 사라짐

/var/log/messages 읽고 있는지 확인
```bash
sudo grep "messages" /var/ossec/logs/ossec.log | tail -5
```

Analyzing file: '/var/log/messages' 뜨고 있음

Kali에서 스캔 날리고 알람 확인

하지만 안됨

매니저가 실제로 로그를 받고 있는지 확인

grep 없이 전체 로그 보면서 Kali 스캔 후 kernel 관련 확인
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log
```

아직

SSH 브루트포스만 오고 있고 kernel/PORTSCAN은 없음

매니저가 /var/log/messages 에서 오는 로그를 받고 있는지 확인

에이전트에서 테스트 로그 직접 넣기
```bash
sudo logger -p kern.warning "PORTSCAN: test message from iptables"

```

그 다음
```bash
sudo tail -3 /var/log/messages
```
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -20 /var/ossec/logs/alerts/alerts.log | grep -i "PORTSCAN"
```

에이전트가 이 로그를 매니저로 보내고 있는지 확인
```bash
sudo grep "PORTSCAN" /var/ossec/logs/ossec.log
```

에이전트가 /var/log/messages를 읽고 있지만 매니저로 전송이 안 되고 있음.

에이전트-매니저 연결 상태 확인:

sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

sudo grep "messages" /var/ossec/logs/ossec.log | tail -3

sudo cat /var/ossec/etc/client.keys

에이전트 ID 확인 : 002 RockyLinux

12:43:15에 /var/log/messages 읽기 시작

12:39 :Invalid location value '/var/log/messages' when using 'journald' 경고

매니저에서 002 에이전트 로그 확인:
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -50 /var/ossec/logs/alerts/alerts.log | grep "RockyLinux\|002"

```

RockyLinux 에이전트가 매니저로  /var/log/secure만 보내고 있고 /var/log/messages는 안 보냄

에이전트가 /var/log/messages를 읽기 시작한 게 12:43인데, 그 이후 로그가 매니저에 도착했는지 확인:
```bash
sudo docker exec -it single-node-wazuh.manager-1 grep "messages" /var/ossec/logs/alerts/alerts.log | tail -5

```

매니저가 sudo 명령 로그를 잡고 tail -3 /var/log/messages 한 것까지 기록

/var/log/messages 자체 내용은 안 오고 있음

에이전트가 /var/log/messages를 읽긴 하는데 매니저로 전송을 안 하고 있음

에이전트 설정에서 /var/log/messages 블록이 제대로 있는지 최종 확인:
```bash

sudo grep -A3 "log/messages" /var/ossec/etc/ossec.conf
```

/var/ossec/etc/ossec.conf

그냥 Wazuh 패키지의 원본 설정 파일로 복원
```bash
sudo cp /usr/share/wazuh-agent/etc/ossec.conf /var/ossec/etc/ossec.conf 2>/dev/null || \
sudo find / -name "ossec.conf.rpmnew" 2>/dev/null
```

원본파일이 없어서 새로 만듦
```bash
sudo tee /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <client>
    <server>
      <address>127.0.0.1</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>rocky, rocky9, rocky9.7</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
EOF
```

그다음 검증:
```bash
sudo python3 -c "import xml.etree.ElementTree as ET; ET.parse('/var/ossec/etc/ossec.conf'); print('XML OK')"
```

ok메세지 나옴
```bash
sudo systemctl restart wazuh-agent
sudo tail -5 /var/ossec/logs/ossec.log
```

에러 없이 정상 시작

하지만 로그는 잡히지 않음

Wazuh 에이전트는 Rocky Linux(호스트)에 있고, 매니저는 Docker 컨테이너 안에 있어. 에이전트가 로그를 읽어서 매니저로 보내는데, 매니저 컨테이너가 /var/log/messages를 직접 못 읽는 게 아니라 에이전트가 보낸 로그를 매니저가 룰로 매칭해야 한다.

매니저가 실제로 /var/log/messages 로그를 받고 있는지 확인:
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log
```

Kali 스캔 날리고 messages 또는 kernel 관련 알람이 뜨지를 않는다.

에이전트가 /var/log/messages 로그를 매니저로 전송을 못 하고 있음

에이전트 로그에서 messages 읽고 있는지 확인:
```bash

sudo grep "messages" /var/ossec/logs/ossec.log | tail -5

```

14:01:53에 /var/log/messages 읽고 있지만 매니저로는 안가고 있음

logger로 테스트 메시지 보내고 매니저에서 바로 확인
```bash
sudo logger -p kern.warning "TEST PORTSCAN detection"
```

sudo docker exec -it single-node-wazuh.manager-1 tail -20 /var/ossec/logs/alerts/alerts.log

/var/log/secure 로그는 오는데 /var/log/messages 로그는 안오고 test

메세지도 안옴

에이전트가 /var/log/messages를 읽고는 있는데 전송을 안 하고 있음.

/var/log/messages 파일 권한 문제일 가능성
```bash
ls -la /var/log/messages

```

권한이 root만 읽을 수 있음
```bash

sudo chmod 644 /var/log/messages

```

그다음 logger 테스트:
```bash
sudo logger -p kern.warning "TEST PORTSCAN detection"
```
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -20 /var/ossec/logs/alerts/alerts.log | grep -i "TEST\|messages\|kernel"
```

실패, /var/log/secure 로그만

- ptables로 PORTSCAN 로그 생성 ✅
- /var/log/messages에 로그 찍힘 ✅
- Wazuh 에이전트가 파일 읽음 ✅
- 매니저로 전송 ❌

/var/log/secure는 잘 전송되고 있음

. PORTSCAN 로그를 /var/log/secure로 보내기

imjournal을 쓰고 있어서 /var/log/messages에 kern 로그가 제대로 안 가고 있음

PORTSCAN 로그가 /var/log/secure로도 가서 Wazuh가 잡을 수게 수정
```bash
sudo tee /etc/rsyslog.conf << 'EOF'
# rsyslog configuration file

#### GLOBAL DIRECTIVES ####
global(workDirectory="/var/lib/rsyslog")
module(load="builtin:omfile" Template="RSYSLOG_TraditionalFileFormat")

#### MODULES ####
module(load="imuxsock" SysSock.Use="on")
module(load="imklog")

# Include all config files in /etc/rsyslog.d/
include(file="/etc/rsyslog.d/*.conf" mode="optional")

#### RULES ####
# kern 로그를 secure와 messages 둘 다 기록
kern.*                                                  /var/log/messages
kern.*                                                  /var/log/secure

# 기타 로그
*.info;mail.none;authpriv.none;cron.none;kern.none      /var/log/messages
authpriv.*                                              /var/log/secure
mail.*                                                  -/var/log/maillog
cron.*                                                  /var/log/cron
*.emerg                                                 :omusrmsg:*
uucp,news.crit                                          /var/log/spooler
local7.*                                                /var/log/boot.log
EOF
```
```bash
sudo systemctl restart rsyslog
sudo logger -p kern.warning "TEST PORTSCAN detection"
sudo tail -5 /var/log/secure | grep TEST

```
```bash
sudo systemctl restart rsyslog
sudo logger -p kern.warning "TEST PORTSCAN detection"
sudo tail -5 /var/log/secure | grep TEST

```

/var/log/secure에 TEST 안 찍힘

rsyslog.conf가 제대로 바뀌었는지 확인:
```bash
sudo grep "kern" /etc/rsyslog.conf
```

rsyslog.conf 설정은 맞음

imklog 모듈이 제대로 로드됐는지 확인:
```bash
sudo systemctl status rsyslog | grep -i "error\|fail\|active"
```

rsyslog 정상 실행 중

logger 테스트:
```bash
sudo logger -p kern.warning "TEST PORTSCAN detection"
sleep 3
sudo tail -5 /var/log/secure
sudo tail -5 /var/log/messages
```

/var/log/secure에 드디어 다 찍힘

- kernel: PORTSCAN ✅
- TEST PORTSCAN detection ✅
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.log | grep -i "PORTSCAN\|100004"
```

안됨

/var/log/secure에는 찍히는데 Wazuh가 못 잡고 잇어서 매니저 룰 확인:
```bash
sudo docker exec -it single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml

```

룰은 정상

Wazuh logtest로 직접 테스트 매니저 컨테이너 안에서:
```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```
```bash
echo "Apr 14 14:12:50 localhost kernel: PORTSCAN: IN=ens160 OUT= SRC=192.168.190.130 DST=192.168.190.128" | /var/ossec/bin/wazuh-logtest
```

룰 100004가 매칭확인

bulleted_list:

Rule ID 100001 중복 경고

bulleted_list:

Phase 3에서 Rule 4100 (Firewall rules grouped, level 0)으로 매칭됨 — 우리 룰 100004

Rule 4100이 먼저 매칭되어서 100004가 실행이 안 되고 있음.

100004가 4100의 자식 룰로 동작하도록 수정
```bash
cat > /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>

<group name="nmap,recon,">
  <rule id="100004" level="10">
    <if_sid>4100</if_sid>
    <match>PORTSCAN</match>
    <description>Nmap port scan detected via iptables</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
EOF
```
```bash
/var/ossec/bin/wazuh-control restart
```

### Nmap 탐지 룰 구현 과정

#### 목표

Kali Linux에서 Nmap 포트스캔 시 Wazuh가 탐지하여 알람 발생

#### 시도 1 — Wazuh 기본 룰 활용

Wazuh 매니저 컨테이너에 커스텀 룰 추가 (if_sid: 5706, 5710)

- 결과: 실패 — Nmap SYN 스캔은 /var/log/secure에 기록 안 됨

#### 시도 2 — iptables로 패킷 레벨 로깅
```bash
sudo iptables -I INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j LOG --log-prefix "PORTSCAN: "
```

- 결과: /var/log/messages에 PORTSCAN 로그 생성 성공 ✅

#### 시도 3 — Wazuh 에이전트 /var/log/messages 수집 설정

ossec.conf에 localfile 블록 추가

- 문제 1: log_format이 journald로 설정되어 있어 파일 못 읽음
- 문제 2: /var/log/messages 권한이 root만 읽기 가능 (rw-------)
- 문제 3: ossec.conf XML 구조 오류 (중복 <ossec_config> 태그)
- 해결: ossec.conf 새로 작성, 권한 644로 변경

#### 시도 4 — rsyslog 설정 변경

kern 로그가 /var/log/secure에 안 찍히는 문제

- imjournal → imklog 모듈로 변경
- kern.* 을 /var/log/secure에도 기록하도록 추가
- 결과: /var/log/secure에 PORTSCAN 로그 찍힘 ✅

#### 시도 5 — Wazuh logtest로 룰 매칭 확인

Rule 4100 (Firewall rules grouped, level 0) 이 먼저 매칭

→ 우리 룰 100004가 실행 안 됨

- 해결 방향: 100004 룰에 <if_sid>4100</if_sid> 추가하여 4100의 자식 룰로 동작하도록 수정 중

#### 현재 상태

- iptables PORTSCAN 로그 생성 ✅
- /var/log/secure에 로그 찍힘 ✅
- Wazuh 에이전트 파일 수집 ✅
- 룰 매칭 수정 중 ⬅️ 지금 여기
```bash
docker exec -it single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << EOF
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>

<group name="nmap,recon,">
  <rule id="100004" level="10">
    <if_sid>4100</if_sid>
    <match>PORTSCAN</match>
    <description>Nmap port scan detected via iptables</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
EOF'
```

1. 룰 파일 확인
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```

2. Wazuh manager 재시작
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

3. logtest로 룰 매칭 재확인
```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

logtest 프롬프트에 아래 샘플 로그 붙여넣기:
```bash
Apr 14 12:00:00 localhost kernel: PORTSCAN: IN=eth0 OUT= SRC=192.168.x.x DST=192.168.x.x PROTO=TCP
```
```bash
Rule 4100 fired  → Rule 100004 fired (level 10)
```

성공

- Rule 100004 fired ✅
- level 10 ✅
- MITRE T1046 / Discovery / Network Service Discovery ✅
- Alert to be generated ✅

Rule ID '100001' is duplicated — local_rules.xml에 100001이 두 번
