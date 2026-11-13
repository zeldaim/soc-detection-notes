# SSH 브루트포스 커스텀 룰(100001) 탐지 실패

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

SSH 룰 XML
```bash
# 1. Wazuh Manager 컨테이너 접속
sudo docker exec -it single-node-wazuh.manager-1 bash
 # 2. 커스텀 룰(ID: 100001) 작성
 # if_matched_sid를 5760(sshd: authentication failed)으로 설정하여 탐지 트리거 생성
cat > /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="custom_rules">
  <rule id="100001" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>SSH Brute Force Attack Detected - MITRE T1110</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
EOF
 # 3. 설정 적용을 위한 컨테이너 재시작
exit
sudo docker restart single-node-wazuh.manager-1
```

> 📷 Wazuh Threat Hunting 화면(최근 24시간 601건). agent 003에서 5557(unix_chkpwd 비밀번호 확인 실패)·5760(sshd 인증 실패, T1110.001/T1021.004)이 반복되고, 5763(sshd brute force, level 10)이 발동함. 커스텀 룰 100001은 목록에 없음.

룰은 작동하고 있지만 커스텀 룰은 100001은 안보임.

- 5557 — unix_chkpwd: Password check failed (level 5)
- 5760 — sshd: authentication failed (level 5)
- 5763 — sshd: brute force trying to get access (level 10) ← 이게 Wazuh 기본 브루트포스 룰

100001이 바라보는 5760이 쌓이면 5763이 먼저 발동한다.
```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
grep -r "5763" /var/ossec/ruleset/rules/
```

5763룰 열어 frequency/timeframe 설정을 확인하고, 조건이 100001이랑 겹치는지 확인한다.

> 📷 `grep -r "5763" /var/ossec/ruleset/rules/` 결과: `0095-sshd_rules.xml`의 `<rule id="5763" level="10" frequency="8" timeframe="120" ignore="60">`.

5763 기본 룰 조건:

- frequency="8" timeframe="120" → 120초 내 8회

그런데 나의 100001 조건:

- frequency="5" timeframe="60" → 60초 내 5회
```bash
grep -r "100001" /var/ossec/etc/rules/local_rules.xml
```

> 📷 `grep -r "100001" local_rules.xml` 결과: `<rule id="100001" level="5">` — 작성한 level 10·frequency 조건이 아니라 level 5짜리 다른 룰이 들어가 있음.

커스텀 룰이 초기 설정과 다르게 설정되어 있음을 확인함.

전체 내용 확인
```bash
cat /var/ossec/etc/rules/local_rules.xml
```

> 📷 당시 `local_rules.xml` 전체: 100001(level 5, if_sid 5716, srcip 1.1.1.1 단순 탐지), 100004(level 10, if_sid 4100, match PORTSCAN, T1046), 100005(level 10, if_sid 31103, url에 union|select|insert|drop|delete|update|cast|exec|declare|--|%27|%3B, T1190).

- 100001 — IP 1.1.1.1 SSH 실패 단순 탐지 (브루트포스 chaining 아님)
- 100004 — Nmap 포트스캔 ✓
- 100005 — SQL Injection 단순 탐지 ✓

룰 수정
```bash
cat > /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="local,syslog,sshd,">
  <rule id="100001" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>SSH Brute Force Attack Detected - MITRE T1110</description>
    <mitre>
      <id>T1110</id>
    </mitre>
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

<group name="web,sqli,">
  <rule id="100005" level="10">
    <if_sid>31103</if_sid>
    <url>union|select|insert|drop|delete|update|cast|exec|declare|--|%27|%3B</url>
    <description>SQL Injection attempt detected</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>
  <rule id="100006" level="12" frequency="5" timeframe="60">
    <if_matched_sid>100005</if_matched_sid>
    <same_source_ip />
    <description>SQL Injection Brute Attack - 5 attempts in 60s - MITRE T1190</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>
</group>
EOF
```

재시작
```bash
exit
sudo docker restart single-node-wazuh.manager-1
```

확인

> 📷 룰 수정·재시작 후 Threat Hunting(5,068건): 5760·5557·5503과 함께 **100001 "SSH Brute Force Attack Detected - MITRE T1110" (level 10)** 이 발동한 것을 확인.

- rule.id: 100001
- rule.description: SSH Brute Force Attack Detected - MITRE T1110
- rule.level: 10
```bash
5760 (sshd authentication failed) — 개별 실패 감지
      ↓ 60초 내 5회 쌓임
100001 (SSH Brute Force Attack Detected) — level 10 발동 ✓
```

- 100001 — SSH 브루트포스 chaining ✓
- 100004 — Nmap 포트스캔 ✓
- 100005 — SQL Injection 단순 탐지 ✓
- 100006 — SQL Injection chaining (추가됨, 아직 미검증)
