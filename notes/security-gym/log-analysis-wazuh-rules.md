# [수업 노트] Security Gym 활용1 — 윈도우·리눅스 로그, Wazuh 로그 분석, 디코더·커스텀 룰, MITRE ATT&CK

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## Window log

> 📷 강의 슬라이드(로그란): 시스템·사용자·애플리케이션·네트워크의 행위와 상태를 시간순으로 기록한 데이터로, 시스템이 무슨 일이 있었는지 스스로 설명하는 유일한 수단. 장애 해결·보안 분석·감사에 필수. 로그는 CPU·I/O·디스크를 쓰므로 OS는 핵심 운영·보안 이벤트만 기본 기록하고 세부 추적은 관리자가 켜야 한다. 공격자는 침해 후 가장 먼저 로그를 지우려 한다.

> 📷 Windows 로그 시스템: 이벤트(로그인 성공, 프로세스 생성, 파일 변경 등)가 발생할 때마다 기록하는 이벤트 기반 구조. XML 구조의 바이너리 형식인 EVTX로 C:\Windows\System32\winevt\Logs\에 저장되고 이벤트 뷰어로 읽는다.

> 📷 Windows 로그 종류: Application(앱 충돌·오류), System(커널·서비스·드라이버 — 부팅 실패, 서비스 중단, 장치 오류), Security(감사 정책에 따라 LSA·Winlogon이 기록 — 로그인 성공/실패, 사용자 생성, 권한 상승, 프로세스 실행), Setup(Windows Update·설치 — 패치 이력, 설치 오류).

> 📷 보안상 주요 이벤트 — 외부 유출·무단 접근: 허가되지 않은 USB·외장 HDD 연결이나 공유 폴더 접근은 유출 가능성으로 보고 언제 연결돼 무엇을 했는지 추적. Driver Frameworks 2003~2006(USB 삽입), 2101~2102(해제), Print Service 307(출력 문서), Security 5140(공유 리소스 접근).

> 📷 원격 제어·세션 접근: RDP 등 원격 접속 흔적은 유출 경로가 될 수 있다. Security 4778~4779(RDP 세션 연결·해제), Remote Connection Manager 1149(RDP 인증 성공), Local Session Manager 1024(RDP 세션 생성).

> 📷 흔적 삭제·시간 조작(안티포렌식): 일반 사용자가 로그를 지우거나 시간을 바꿀 일은 거의 없어 은폐 시도로 의심. Security 4616(시스템 시간 변경), 4719(감사 정책 변경), 1102(Security 로그 삭제).

> 📷 프로세스 실행·시스템 조작: 악성코드는 실행 시 프로세스를 만들고, 추가 파일을 드롭하거나 다른 프로세스를 띄워 감염을 넓히며, 서비스 등록·작업 스케줄러로 지속성을 확보한다. Security 4688~4689(프로세스 생성·종료), 4697(서비스 등록), 4672(권한 상승된 세션 시작).

> 📷 Sysmon: Sysinternals의 경량 커널 드라이버+서비스 조합으로 기본 감사 로그가 놓치는 명령 실행·프로세스 관계·네트워크 연결 등을 29개 이벤트로 기록. 위치는 %SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx. 예시 Event 1: mmc.exe가 eventvwr.msc를 실행, 부모 explorer.exe, IntegrityLevel Medium, SHA256 해시 포함.

> 📷 Sysmon 주요 이벤트 ID: 1 프로세스 생성(명령줄 포함), 3 네트워크 연결(외부 IP·포트), 8 다른 프로세스에 스레드 생성(DLL 인젝션·셸코드), 11 파일 생성(드롭 흔적), 13 레지스트리 값 설정(지속성), 26 파일 삭제(누가 무엇을 지웠는지).

> 📷 Windows 로그 강의 요약: 이벤트 로그 분석은 침해 흔적·이상 행위·사용자 활동 추적의 핵심이고, 로그온·프로세스 생성·로그 삭제 같은 중요 이벤트를 알아야 한다. Sysmon은 기본 로그의 한계를 보완해 프로세스 생성·네트워크 연결·파일 생성을 정밀하게 기록한다.


## Linux Log

> 📷 Linux 로그: 커널·서비스·애플리케이션이 남기는 시간·주체·행위·결과 기록(타임스탬프+호스트/프로세스+심각도+메시지). OS 수준 이벤트는 구조화돼 기록되고 데몬·앱·보안 감사는 각자 방식으로 남긴다. Linux는 journald, Windows는 Event Log. 라이프사이클은 수집 → 집계 → 파싱·정규화 → 저장 → 보관·폐기.

> 📷 journald: systemd(부팅 시 가장 먼저 실행돼 서비스를 관리하는 init)의 구성 요소로, 서비스 로그·커널 메시지·syslog API 메시지(로그인·로그아웃·cron·하드웨어 오류·서비스 시작/종료·관리자 명령)를 수집해 /var/log/journal에 바이너리로 저장. Audit·Kernel·Services·Boot·Containers가 journald로 모이며 journalctl로 검색.

systemd:

> 📷 syslog와 rsyslog: 예전에는 init과 별개인 텍스트 기반 syslogd(syslog() API, UDP 514)를 썼고 2004년 안정성을 높인 rsyslogd가 나왔다. 2010년 systemd와 함께 journald가 등장해 구조화·색인(빠른 필터링, 무결성)과 서비스 stdout 자동 수집을 제공. journald는 출력 플러그인·원격 전송이 약해 지금은 journald 단독 또는 journald → rsyslogd 포워딩으로 혼용한다.

> 📷 journald 로그 형식: 단순 문자열이 아니라 key-value 구조로 저장되고 소스마다 필드가 다르다. 주요 필드 _SOURCE_REALTIME_TIMESTAMP(실제 발생 시점), _TRANSPORT(전송 방식), _EXE(실행 파일 경로), _HOSTNAME, _PID, _UID/_GID, _COMM(프로세스명, 예: sshd), _CMDLINE(실행 명령), MESSAGE(본문). journalctl은 이를 일반 텍스트처럼 보여 준다.

> 📷 journald 예시: `journalctl -u sshd.service` → "sshd[1132]: Accepted password for user1 from 192.168.1.10 port 50232 ssh2", pam_unix 세션 열림/닫힘. `-o verbose`로 보면 _BOOT_ID, _MACHINE_ID, _UID=0, _COMM=sshd, _EXE=/usr/sbin/sshd, _SYSTEMD_UNIT=sshd.service, PRIORITY=6, MESSAGE 등 키-값 전체가 보인다. 타임스탬프는 1970-01-01 UTC 이후 마이크로초(Unix Epoch).

> 📷 보안상 중요한 journald 키워드: sudo·su·root(비인가 root 사용), sshd·Accepted·Failed password(무단 접근·비정상 로그인 시간·계정 탈취), systemd-timesyncd·timedatectl(시간 위변조로 로그 은폐), useradd·passwd·usermod(불필요 계정 추가), CRON(백도어·자동화 공격), kernel(루트킷·DoS·하드웨어 장애), systemd(systemctl로 악성 프로세스 시작/종료).

> 📷 auditd: journald는 단순 수집기라 감사 정책·정밀 추적이 없다. auditd는 커널 수준에서 특정 파일·디렉터리 접근, 권한 상승, 시스템 콜 등 누가 언제 무엇에 접근했는지 기록. 룰은 /etc/audit/rules.d/audit.rules, 로그는 /var/log/audit/audit.log(텍스트). 구성: 커널 ↔ auditctl(룰 설정)·auditd(기록) → 로그를 ausearch·aureport·aulast로 조회.

> 📷 보안상 중요한 auditd 키워드(정밀한 만큼 자원을 써서 룰 튜닝 필요, ausearch·auditctl로 검색): EXECVE(명령 실행 — 백도어·수상한 프로세스), CWD/PATH(어느 경로에서 무엇을 실행), FD_PAIR/OPEN/CLOSE(민감 파일 읽기·쓰기), CHDIR/RENAME/UNLINK(로그 삭제·은폐), CONFIG_CHANGE(감사 정책 변경 — 감시 우회), SYSCALL(UID·PID 포함 커널 수준 행위, chmod·mount·ptrace), USER_CMD(사용자 명령 전체).

> 📷 Apache 웹 서버 로그: 시스템 로그 위 계층의 애플리케이션 로그로 클라이언트 요청·응답을 기록. 침해는 웹 서버에서 시작되는 경우가 많아 필수 확인 대상. access.log(누가 언제 무엇을 요청), error.log(서버 오류·경고), 텍스트 형식, 설정 /etc/apache2/apache2.conf, 로그 /var/log/apache2/.

> 📷 Apache Combined Log Format 예: `127.0.0.1 - frank [10/May/2024:13:55:36 +0900] "GET /index.html HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"` — 클라이언트 IP, 인증 사용자, 시각, 요청 줄(메서드·URI·프로토콜), 상태 코드, 응답 크기, Referer(이전 페이지), User-Agent.

> 📷 Apache 로그 의심 징후: 이상 경로(../, %2e%2e/, /.env, /.git — 디렉터리 트래버설·환경/백업 파일 노출·CMS 스캔), 비정상 메서드(PUT, DELETE, PROPFIND, CONNECT — 웹셸 업로드·프록시 터널링), 한 IP의 단시간 수백 건 요청(브루트포스·크롤링·스캐닝), 의심 User-Agent(sqlmap, curl, python-requests), 수 MB 이상 응답(대량 데이터 덤프).

> 📷 로그 로테이션: 로그가 계속 커져 디스크가 차는 것을 막기 위해 시간·용량 기준으로 압축·번호를 붙여 보관하고 새 파일로 기록(access.log → access.log.1.gz, .2.gz …). 일반 텍스트 로그는 logrotate(/etc/logrotate.conf), journald와 auditd는 각자 설정 파일에서 자체 로테이션.

> 📷 Linux 로그 강의 요약: journald는 구조화된 바이너리로 저장하고 필요하면 rsyslog로 포워딩해 호환성을 확보. auditd로 시스템 콜·파일 접근·명령 실행을 정밀 추적하고, Apache 로그로 SQL 인젝션·XSS·디렉터리 스캔 같은 웹 공격 흔적을 분석.


> 📷 실습 네트워크 구조: OPNSense 방화벽(WAN 192.168.44.1 / LAN 192.168.1.1)으로 구역 분리. WAN(신뢰하지 않는 외부)에 Attacker_Kali 192.168.44.10, LAN(보호 대상)에 WEBSrv_Ubuntu 192.168.1.80(에이전트 #1, 웹 서버), HostPC_Win10 192.168.1.70(에이전트 #2), Wazuh 서버 192.168.1.100. 웹 서버는 원래 DMZ에 두지만 편의상 LAN에 배치.

> 📷 WebSrv Ubuntu에서 `vim /var/ossec/etc/ossec.conf` 열기. localfile 앞부분은 파일 대신 명령 결과를 주기적으로 수집하는 블록: `df -P`(command, 360초, 디스크 사용량), `netstat -tulpn` 가공 결과(full_command, alias "netstat listening ports", 열린 포트), `last -n 20`(full_command, 최근 로그인 20건).

> 📷 이어지는 localfile: journald(서비스 시작·중지·시스템 오류), apache 형식 /var/log/apache2/error.log와 access.log(접근 패턴·악성 접속 탐지), syslog 형식 /var/ossec/logs/active-responses.log(Wazuh 자동 대응 기록 — IP 차단·파일 삭제), /var/log/dpkg.log(패키지 설치·업데이트·제거).

> 📷 Windows 10 에이전트 설정 파일: 관리자 권한으로 Notepad++ 실행 → C:\Program Files (x86)\ossec-agent\ossec.conf 열기.

> 📷 Windows ossec.conf localfile: Application·Security·System을 eventchannel 형식으로 수집(Security는 5145, 5156, 5447, 4656, 4658, 4663, 4660, 4670, 4690, 4703, 4907, 5152, 5157 등 대량 이벤트 제외 쿼리), active-response\active-responses.log는 syslog 형식. Application은 앱 이벤트·에러, Security는 로그온·권한 변경·감사, System은 OS 안정성·오류.

> 📷 Sysmon 로그 위치 확인: C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx(약 65MB). Sysmon은 기본 제공이 아니라 설치해야 하며 실습 VM에는 미리 설치돼 있다.

> 📷 Sysmon 수집 추가: ossec.conf의 localfile 블록들 아래에 `<localfile><log_format>eventchannel</log_format><location>Microsoft-Windows-Sysmon/Operational</location></localfile>` 작성.

> 📷 저장 후 서비스(services) 앱에서 Wazuh(Wazuh Windows Agent) 서비스를 우클릭 → Restart.

> 📷 크롬에서 https://192.168.1.100 Wazuh 대시보드 접속(admin, 비밀번호는 실습 VM의 pass.txt) → Explore > Discover. 필드 data.win.system.channel을 선택하면 Security와 함께 Microsoft-Windows-Sysmon/Operational 이벤트가 들어오는 것을 확인할 수 있다.

> 📷 Discover에 'No results match your search criteria'가 뜨면 Wazuh 서버와 Windows의 시간이 맞지 않는 것 — 검색창에서 Date & time settings로 이동해 시간을 맞춘다.

> 📷 Date & time에서 자동 설정이 꺼진 상태로 Change를 눌러 Wazuh 서버 시간과 같게 수동 변경(예: 2025-06-02 9:50 PM).

> 📷 시간을 맞춘 뒤 Discover를 새로고침하면 로그 835건이 보인다(PC_Win10 에이전트 002의 Application·Security 이벤트). 필드에 노란 경고와 'Refresh field list'가 보이면 Dashboards Management → Index patterns → wazuh-alerts-*에서 새로고침 버튼을 누른다.

> 📷 로그가 보이지 않을 때 조치: ① Windows VM 시간을 Wazuh 서버에 맞춤 ② Windows는 서비스에서 Wazuh 재시작 ③ Ubuntu 웹 서버는 root로 `systemctl restart wazuh-agent` ④ Wazuh 서버는 root로 `systemctl restart wazuh-manager`.

> 📷 Wazuh 로그 수집 요약: Ubuntu 에이전트는 기본으로 journald·apache·dpkg 로그를, Windows 에이전트는 Application·Security·System을 수집하며, Sysmon 로그는 ossec.conf를 수정해 추가로 수집한다.


## Wazuh 로그 분석

> 📷 강의 'Wazuh 로그 분석' 목표: Discover에서 로그 필터링 습득 — 필드 구성과 DQL 문법, Ubuntu·Windows별 로그 확인, ossec.conf의 log_alert_level 이해.

> 📷 Discover 인덱스 선택: wazuh-alerts-*(Wazuh가 생성한 보안 경고), wazuh-monitoring-*(Wazuh 자체 상태), wazuh-statistics-*(통계), wazuh-states-vulnerabilities-*(취약점 진단 기능을 켰을 때 생성).

> 📷 왼쪽 필드 목록은 디코더가 로그를 분류한 항목. agent.name 필드를 추가하면 결과 표에 해당 열(PC_Win10)만 표시돼 보기 쉬워진다.

> 📷 검색창 오른쪽 DQL 버튼: OpenSearch Dashboards Query Language(DQL)가 켜져 있으면 DQL 문법으로, 끄면 Lucene 문법으로 검색.

> 📷 DQL 기본 문법: `sshd`(단어 포함), `sshd ping`(둘 중 하나), `"sshd ping"`(정확한 구문), `agent.id: 001`(필드 값), `agent.id: *`(필드 존재), `command: (ssh OR ping)`, `command: 5\*6`(특수 문자 \ ( ) : < > " * 이스케이프), `agent.id: 001 AND command: ssh`, 범위 `time >= "2025-01-01T13:00:00" AND time <= "2025-02-01T01:00:00"`, 와일드카드 `rule.*: win`.

> 📷 SSH 접속 실습 1: Windows cmd에서 `ssh root@192.168.1.80` → root SSH 로그인이 금지돼 있어 Permission denied 3회 후 "Permission denied (publickey,password)".

> 📷 SSH 접속 실습 2: `ssh ubuntu@192.168.1.80`은 성공(Ubuntu 22.04.5 LTS, ens160 192.168.1.80), 이어서 `sudo su`로 root 전환.

> 📷 Ubuntu 웹 서버에서 `journalctl`(바이너리 journald 로그) 확인: sshd[1404] "Failed password for root from 192.168.1.70 port 55016 ssh2" 3회와 PAM 인증 실패, 이어서 sshd[1406] "Accepted password for ubuntu from 192.168.1.70 port 55017", 아래쪽에 `sudo su`로 root 세션이 열린 기록(sudo: ubuntu ; USER=root ; COMMAND=/usr/bin/su).

> 📷 같은 내용을 텍스트 로그 `vim /var/log/auth.log`(SSH·sudo·PAM 인증 등 보안 로그)에서도 확인: authentication failure rhost=192.168.1.70 user=root, Failed password 반복, Accepted password for ubuntu, sudo·su 세션 열림.

> 📷 Windows 쪽 확인: C:\Windows\System32\winevt\Logs의 Security.evtx(약 1GB)와 Microsoft-Windows-Sysmon%4Operational.evtx를 이벤트 뷰어로 연다.

> 📷 Security 이벤트 5156(Windows Filtering Platform이 연결 허용): 애플리케이션 \windows\system32\openssh\ssh.exe, Outbound, 출발지 192.168.1.70:55017 → 목적지 192.168.1.80:22, 프로토콜 6(TCP).

> 📷 Sysmon 이벤트 3(Network connection detected, rule SSH): Image C:\Windows\System32\OpenSSH\ssh.exe, tcp, 192.168.1.70:55016 → 192.168.1.80:22(ssh).

> 📷 Discover에서 `agent.id:001`(WEB_Ubuntu, ID는 Overview에서 확인)로 필터링 → predecoder.program_name 필드에서 su, sudo, sshd 로그 확인. 예: rule.id 5501 PAM: Login session opened, 5402 Successful sudo to ROOT executed(MITRE T1548.003), 5715 sshd authentication success(srcip 192.168.1.70, T1078·T1021).

> 📷 rule.description 필드를 추가하면 어떤 룰에 탐지됐는지 한눈에 보인다: sshd authentication failed(여러 건), connection reset, PAM: User login failed, syslog: User missed the password more than one time, sshd authentication success, Successful sudo to ROOT executed, PAM: Login session opened. rule.level 필드를 더하면 대부분 3, 인증 실패는 5, connection reset 4, 비밀번호 여러 번 틀림은 10.

> 📷 Windows 쪽은 `agent.id:002`(PC_Win10)로 필터링. 펼쳐 보면 Security 이벤트 4688에 commandLine "ssh ubuntu@192.168.1.80", newProcessName C:\Windows\System32\OpenSSH\ssh.exe, parentProcessName C:\Windows\System32\cmd.exe.

> 📷 data.win.eventdata.commandLine 필드만 표시하면 cmd에서 입력한 `ssh ubuntu@192.168.1.80`, `ssh root@192.168.1.80`가 svchost·taskhostw 등 다른 실행 명령 사이에서 바로 보인다.

> 📷 프로세스 계보 분석: newProcessName·commandLine에 parentProcessName·parentCommandLine을 나란히 놓으면 ssh.exe의 부모가 인자 없는 cmd.exe라 사용자가 직접 cmd를 열어 실행한 것임을 알 수 있다. 반대로 `cmd.exe /c ssh.exe user@192.168.1.10 -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o "ProxyCommand=cmd.exe /c echo malicious_command"`처럼 스크립트로 생성됐다면 악성 행위를 의심할 수 있다.

> 📷 data.win.system.channel로 Sysmon을 찾으면 아무것도 안 나온다. 이유는 Wazuh 서버 ossec.conf의 `<alerts><log_alert_level>3</log_alert_level><email_alert_level>12</email_alert_level></alerts>` — 레벨 3 미만(0~2)은 정상으로 보고 alerts.log에 기록하지 않기 때문.

> 📷 `vim /var/ossec/ruleset/rules/0330-sysmon_rules.xml` 확인: rule 184665(Sysmon Event 1), 185000(Event 2), 185001(Event 3), 185002(Event 4) 모두 if_sid 18100, level="0" — 기본 Sysmon 이벤트 ID 3 로그는 레벨 0이라 alerts.log에 저장되지 않아 Discover에서 볼 수 없다.

> 📷 Sysmon 이벤트 3을 Discover에서 보려면 두 가지 방법: ① `<log_alert_level>0</log_alert_level>`로 낮추면 모든 로그가 기록되지만 잡다한 정상 로그까지 쌓여 자원 부담 ② 원하는 룰만 `<rule id="185001" level="3">`(if_sid 18100, match INFORMATION(3), Sysmon - Event 3)으로 올리는 것이 효율적.

> 📷 Wazuh Sample Data: 메뉴 Indexer management → Sample Data에서 Sample security information(FIM, AWS, Office 365, GitHub, ssh, web 등 — 설치됨, Remove data), Sample Malware Detection(VirusTotal, YARA), Sample threat detection and response(Vulnerability Detection, Docker, MITRE ATT&CK)를 추가·삭제해 필터링 연습에 쓸 수 있다.

> 📷 Wazuh 로그 분석 요약: Discover에서 DQL과 필드 구성으로 탐지 로그를 쉽게 식별. Windows → Ubuntu SSH 접속 기록은 Ubuntu에선 journald·auth.log, Windows에선 Security·Sysmon 이벤트로 확인. Wazuh는 모든 로그가 아니라 기본적으로 레벨 3 이상 룰에 걸린 로그만 수집(alert)한다.


## Wazuh 디코더와 룰의 이해와 실습

> 📷 강의 'Wazuh 디코더와 룰의 이해' 목표: Analysis Engine 동작 흐름과 디코더·룰 구조를 이해하고 커스텀 룰로 탐지 능력 확장 — 디코더 구조·원리, 룰 기본 구조, Default·Custom Rule, Rule Order.

> 📷 Analysis Engine: 로그 라이프사이클은 생성 → 수집·전송 → 수신 → 디코딩 → 룰 평가 → 경고 생성. 엔드포인트 에이전트가 수집·전송하면 Wazuh 서버의 Analysis Engine이 디코딩·룰 매칭·경고 생성을 실시간으로 수행한다. 이 원리를 알아야 정확한 탐지 정책과 오탐 감소가 가능.

> 📷 Decoder: Apache·SSH·Windows 등 시스템마다 다른 원시 로그를 정규식으로 분해해 srcip, user, action, status 같은 공통 필드로 표준화 → 하나의 룰셋으로 분석 가능. 디코딩 전에 출처(호스트·프로세스) 같은 기본 정보를 뽑는 Pre-decoding을 모든 로그에 먼저 적용. 예: Apache 텍스트 로그 `192.168.1.10 - - [12/May/2025:10:21:45 +0000] "GET /index.php?id=1 HTTP/1.1" 200 1234 "-" "curl/7.68.0"` → JSON {timestamp, srcip, method GET, url, protocol, status 200, size, user_agent curl/7.68.0, program_name apache}.

> 📷 디코더는 XML로 작성하고 결과는 내부에서 JSON으로 처리. Apache·auditd·Windows·journald 등은 기본 디코더(/var/ossec/ruleset/decoders) 제공, 특수 형식은 커스텀 디코더 작성. 예 sshd 디코더: prematch `sshd\[.*\]:\sFailed password for invalid user`(사전 필터 — 없으면 바로 패스), regex `sshd\[\d+\]:\sFailed password for invalid user (\S+) from (\S+) port (\d+) ssh2`(괄호가 추출 대상), order `dstuser,srcip,srcport`(추출값을 매핑할 필드 순서).

> 📷 처리 예: "sshd[1025]: Failed password for invalid user guest from 192.168.1.50 port 55432 ssh2" → Phase 1 Pre-decoding(timestamp 'May 12 11:14:01', hostname ubuntu, program_name sshd) → Phase 2 Decoding(name sshd, srcip 192.168.1.50, dstuser guest, srcport 55432).

> 📷 Wazuh Rule: 디코딩된 필드 값을 조건과 비교해 경고 여부를 판단하는 XML 조건 집합(위협 탐지, 상관 분석, MITRE 매핑, 자동 대응에 사용). 각 룰은 ID·심각도·매칭 조건·설명·그룹으로 구성. 심각도 0~15: 0 무시, 5 사용자 생성 오류(비밀번호 오류 등 단독으론 위협 아님), 7 "Bad word" 매칭(error·bad 포함), 12 중요 이벤트(시스템·커널 오류, 특정 앱 공격), 15 심각한 공격(오탐 가능성 낮은 즉시 대응). 보통 7 이하는 정보성, 10 이상은 적극 대응 필요.

> 📷 Default Rules: 설치 시 포함되는 내장 룰로 /var/ossec/ruleset/rules에 있으며 Wazuh 팀이 계속 업데이트. 디렉터리 구조 — /var/ossec/etc/decoders/local_decoder.xml, /var/ossec/etc/rules/local_rules.xml(사용자 정의), /var/ossec/ruleset/decoders/, /var/ossec/ruleset/rules/(기본).

> 📷 SSH 로그인 실패 룰 예: `<rule id="5710" level="5"><decoded_as>sshd</decoded_as><match>Failed password for</match><description>SSH authentication failed.</description><group>authentication_failed,sshd</group></rule>` — sshd 디코더로 해석된 로그에 "Failed password for"가 있으면 매칭, description은 대시보드·alerts.json에 표시, group은 필터링·상속 조건에 활용.

> 📷 wazuh-logtest로 같은 SSH 실패 로그를 분석한 결과: decoding(name sshd, srcip 192.168.1.50, dstuser guest) → filtering(id 5710, level 5, "SSH authentication failed.", groups authentication_failed·sshd, firedtimes 1, mail False). 계정 탐색이나 브루트포스 사전 단계일 수 있고, 같은 IP에서 짧은 시간에 반복되면 상위 룰이 추가로 매칭돼 브루트포스로 탐지된다.

> 📷 Custom Rules: 기본 룰셋이 다루지 못하는 조직 고유 요구를 /var/ossec/etc/rules/local_rules.xml에 작성(충돌 방지를 위해 ID 100000~120000 권장). 예: `<group name="ssh, bruteforce"><rule id="100502" level="10" frequency="10" timeframe="60"><if_matched_sid>5710</if_matched_sid><same_srcip /><description>SSH brute-force detected: $(srcip) failed authentication</description></rule></group>` — 같은 IP에서 60초 안에 10회 이상 실패하면 매칭.

> 📷 Rule Order(룰 간 선행 조건): if_sid(특정 룰 ID가 먼저 트리거 — 부모 룰), if_group(특정 그룹의 룰이 먼저 매칭), if_matched_sid(지정 시간 내 일정 횟수 이상 매칭). 위 100502는 5710이 먼저 트리거된 뒤 동일 IP 60초 10회 조건으로 브루트포스를 탐지.

> 📷 디코더·룰 이론 요약: 로그 흐름은 생성 → 수집·전송 → 수신 → 디코딩 → 룰 평가 → 경고. 디코더는 다양한 로그를 공통 구조로 표준화하고, 룰은 디코딩된 필드로 조건을 비교해 경고를 만들며, 커스텀 룰로 조직에 맞게 탐지를 확장할 수 있다.

> 📷 강의 'Wazuh 디코더와 룰 실습' 목표: 디코더·룰 구조 이해와 커스텀 룰 제작, 커스텀 룰 동작 후 생성되는 로그 이해.

> 📷 Wazuh 서버 /var/ossec/ruleset/decoders 목록: 0005-wazuh, 0025-apache, 0040-auditd, 0310-ssh, 0320-sudo, 0350-unix, 0380-windows, 0410-docker 등 로그 종류별 디코더 XML 파일. 디코더는 원시 로그에서 소스·이벤트 타입·세부 필드를 뽑아 룰 적용의 기반을 만든다.

> 📷 `vim 0380-windows_decoders.xml`: MS IIS, MS Firewall, Exchange, Sysmon, Defender, Terminal Services 디코더가 들어 있다. 예: windows-date-format(prematch `^\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d `), 이를 부모로 하는 windows-firewall 디코더(action, protocol, srcip, dstip, srcport, dstport 추출).

> 📷 Sysmon Event ID 1 샘플: Image C:\Windows\System32\cmd.exe, CommandLine `cmd.exe /c whoami`, User ACME\alice, IntegrityLevel High, 부모 ParentImage powershell.exe, ParentCommandLine `powershell.exe -NoP -EncodedCommand …` — 이 로그가 어떻게 디코딩되고 룰이 적용되는지 살펴본다.

> 📷 Sysmon은 이벤트 하나가 여러 줄에 걸친 멀티라인 로그라, Wazuh는 이벤트 ID별로 여러 디코더를 연결한다: Sysmon-EventID#1(prematch INFORMATION\(1\)…HashType, image·srcuser·hash·parentImage 추출), 이어서 같은 이름 Sysmon-EventID#1_new 블록들이 offset="after_regex"로 ProcessGuid·ProcessId·Image·CommandLine → CurrentDirectory·User·LogonGuid·IntegrityLevel·Hashes·ParentProcessId·ParentImage → ParentCommandLine을 차례로 추출.

> 📷 디코더 태그 정리: name(디코더 이름 — 분석 결과에서 어떤 디코더가 쓰였는지 확인), parent(부모 디코더 상속), type(플랫폼·카테고리 분류), prematch(1차 판별 — 이 정규식을 포함한 줄만 대상), regex(추출할 정보 정의), offset=after_regex(직전 매칭 지점 이후부터 다시 읽어 남은 필드 추출), order(추출값이 들어갈 필드).

> 📷 룰은 /var/ossec/ruleset/rules/에 있다. `cd /var/ossec/ruleset/rules` 후 ls로 0800-sysmon_id_1.xml, 0810-sysmon_id_3.xml, 0830-sysmon_id_11.xml, 0850-sysmon_id_13.xml 등을 확인하고 `vim 0800-sysmon_id_1.xml`로 Sysmon Event ID 1 룰을 연다.

> 📷 기본 룰 92002(level 6): if_sid 92000(스크립트 엔진이 다른 프로세스를 호출할 때 매칭)인 로그 중 win.eventdata.commandLine에 pcre2 `\\cmd\.exe`가 있으면 매칭 — wscript.exe·cscript.exe(VBScript·JScript 엔진)가 cmd.exe를 자식으로 띄운 상황(파일리스 공격)을 잡는 행위 탐지. options no_full_log(알림에서 전문 생략), description "Scripting interpreter spawned Windows command shell instance", MITRE T1059.003.

> 📷 커스텀 룰은 `vim /var/ossec/etc/rules/local_rules.xml`에 작성. 기본 예시: group "local,syslog,sshd,"의 rule 100001(level 5) — if_sid 5716, srcip 1.1.1.1, "sshd: authentication failed from IP 1.1.1.1.", group authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5.

> 📷 실습 커스텀 룰(비업무 시간 로그인): `<group name="login_night,login_time"><rule id="100500" level="6"><if_sid>92027</if_sid><time>11 pm - 8 am</time><description>Successful login during non-business hours.</description></rule></group>` — 정상 로그인도 23:00~08:00(서버 로컬 시각)이면 위험 신호로 보는 관제 정책. 실습에선 VM 재시작이 어려워 powershell.exe 실행 시 트리거되도록 if_sid를 92027로 바꾸고 시간도 실습 시간에 맞춘다.

> 📷 local_rules.xml에 100500 룰 그룹을 추가해 :wq로 저장(27줄, 711B) 후 `systemctl restart wazuh-manager`로 적용.

> 📷 Windows PC에서 PowerShell 창에 `powershell.exe` 실행 → Discover에서 rule.id 필드로 보면 100500이 탐지됨(agent PC_Win10 192.168.1.70, commandLine "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", Windows PowerShell 10.0.19041.546).

> 📷 Threat Hunting 탭(PC_Win10, 567건)에서도 확인: "Successful login during non-business hours." level 6, rule 100500, groups login_night·login_time. 주변에는 67027 "A process was created"(3), 60106 Windows Logon Success(3), 92213 "Executable file dropped in folder commonly used by malware"(15) 등.

> 📷 디코더·룰 실습 요약: 디코더는 멀티라인 로그를 처리하려고 여러 디코더를 체이닝으로 연결하고, 룰은 구조화된 로그를 읽어 조건에 맞으면 alert를 낸다. 기본 룰셋은 일반 상황용이라 조직의 정책·운영 시간·중요 사용자·민감 시스템을 반영하려면 커스텀 룰이 필수.


> 📷 강의 'MITRE ATT&CK 이해' 목표: ATT&CK이 무엇이고 어떻게 활용하는지, TTPs 매트릭스 구조 이해 — 등장 배경, 실무 활용, 공격자 행위 기반 매트릭스.

> 📷 MITRE ATT&CK: MITRE가 관리하는 무료 공개 사이버 위협 지식 베이스(Adversarial Tactics, Techniques, and Common Knowledge). 공격을 14개 전술과 수백 개의 기법·하위 기법으로 분류하며 탐지·대응, 위협 인텔 공유, 보안 운영 자동화, 솔루션 평가 기준에 쓰인다. 슬라이드에는 Initial Access부터 Command and Control까지의 ATT&CK 매트릭스 표.

> 📷 ATT&CK 프레임워크는 공격자 행동을 TTP로 구조화 — 왜(Tactics), 어떻게(Techniques), 구체적으로 무엇을(Procedures). 그림: 전술 아래 여러 기법, 기법 아래 하위 기법이 달린 트리, 그리고 실제 매트릭스에서 상단 행이 전술, 열 아래가 기법·하위 기법(예: Lateral Movement 열).

> 📷 Tactics(전술)=공격자의 목적("무엇을 하려 했나"). 12~14개 전술을 공격 단계 순서로 배열해 흐름을 한눈에 볼 수 있게 한다. 예: "정보 수집 → 피싱으로 초기 접근 → 악성코드 실행·지속성 확보 → 탐지 회피 → 다른 시스템으로 이동·계정 탈취"를 TA0043 Reconnaissance → TA0001 Initial Access → TA0002 Execution → TA0003 Persistence → TA0005 Defense Evasion → TA0008 Lateral Movement → TA0006 Credential Access로 표현.

> 📷 전술 ID 표: TA0043 정찰, TA0042 자원 개발, TA0001 초기 접근, TA0002 실행, TA0003 지속성 확보, TA0005 탐지 회피, TA0006 자격 증명 접근, TA0007 환경 탐색, TA0008 수평 이동, TA0009 수집, TA0011 명령 및 제어, TA0010 탈취(유출), TA0040 영향(조작·중단·파괴).

> 📷 Techniques(기술)=전술을 수행하는 구체적 수단(How). 기법마다 고유 ID가 있어 같은 방식으로 분류·소통할 수 있다. 예 T1110 Brute Force 페이지: 하위 기법 .001 Password Guessing, .002 Password Cracking, .003 Password Spraying, .004 Credential Stuffing, 전술 Credential Access, 플랫폼·버전·수정일. 서술 예: "Spearphishing Attachment(T1566.001)로 초기 접근 → PowerShell(T1059.001)로 명령 실행 → Registry Run Key(T1547.001) 등록으로 재부팅 후에도 자동 실행되는 지속성 확보".

> 📷 Procedure(절차)=실제로 수행한 구체적 방식(Exactly how). ATT&CK에서는 정해진 형식 없이 APT 그룹 페이지의 Techniques Used 표에 들어 있다. 예 Lazarus Group: 키로거 KiloAlfa가 CreateProcessAsUserA로 토큰 사용(T1134.002), Operation Dream Job에서 AD 서버에 관리자 계정 목록 질의(T1087.002), 캠페인용 도메인·서버 확보(T1583), Github·DropBox·OneDrive로 악성 파일 호스팅, Responder로 LLMNR/NBT-NS 포이즈닝(T1557.001), HTTP/HTTPS C2(T1071.001).

> 📷 Adversary Emulation Plan: 실제 공격자 행위를 흉내 내 탐지·대응을 점검하는 시뮬레이션. 흐름도는 스피어피싱 메일 → DOCX(DDEAUTO) → mshta.exe → HTA 다운로드 → Excel → 난독화 매크로 → rundll32.exe 코드 인젝션 → 비콘 DLL을 메모리에만 다운로드 → 디코딩 → reflective DLL 인젝션. 대응 ATT&CK ID: T1566.001, T1559.002, T1218.005, T1055, T1140, T1059.005, T1027, T1106, T1129, T1105, T1055.001, T1071.001. 하단 표는 단계별 실제 명령·절차(예: DDEAUTO로 mshta.exe http://teamserver/security-update 실행, C2와 SSL/TLS 암호화 통신 T1032).

> 📷 고통의 피라미드(David Bianco): 해시값(Trivial) → IP 주소(Easy) → 도메인(Simple) → 네트워크/호스트 아티팩트(Annoying) → 툴(Challenging) → TTP(Tough). 하단 지표는 탐지는 쉬워도 공격자가 쉽게 바꾸고, 상단의 도구·행동 패턴을 탐지해야 공격자가 전술 자체를 바꿔야 하는 부담을 진다 → 단순 IOC가 아닌 TTP 기반 분석이 필요.

> 📷 ATT&CK 활용 배경: 기존 보안은 로그·IOC·취약점 중심이라 공격자가 어떻게 행동했는지 구조화된 정보가 부족했다. ATT&CK이 기법을 ID(T1059 등)로 표준화해 기관 간 보고서·탐지 룰·정책의 상호 운용성이 높아졌고 SIEM·EDR도 룰을 MITRE ID에 매핑하는 추세 — 글로벌 보안 커뮤니티의 '공통 언어'. 예: KISA가 2023년 6월 공개한 10번째 TTPs 프로파일링 보고서도 침해 과정 전체를 ATT&CK으로 설명.

> 📷 실무 활용: 보안 운영(SIEM·EDR·Wazuh·Suricata 룰 매핑, Navigator로 커버리지 시각화), 레드·블루팀(공격 시나리오 작성, Atomic Red Team·Caldera로 탐지 역량 평가), 위협 인텔(APT 그룹 TTP 분석으로 패턴 파악·사전 대응). 화면: Wazuh MITRE ATT&CK 모듈의 Framework 탭(최근 30일 전술별 건수 — Defense Evasion 1841, Privilege Escalation 1395, Execution 1127 등; 기법별 T1087 Account Discovery 851, T1059.003 749, T1055 719 등)과 ATT&CK Navigator의 Lazarus Group(G0032) 레이어.

> 📷 MITRE ATT&CK 이해 요약: 실제 공격자 전술·기법으로 위협 행위를 체계화한 프레임워크이고 매트릭스가 이를 시각화한다. TTP는 목적(Tactics)·방법(Techniques)·실제 세부 절차(Procedures)로 이루어지며, 기관·도구·팀 간 공통 언어로 보안 운영·탐지 강화·위협 인텔 전반에 쓰인다.


수)

01. 나는 보안 솔루션 EDR, SIEM, XDR의 특징 및 차이를 이해하고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

02. 나는 Wazuh 아키텍처(Agent, Server, Indexer, Dashboard)의 구조 및 기능을 설명할 수 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

03. 나는 Wazuh 에이전트를 직접 호스트에 설치할 수 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

04. 나는 Wazuh 에이전트의 설정 파일인 ossec.conf 파일 내부 구조를 설명할 수 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

05. 나는 Windows의 주요 이벤트(Application, System, Security, Setup) 로그에 대해 이해하고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

06. 나는 Sysmon 이벤트 로그에 대해서 이해하고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

07. 나는 Linux의 대표적인 로그인 journald, syslog, rsyslog 및 auditd 로그에 대해서 이해하고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

08. 나는 프로세스의 이상징후를 식별하는 방법을 몇 가지 설명할 수 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

09. 나는 Wazuh 에이전트의 ossec.conf 파일에서 원하는 로그 파일을 추가적으로 수집하도록 설정을 변경할 수 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

10. 나는 Wazuh 대시보드에서 수집한 로그를 분석할 수 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

11. 나는 Wazuh가 디코더를 통해 다양한 로그 메시지를 일관된 형식으로 관리하는지 설명할 수 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

12. 나는 Wazuh의 룰 구조를 이해하고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

13. 나는 간단한 커스텀 룰을 작성하는 스킬을 가지고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

14. 나는 MITRE ATT&CK의 TTPs(Tactics, Techniques, Procedures)에 대해 이해하고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

15. 나는 Wazuh에서 Wazuh 에이전트가 수집한 로그를 TTPs 관점에서 분류를 할 수 있는 스킬을 가지고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

16.  나는 FIM(File Integrity Monitoring)의 개념에 대해 이해하고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

17. 나는 Wazuh에서 제공하는 FIM 기능을 세부적으로 설정하는 스킬을 가지고 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

18. 나는 악성 파일을 이용한 스피어 피싱 공격 기법을 이해하고 대표적인 과정을 간단히 설명할 수 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

19. 나는 Wazuh의 다양한 기능을 사용하여 공격 흐름을 따라가며 발생된 IOC 정보를 정리 수 있다.

1. 전혀 그렇지 않다2. 그렇지 않다3. 보통이다4. 그렇다5. 매우 그렇다

(필수)

20. 나는 발생한 이벤트 로그가 어떤 행위를 의미하는지 유추할 수 있는 스킬을 가지고 있다.
