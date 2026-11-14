# [수업 노트] 방화벽과 웹 방화벽(FW·WAF) 실습 — OPNSense, ModSecurity

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## 🔥 방화벽 보안 강좌 정리
> 방화벽 개념부터 OPNSense 실습, IPS/WAF 실습까지 정리한 보안 학습 노트.

홈 SOC 랩(OPNSense + Wazuh) 연계 실습 포인트 포함.

### 📚 목차

#### Part 1. 방화벽 이론

- 1-1. 방화벽 개요
- 1-2. 방화벽 작동 방식
- 1-3. 네트워크 배치 및 도입 고려사항

#### Part 2. OPNSense 실습 환경

- 2-1. 실습 네트워크 구성
- 2-2. 기본 통신 확인

#### Part 3. OPNSense 실습 시나리오

- 3-1. Outbound NAT를 활용한 내부 네트워크 은닉
- 3-2. 포트 주소 기반 접근통제
- 3-3. IPS 플러그인(Suricata)을 이용한 유해패턴 탐지

#### Part 4. ModSecurity WAF

- 4-1. WAF 개요 및 ModSecurity 개념
- 4-2. 실습 환경 및 설정 파일 구조
- 4-3. 룰셋 문법 — ARGS & REQUEST_URI 실습

### Part 1. 방화벽 이론

#### 1-1. 방화벽 개요

정의: 네트워크 사이의 경계에 위치하여 허가되지 않은 접근으로부터 보호대상 네트워크를 보호하는 보안 솔루션

#### 세대별 역사

#### 구현 방식별 종류
> 💡 홈랩 연계: OPNSense = 소프트웨어 방화벽(가상 어플라이언스). 범용 CPU 처리라 하드웨어 방화벽 대비 처리량 한계 존재.

#### 1-2. 방화벽 작동 방식

패킷이 지나갈 때 여러 단계 검사 메커니즘을 통해 허용/차단을 결정. 각 작동방식은 동시에 이루어진다.

패킷 필터링 검사 범위:
```plain text
이더넷 헤더 → IP 헤더 → TCP/UDP 헤더 → 응용계층 헤더 → 페이로드
```

#### 방화벽 vs IPS vs WAF 비교

#### 1-3. 네트워크 배치 및 도입 고려사항
```plain text
외부 네트워크
      │
   [방화벽]
   ┌───┴────────────┐
DMZ 네트워크    [방화벽]
(외부/내부       ┌────┴────┐
접속 가능)  내부 네트워크  격리 네트워크
           (외부통신 가능) (내부만 접근)
```

### Part 2. OPNSense 실습 환경

#### 2-1. 실습 네트워크 구성
```plain text
[WAN Network: 192.168.10.0/24]
  Attacker_Kali   WAS01_CentOS5   WAS02_CentOS4   WAS03_Ubuntu10
  .10.10          .10.20          .10.30          .10.40
                        │
               OPNSense_FreeBSD
               WAN: 192.168.10.1
               LAN: 192.168.20.1
                        │
[LAN Network: 192.168.20.0/24]
  Desktop_Win10
  .20.10
```

#### 2-2. 기본 통신 확인

공격자 → 방화벽 PING (Attacker_Kali)
```bash
ping 192.168.10.1
# 결과: 100% packet loss → 방화벽이 ICMP 응답 차단 (ping sweep 방지)

arp -an
# ARP 캐시에는 방화벽 MAC 주소 존재 → NIC는 살아있음
```

내부 → 외부 통신 (Desktop_Win10)
```shell
ping -n 1 192.168.10.10   # TTL=63 (방화벽 한 홉 경유)
ping -n 1 192.168.20.1    # TTL=64 (방화벽 LAN 직접)
```
> TTL이 1 감소 = 방화벽(게이트웨이) 한 홉 경유. 패킷 경로 추적에 활용.

### Part 3. OPNSense 실습 시나리오

#### 3-1. Outbound NAT를 활용한 내부 네트워크 은닉

#### 핵심 개념
> ⚠️ NAT와 방화벽 필터링은 완전히 독립적으로 동작. NAT가 없어도 패킷은 통과하지만 내부 IP가 노출됨.
```plain text
[NAT 정상]   Desktop(192.168.20.10) → 방화벽 변환 → 외부: 192.168.10.1
[NAT 초기화] Desktop(192.168.20.10) → 변환 없음  → 외부: 192.168.20.10 노출!
```

#### OPNSense Outbound NAT 설정

경로: Firewall → NAT → Outbound → Manual 모드 선택

#### PF 처리 순서 (FreeBSD)
```plain text
패킷 수신 → 정규화 → NAT(nat-to) → 필터링(block/pass) → 라우팅
```
> NAT가 필터링보다 먼저 처리됨.
```bash
# pfctl로 NAT 룰 확인
pfctl -sn
# NAT 적용 후:
# nat on em1 inet from (em0:network) to any -> (em1:0) port 1024:65535
```

#### 결과 비교 (Wireshark)

#### 3-2. 포트 주소 기반 접근통제

시나리오: 악성코드 유포 사이트(192.168.10.20)로의 일반 접근은 차단하되, SSH 원격 관제는 허용

#### 적용 룰 (순서 중요!)
```plain text
✅ 올바른 순서:
1. Pass  | LAN | TCP | LAN Net → 192.168.10.20:22 (SSH 허용)
2. Block | LAN |     | LAN Net → 192.168.10.20    (전체 차단)
3. Pass  | LAN |     | LAN Net → *               (기본 허용)
```
> ⚠️ OPNSense는 first-match 방식. SSH 허용 룰이 Block 룰보다 위에 있어야 함.

#### 결과 확인
```shell
# Desktop_Win10
# 브라우저 접속 → 차단
# SSH 접속 → 성공
ssh root@192.168.10.20   # password: lab
```

로그 확인: Firewall → Log Files → Live View

#### 3-3. IPS 플러그인(Suricata)을 이용한 유해패턴 탐지

#### Suricata 설정

경로: Services → Intrusion Detection → Administration

#### malicious.rules 룰 문법
```plain text
# alert 모드 — 탐지만, 차단 안 함
alert tcp any any -> any any (msg:"Malicious file pattern test1"; sid:2;
flow:to_client,established; file_data; content:"MALSIG1"; depth:16;)

# drop 모드 — 탐지 + 차단
alert tcp any any -> any any (msg:"Malicious file pattern test2"; sid:3;
flow:to_client,established; file_data; content:"MALSIG2"; depth:16;)
```

#### alert vs drop 차이

로그 확인: Services → Intrusion Detection → Alerts

### Part 4. ModSecurity WAF

#### 4-1. WAF 개요 및 ModSecurity 개념

WAF(Web Application Firewall): HTTP/HTTPS 요청과 응답의 내용을 분석하여 웹 애플리케이션 계층(L7)의 공격을 탐지·차단하는 보안 시스템.

ModSecurity: Apache, Nginx, IIS에 모듈 형태로 탑재되는 오픈소스 WAF.

#### Process Phases (처리 단계)

#### 주요 지시자
```plain text
# 예시
SecDefaultAction "phase:1,deny,log,auditlog,status:403"
SecDefaultAction "phase:1,deny,log,auditlog,status:403,t:lowercase,t:urlDecodeUni,t:htmlEntityDecode"
```

#### 4-2. 실습 환경 및 설정 파일 구조

#### tortix_waf.conf 주요 설정
```plain text
SecAuditEngine RelevantOnly          # 매칭된 요청만 로그 기록
SecAuditLogType Serial               # 이벤트마다 고유 ID 부여
SecAuditLog logs/modsec_audit.log    # 로그 저장 경로

SecRule REQUEST_METHOD "(PUT|DELETE|TRACE)" "deny,log"  # 위험 HTTP 메서드 차단

SecRequestBodyAccess On              # 요청 본문 검사
SecResponseBodyAccess On             # 응답 본문 검사
SecResponseBodyMimeType (null) text/html text/plain text/xml
SecResponseBodyLimit 524288          # 응답 본문 최대 512KB
```

#### 4-3. 룰셋 문법 — ARGS & REQUEST_URI 실습

#### SecRule 문법 구조
```plain text
SecRule  VARIABLES  OPERATOR  [ACTIONS]
```

#### 주요 VARIABLES

#### 주요 OPERATOR

#### 실습 #1 — ARGS로 셸코드 탐지
```bash
# CentOS5에서 룰 추가
vi /etc/httpd/modsecurity.d/tortix_waf.conf
# 아래 룰 추가
SecRule ARGS ^shell. "id:7,redirect:/error.html"
:wq!
service httpd restart
```
```bash
# Kali에서 테스트
Firefox http://192.168.10.20/coremall
# 검색창에 'shellcode' 입력 → /error.html 리다이렉트
```
```bash
# 로그 확인
cat /var/log/httpd/modsec_audit.log | grep id[[:space:]]\"7\"
# Pattern match "^shell." at ARGS:ps_search.
```

#### 실습 #2 — REQUEST_URI로 경로 기반 탐지
```bash
# 정규식 패턴 탐지
SecRule REQUEST_URI "@rx patt+ern" "id:7,redirect:/error.html"

# 어드민 페이지 접근 차단
SecRule REQUEST_URI "admin" "msg:'Admin',redirect:/error.html"
```
```bash
# 테스트
Firefox 192.168.10.20/webhack/pattttttttttern   # → error.html
Firefox 192.168.10.20/webhack/admin.php          # → error.html
```
> 💡 patt+ern 정규식: +는 앞 문자(t)가 1회 이상 반복. 변형 URL 우회 공격 탐지에 활용.

### 🔗 홈랩 연계 포인트

### 📝 보안기사 시험 대비 포인트

- 방화벽 세대별 특징 (1~4세대)
- 패킷 필터링 vs 상태기반 vs DPI 차이
- NAT(Stateful) vs 방화벽 필터링 독립성
- Suricata alert vs drop 액션 차이
- ModSecurity SecRule 문법 구조: SecRule VARIABLES OPERATOR [ACTIONS]
- ModSecurity Phase 1~5 처리 단계
- WAF vs IPS vs 방화벽 계층별 차이
> ⚠️ Note: 강좌 진행 중. 이후 섹션 추가 예정.

> 📷 윈도우 클라이언트 `ipconfig`: IPv4 192.168.20.10, 서브넷 마스크 255.255.255.0, 기본 게이트웨이 192.168.20.1(방화벽 LAN 쪽).

> 📷 Kali에서 `ping 192.168.10.1` → 11개 전송, 0개 수신(100% 손실). `arp -an` 결과 192.168.10.1이 `<incomplete>` — ARP 응답이 없어 MAC을 못 얻은 상태(같은 L2에 도달 못 함).


## 네트워크 기초 정리
> ifconfig → 서브넷 마스크 → 게이트웨이 개념 흐름 정리

### 1. ifconfig란?

Interface Configuration의 약자. 네트워크 인터페이스를 조회·설정하는 명령어.

#### Kali에서 주요 사용 목적

#### ifconfig vs ip (현대 명령어)
> 💡 실무에서는 ip 명령어가 표준. 오래된 튜토리얼은 ifconfig 많이 사용.

### 2. wlan0이 없는 이유

VM 환경(VMware / VirtualBox)에서는 무선 랜카드가 기본적으로 패스스루 안 됨.

- VM은 호스트의 WiFi를 직접 못 씀
- 가상 유선(eth0 or ens33)만 보임
- 모니터 모드 실습 필요 시 → USB 무선 랜카드 + VM USB 패스스루 설정 필요

#### 인터페이스 확인 명령어
```bash
ip link show       # 모든 인터페이스 목록
iwconfig           # 무선 인터페이스만
lsusb              # USB 랜카드 인식 여부
dmesg | grep wlan  # 드라이버 오류 확인
```

### 3. 서브넷 마스크

#### 255.255.255.0 의미
```plain text
255  .  255  .  255  .  0
11111111.11111111.11111111.00000000
```

- 1인 비트 → 네트워크 부분 (고정, 건드리지 말 것)
- 0인 비트 → 호스트 부분 (자유롭게 사용)
> 255 = 11111111 (2진수) → 8비트 전부 1 → "이 옥텟은 네트워크 식별자"

0 = 00000000 → 8비트 전부 0 → "이 옥텟은 호스트 번호로 자유롭게 써"

#### 예시 분석 (ipconfig 결과 기준)
```plain text
IP:     192.168.20.10
Mask:   255.255.255.0  (/24)
GW:     192.168.20.1
```

### 4. 네트워크 주소 / 호스트 주소 / 브로드캐스트

#### 아파트 비유
```plain text
아파트 단지명: "192.168.20 단지"   → 네트워크 주소
각 호수: .1, .2, .10, .254 ...     → 호스트 주소
관리사무소 방송: .255               → 브로드캐스트
```

#### 왜 이렇게 나누는가?

나누지 않으면 → 인터넷의 수십억 장비가 전부 같은 네트워크 → 패킷 전송 시 전 세계에 "이 장비 어딨어?" 물어봐야 함 → 네트워크 즉시 마비

구역을 나눠서 트래픽을 격리하는 것이 핵심 목적.

#### 세 개의 역할 정리

### 5. 게이트웨이

#### 게이트웨이 = 라우터

물리적으로 동일한 장비. VM 환경에서는 VMware가 가상 라우터 역할 수행.
```plain text
[Windows .10] --- [Kali .X] --- [게이트웨이/라우터 .1] --- [인터넷]
        └─── 같은 네트워크 ───┘         └─── 외부 ───┘
```

### 6. 같은 대역에서만 통신 가능한 이유

#### 핵심: 규칙이다 (소프트웨어적 판단)

패킷이 물리적으로 못 가는 게 아니라, OS가 보내기 전에 목적지를 판단하는 로직.

#### 판단 흐름
```plain text
패킷 생성
    ↓
AND 연산으로 같은 대역인지 판단
    ↓
같음  → ARP로 MAC 주소 찾아서 직접 전송
다름  → 게이트웨이 MAC 주소로 전송 (이후 라우터가 처리)
```

#### AND 연산 예시
```plain text
내 IP:         192.168.20.10  &  255.255.255.0  =  192.168.20.0
목적지 IP:     192.168.20.50  &  255.255.255.0  =  192.168.20.0

결과 같음 → 직접 통신
```
```plain text
내 IP:         192.168.20.10  &  255.255.255.0  =  192.168.20.0
목적지 IP:     8.8.8.8        &  255.255.255.0  =  8.8.8.0

결과 다름 → 게이트웨이(192.168.20.1)로 전송
```

#### 규칙을 어기면?

라우팅 테이블을 수동 수정하면 다른 대역이어도 직접 보낼 수 있음 → 정적 라우트(Static Route) 설정이 그 개념.
> ✅ "다른 대역이면 못 간다" ❌

✅ "기본 규칙상 게이트웨이를 거친다" ✅

### 요약
```plain text
서브넷 마스크 → 어디까지가 내 네트워크인지 정의
AND 연산      → 같은 대역인지 판단하는 실제 계산
게이트웨이    → 다른 대역으로 나가는 출구 (= 라우터)
브로드캐스트  → 같은 대역 전체에 동시 전송
```


## 방화벽 개요

### 정의

네트워크 사이의 경계에 위치하여 허가되지 않은 접근으로부터 보호대상 네트워크를 보호하는 보안 솔루션

### 방화벽 세대별 역사

### 구현 방식별 종류
> 실습 연계: 홈랩 OPNSense = 소프트웨어 방화벽(가상 어플라이언스). 범용 CPU로 패킷 처리하기 때문에 하드웨어 방화벽 대비 처리량 한계 존재.

### 방화벽 작동 방식

패킷이 지나갈 때 여러 단계 검사 매커니즘을 통해 운명(허용/차단)을 결정. 입력된 정책에 따라 각 작동방식이 동시에 이루어진다.

패킷 필터링이 확인하는 헤더 범위:이더넷 헤더 → IP 헤더 → TCP/UDP 헤더 → 응용계층 헤더 → 페이로드

### 네트워크 인프라상 배치

방화벽은 네트워크 구성과 보안 요구사항에 따라 다양한 위치에 배치 가능.
```plain text
외부 네트워크
      │
   [방화벽]
   ┌───┴────────────┐
DMZ 네트워크    [방화벽]
(외부/내부       ┌────┴────┐
접속 가능)  내부 네트워크  격리 네트워크
           (외부통신 가능) (내부만 접근)
```

- DMZ: 웹서버 등 외부에 노출되어야 하는 서버 배치
- 내부 네트워크: 일반 업무망
- 격리 네트워크: 민감 데이터, OT/ICS 망 등 완전 분리 필요 영역

### 방화벽 도입 및 배치시 고려사항
> 실습 연계: Wazuh + OPNSense 연동이 "다른 보안솔루션과의 통합" 항목 실습 사례. SIEM(Wazuh)과 방화벽(OPNSense) 로그 통합이 실무에서 TCO에 영향 주는 설계 결정임.

## OPNSense 실습 환경

### 네트워크 인프라 구조

외부(WAN) 192.168.10.0/24 ↔ OPNSense ↔ 내부(LAN) 192.168.20.0/24 구조. 방화벽이 두 개의 NIC로 양쪽 네트워크에 동시 연결.
```plain text
[WAN Network: 192.168.10.0/24]
  Attacker_Kali   WAS01_CentOS5   WAS02_CentOS4   WAS03_Ubuntu10
  .10.10          .10.20          .10.30          .10.40
                        │
               OPNSense_FreeBSD
               WAN: 192.168.10.1
               LAN: 192.168.20.1
                        │
[LAN Network: 192.168.20.0/24]
  Desktop_Win10
  .20.10
```

#### VM 목록

### 실습 확인 #1 — 공격자 → 방화벽 PING

VM: Attacker_Kali
```bash
# PING → 응답 없음 (방화벽이 정보수집 방지 목적으로 응답 차단)
ping 192.168.10.1
# 결과: 10 packets transmitted, 0 received, 100% packet loss

# ARP 캐시 확인 → NIC는 정상 동작 중
arp -an
# 192.168.10.1 at 00:50:56:aa:b7:b1 [ether] on eth0
```

해석: PING 무응답 ≠ 방화벽 다운. ARP 레벨에서는 살아있음. 방화벽이 ICMP 응답만 의도적으로 차단한 것.
> 보안 관점: 이게 바로 ICMP 차단 정책. 공격자가 ping sweep으로 살아있는 호스트를 스캔하는 걸 막기 위한 기본 설정.

### 실습 확인 #2 — 내부 사용자 → 외부 통신

VM: Desktop_Win10
```shell
ping -n 1 192.168.20.1   # 방화벽 LAN → 응답 OK (TTL=64)
ping -n 1 192.168.10.10  # Attacker_Kali → 응답 OK (TTL=63)
ping -n 1 192.168.10.20  # WAS01 → 응답 OK (TTL=63, 2ms)
```

해석: 내부 → 외부 방향은 허용. 방화벽이 내부→외부 아웃바운드는 허용, 외부→내부 인바운드는 차단하는 기본 정책 적용 중.
> 실습 포인트: TTL=64 vs TTL=63 차이에 주목. 방화벽(게이트웨이)을 한 홉 거치면 TTL이 1 감소. 이걸로 패킷이 라우팅된 경로를 추적할 수 있음.

> 📷 강의 자료: OPNSense 웹 관리 System > Settings > Administration. 펌웨어·웹 GUI·인증서·SSH·서비스를 관리하며, 웹 GUI 프로토콜 HTTPS, TCP 443, TLS 인증서 선택 항목이 있다.

> 📷 Interfaces > Overview: LAN(em0) 192.168.20.1/24, WAN(em1) 192.168.10.1/24, 루프백 127.0.0.1/8, 모두 static. enc0·pflog0는 미할당.

> 📷 Firewall > Rules > LAN: 192.168.57.80/24 대상 차단 룰(비활성) 아래 LAN net → any 허용(IPv4/IPv6). LAN 룰은 기본적으로 first-match(처음 일치한 룰의 동작 실행)로 평가된다.

> 📷 Services > Intrusion Detection > Administration의 Rules 탭: 사용자 룰 파일 malicious.rules의 sid 1이 action alert로 등록됨(Alert/Drop 전환 가능). OPNSense에 내장된 IDS/IPS(Suricata) 설정 화면.


## OPNSense - 방화벽을 이용한 접근통제 실습 시나리오 ( 포트 주소 기반의 접근 통제)

## 배경 시나리오

### 기존 방화벽 정책 확인

경로: Firewall → Rules → LAN (Desktop_Win10에서 웹 관리페이지 접속)

기존 정책: LAN 네트워크에서 목적지 어디든 모든 통신 허용 (별도 접근통제 없음)
```plain text
IPv4 *   LAN net   *   *   *   → pass (Default allow LAN to any rule)
IPv6 *   LAN net   *   *   *   → pass (Default allow LAN IPv6 to any rule)
```
> 핵심 개념: OPNSense는 first-match 방식. 위에서부터 순서대로 매칭되는 첫 번째 룰이 적용됨.

### 적용할 방화벽 정책

룰 1 — SSH 허용 (Block보다 먼저 위치해야 함)

룰 2 — 전체 접근 차단

### 방화벽 정책 순서 배치 (중요!)

방화벽은 **위에서부터 순차 적용(first-match)**되므로 룰 순서가 결과를 결정함.

#### ❌ 잘못된 순서 (기본 상태)
```plain text
1. IPv4 * LAN net → * (pass)          ← 여기서 이미 허용됨
2. IPv6 * LAN net → * (pass)
3. TCP  LAN net → 192.168.10.20:22 (pass)   ← 절대 도달 안 함
4. IPv4 * LAN net → 192.168.10.20 (block)   ← 절대 도달 안 함
```

#### ✅ 올바른 순서 (최상단으로 이동 후)
```plain text
1. IPv4 TCP LAN net → 192.168.10.20:22 (pass)   ← SSH 먼저 허용
2. IPv4 * LAN net → 192.168.10.20 (block)        ← 나머지 전체 차단
3. IPv4 * LAN net → * (pass)                     ← 기본 허용 (다른 목적지)
4. IPv6 * LAN net → * (pass)
```
> 조작 방법: 새로 추가한 룰 2개를 체크박스로 선택 → 상단 이동 버튼으로 최우선 순위로 이동 → Apply Changes

### 결과 확인

#### 확인 #1 — 브라우저 접속 차단 확인 (Desktop_Win10)

- http://192.168.10.20 브라우저 접속 → 접속 불가 (차단 정책 적용)

#### 확인 #2 — SSH 접속 허용 확인 (Desktop_Win10)
```shell
ssh root@192.168.10.20
# password: lab
# 접속 성공 → ifconfig로 IP 확인 (192.168.10.20)
```

#### 확인 #3 — 로그 확인 (OPNSense Live View)

경로: Firewall → Log Files → Live View

### 정책 원상복구

실습 완료 후 추가한 룰 2개를 휴지통 아이콘으로 삭제 또는 비활성화 → Apply Changes

### 강의 요약

- 포트 기반 접근통제로 동일 목적지에 대해 서비스(포트)별 허용/차단을 세분화할 수 있음
- 방화벽 정책은 **최상위 목록부터 순차 적용(first-match)**되므로 룰 순서가 핵심
- SSH 허용 룰을 Block 룰보다 반드시 위에 배치해야 의도한 대로 동작
- 차단 로그 확인으로 보안 이벤트 가시성 확보 → SIEM(Wazuh) 연동 시 알람 트리거 가능
> 실습 연계: 이 시나리오는 홈 SOC 랩에서 OPNSense + Wazuh 연동의 기반. OPNSense 로그를 Wazuh로 수집하면 차단 이벤트를 자동 탐지·알람 가능.


## OPNSense- 방화벽의 IPS 플러그인을 이용한 유해패턴 탐지 실습

### 배경 개념
> 방화벽 vs IPS 차이: 방화벽은 IP/포트(헤더) 기반 판단, IPS는 패킷 페이로드(내용) 의 악성 패턴 시그니처를 매칭해서 판단.

### 시나리오 배경과 미션

### Suricata 플러그인 기본 설정

경로: Services → Intrusion Detection → Administration

VM: Desktop_Win10

### 정책파일(Rules) 관리 구조

#### 외부 룰셋 다운로드

경로: Services → Intrusion Detection → Download

- 외부 위협 인텔리전스 룰셋을 선택하여 Download & Update Rules로 업데이트 가능
- 주요 룰셋: abuse.ch/Feodo Tracker, abuse.ch/ThreatFox, ET open/*, customrules/Malicious

#### 커스텀 룰셋 XML 구조

룰셋 메타데이터 경로: /usr/local/opnsense/scripts/suricata/metadata/rules/
```xml
<!-- customrules.xml -->
<?xml version="1.0"?>
<ruleset documentation_url="http://docs.opnsense.org/">
    <location url="http://192.168.20.10/" prefix="customrules" />
    <files>
        <file description="Malicious">malicious.rules</file>
    </files>
</ruleset>
```

- OPNSense가 Desktop_Win10(192.168.20.10)의 HTTP 서버에서 malicious.rules 파일을 다운로드하는 구조
- Desktop_Win10에서 HFS(HTTP File Server) 를 구동하여 룰 파일 공유

### malicious.rules 파일 내용

경로: E:\Suricata\malicious.rules
```plain text
# 룰 1 - MALSIG1 패턴 탐지 (alert 모드)
alert tcp any any -> any any (msg:"Malicious file pattern test1"; sid:2;
flow:to_client,established; file_data; \
content:"MALSIG1"; depth:16;)

# 룰 2 - MALSIG2 패턴 탐지 (drop 모드)
alert tcp any any -> any any (msg:"Malicious file pattern test2"; sid:3;
flow:to_client,established; file_data; \
content:"MALSIG2"; depth:16;)
```

#### Suricata 룰 문법 해설

### 악성파일 준비 (Attacker_Kali)
```bash
# 웹 루트에서 악성파일 패턴 확인
cd /var/www/html
hexdump -C malfile1.bin
# 00000000  4d 41 4c 53 49 47 31 0a   |MALSIG1.|

hexdump -C malfile2.bin
# 00000000  4d 41 4c 53 49 47 32 0a   |MALSIG2.|

# Apache 웹서버 구동
systemctl start apache2
lsof -i:80   # 포트 수신 확인
```

### 정책 적용 순서

1. Desktop_Win10에서 HFS 구동 → malicious.rules 파일 공유 (port 80)
1. OPNSense Download 탭에서 customrules/Malicious 체크 → Download & Update Rules
1. OPNSense가 Desktop_Win10 HTTP 서버에서 malicious.rules 다운로드
1. Suricata 재시작 → 룰 적용 완료

### 정책 동작 테스트 (Desktop_Win10)
```shell
# MALSIG1 패턴 파일 다운로드 → alert 모드이므로 다운로드 성공, 로그만 기록
wget http://192.168.10.10/malfile1.bin
# 결과: 200 OK, malfile1.bin saved [8/8]

# MALSIG2 패턴 파일 다운로드 → drop 모드이므로 차단, 응답 없음
wget http://192.168.10.10/malfile2.bin
# 결과: 연결은 되나 응답 없음 (WGET이 재시도 → 히트 2번 발생)
```

#### alert vs drop 모드 차이

### 탐지 로그 확인

경로: Services → Intrusion Detection → Alerts

- SID 2 (MALSIG1) → allowed: alert 모드라 탐지만 하고 통과
- SID 3 (MALSIG2) → blocked 2회: drop 모드로 차단, WGET 재시도로 2회 히트

### 강의 요약

- IPS는 방화벽과 달리 **패킷 페이로드 내용(시그니처)**을 보고 탐지·차단
- Suricata 룰에서 alert vs drop 액션으로 탐지만 할지, 차단까지 할지 결정
- OPNSense는 외부 룰셋 + 커스텀 룰셋을 XML 메타데이터로 관리
- 룰 순서(sid), flow 방향, content 패턴, depth 가 룰 정밀도를 결정하는 핵심 요소
> 실습 연계: Suricata Alert 로그 → Wazuh SIEM 수집 → 자동 알람 구성이 홈 SOC 랩 다음 단계. file_data + content 매칭은 실제 악성코드 시그니처 탐지의 기본 원리와 동일.


## OPNSense - 방화벽의 Outbound NAT를 활용한 내부 네트워크 은닉 실습

### 개념 정리

#### 방화벽 필터링 vs NAT — 완전히 별개 엔진

- Stateful 상태성: Outbound로 나간 세션의 Inbound 응답은 별도 룰 없이 자동 허용 → 이건 차단/허용 의 문제
- Outbound NAT: 내부 IP → 방화벽 외부 IP로 주소 변환 → 이건 주소 노출 의 문제
- NAT가 초기화되어도 패킷은 여전히 통과함. 단, 내부 IP가 외부에 그대로 노출됨

#### NAT가 없으면 왜 문제인가?
```plain text
[NAT 정상]
Desktop_Win10(192.168.20.10) → 방화벽 NAT 변환 → 외부에는 192.168.10.1로 보임

[NAT 초기화]
Desktop_Win10(192.168.20.10) → 변환 없음 → 외부에 192.168.20.10 그대로 노출
→ 공격자가 내부 망 대역(192.168.20.0/24) 구조 파악 가능 → 타깃 공격 가능
```

### 시나리오 배경과 미션

### 사전 준비

#### Attacker_Kali — Wireshark 패킷 캡처 준비
```bash
# Wireshark 실행 → eth0 인터페이스 선택 → 캡처 시작
# Desktop_Win10에서 접속 시 수신 패킷 분석
```

#### Attacker_Kali — 웹 서버 구동
```bash
systemctl start apache2
lsof -i:80   # 포트 80 수신 확인
```

### NAT 설정 전 패킷 상태 확인

Desktop_Win10 브라우저에서 http://192.168.10.10 접속 → Wireshark 캡처 확인
```plain text
NAT 설정 전 Wireshark 캡처 결과:
Source: 192.168.20.10  →  Destination: 192.168.10.10  (TCP SYN)
→ 내부 IP(192.168.20.10)가 외부에 그대로 노출됨
→ 방화벽이 주소 변환 없이 패킷을 그대로 포워딩하고 있는 상태
```

### Outbound NAT 설정 (Desktop_Win10)

#### Step 1 — 모드 선택

경로: Firewall → NAT → Outbound

→ Manual 선택 후 Save → 우측 하단 + 버튼으로 정책 추가

#### Step 2 — 정책 설정

→ 저장 후 Apply Changes

### PF(Packet Filter) 커널 동작 확인

OPNSense는 FreeBSD 기반. 패킷 제어는 PF(Packet Filter) 모듈이 담당. pfctl 명령어로 제어.

(Linux는 netfilter 모듈 + iptables 명령어로 제어)

#### FreeBSD PF 모듈 패킷 처리 흐름
```plain text
패킷 수신
    │
    ├── 1. 정규화(Normalization): 패킷 조각화 처리, TTL 정규화, 비정상 패킷 정리
    │
    ├── 2. NAT
    │       ├── rdr-to: 리다이렉션/목적지 NAT (Inbound, Port Forward)
    │       ├── nat-to: Source NAT (Outbound NAT ← 이번 실습)
    │       └── binat-to: 양방향 NAT
    │
    ├── 3. 필터링(Filtering)
    │       ├── block: 패킷 차단
    │       └── pass: 패킷 허용
    │
    └── 4. 라우팅/전달: 라우팅 테이블 참조하여 패킷이 어떤 NIC로 전달될지 결정
```
> 핵심: NAT가 필터링보다 먼저 처리된다. 즉 주소 변환이 이루어진 후 필터링 룰이 적용됨.

#### pfctl로 NAT 룰 확인
```bash
# OPNSense SSH 접속 후
pfctl -sn

# NAT 설정 전
# → nat 룰 없음 (no nat proto carp all만 존재)

# NAT 설정 후
nat on em1 inet from (em0:network) to any -> (em1:0) port 1024:65535
# em0: LAN NIC, em1: WAN NIC
# LAN 대역에서 나가는 패킷을 WAN IP로 변환
```

### NAT 설정 후 패킷 상태 확인

Desktop_Win10 브라우저에서 http://192.168.10.10 재접속 → Wireshark 캡처 확인
```plain text
NAT 설정 후 Wireshark 캡처 결과:
Source: 192.168.10.1  →  Destination: 192.168.10.10  (TCP SYN)
→ 내부 IP(192.168.20.10)가 방화벽 WAN IP(192.168.10.1)로 변환되어 전달
→ 공격자는 내부 네트워크 구조를 알 수 없음
```

### 강의 요약

- Outbound NAT는 방화벽 필터링(허용/차단)과 완전히 독립적인 주소 변환 기능
- NAT 없이도 패킷은 통과하지만, 내부 사설 IP가 외부에 노출되어 내부 망 구조가 파악될 위험
- OPNSense의 Outbound NAT → PF 모듈의 nat-to 기능(Source NAT)으로 구현
- PF 처리 순서: 정규화 → NAT → 필터링 → 라우팅 (NAT가 필터링보다 먼저)
- pfctl -sn 명령어로 현재 적용된 NAT 룰을 CLI에서 직접 확인 가능
> 실습 연계: OT/ICS 환경에서 내부 제어망 IP 대역 은닉은 필수 보안 요소. Outbound NAT로 제어망(192.168.20.x)을 외부에 노출하지 않는 구성이 KEPCO/KHNP 같은 환경에서 기본 설계 원칙임.


## ModeSecurity WAF

## WAF(Web Application Firewall)란?

웹 애플리케이션을 대상으로 한 공격을 탐지하고 차단하기 위해 설계된 웹 특화 보안 시스템.

기존 네트워크 방화벽이 IP, 포트, 패킷 수준에서 접근을 제어하는 것과 달리, WAF는 HTTP/HTTPS 요청과 응답의 내용을 분석하여 웹 애플리케이션 계층에서 발생하는 보안 위협을 식별하고 대응한다.
> 방화벽 vs IPS vs WAF 비교

### ModSecurity란?

웹 서버(Apache, Nginx, IIS)에 모듈 형태로 탑재되어 동작하는 오픈소스 WAF.

- HTTP 요청과 응답을 실시간으로 분석하여 로그 수집, 접근 제어, 보안 위협 탐지 및 차단 수행
- 웹 서버에 도달하는 트래픽을 다른 모듈이 처리하기 전에 먼저 가로채어 분석
- 악성 요청을 차단하거나 기록으로 남겨 관리자가 즉시 대응할 수 있도록 지원

#### 주요 기능

### 주요 지시자(Directive)

#### SecRuleEngine — 전체 기능 활성화 여부

#### SecAuditEngine — 감사 로그(Audit Log) 제어

#### SecDefaultAction — 룰 매칭 시 기본 동작 지정

룰이 매칭될 때 기본으로 적용할 동작을 지정. 로그 기록, 차단, 상태 코드 반환 등을 포함.

#### SecDefaultAction 예시
```plain text
# 예시 1: Phase 1에서 탐지 → 차단(deny) → 로그(log) → 감사 로그(auditlog) + 상태 코드 403 반환
SecDefaultAction "phase:1,deny,log,auditlog,status:403"

# 예시 2: t 옵션으로 입력값 변조 전처리 (소문자 변환, null 대체, 유니코드 URL 디코딩, HTML entity 디코딩, HTML 주석 제거)
SecDefaultAction "phase:1,deny,log,auditlog,status:403,t:lowercase,t:replaceNulls,t:urlDecodeUni,t:htmlEntityDecode,t:removeComments"
```
> t 옵션을 쓰는 이유: 공격자가 %3cscript%3e 같은 인코딩 우회 기법을 쓸 때, 디코딩 후 패턴 매칭을 해야 정확하게 탐지할 수 있음.

### ModSecurity Process Phases (처리 단계)

ModSecurity는 HTTP 트랜잭션을 5단계로 나누어 순차적으로 룰을 적용한다.
```plain text
[클라이언트 요청]
      │
   Phase 1: Request Headers 검사
      │
   Phase 2: Request Body 검사
      │
   [웹 서버 처리]
      │
   Phase 3: Response Headers 검사
      │
   Phase 4: Response Body 검사
      │
   Phase 5: Logging
      │
[클라이언트 응답]
```

### 강의 요약

- ModSecurity는 Apache, Nginx, IIS 웹 서버에 모듈 형태로 설치되며 HTTP 요청 및 응답 내용을 실시간으로 분석하여 웹 공격으로부터 시스템을 보호
- SQL Injection, XSS 등 주요 웹 기반 공격을 룰셋에 기반해 탐지하고 차단
- SecRuleEngine, SecAuditEngine, SecDefaultAction 지시자 설정을 통해 WAF 동작방식을 세밀하게 제어
- Phase 1~5 처리 단계 구조를 통해 웹 요청이 서버에 도달하기 전부터 응답 처리 후 로깅 단계까지 전 흐름을 단계적으로 보호하는 룰셋 설계 원리 이해 가능
> 실습 연계: ModSecurity가 탐지한 SQLi/XSS 로그를 Wazuh로 수집하면 웹 공격 자동 탐지 파이프라인 구성 가능. phase:2 (Request Body)에서 SQLi 패턴 매칭이 가장 핵심 단계.

> 📷 공격 요청 후 브라우저가 192.168.10.20/error.html로 이동해 "Attack is detected.. This is redirected page by modsecurity..." 표시 — ModSecurity 룰이 302 리다이렉트로 차단.

> 📷 tortix_waf.conf에 'Malicious File Upload Detection', 'XSS Detection'(fromcharcode 패턴, id:101, redirect:/error.html) 룰 작성 후 `service httpd restart`. modsec_audit.log에서 id 7 확인: ARGS:ps_search에서 `^shell.*` 패턴 일치 → /error.html로 302 리다이렉트(phase 4).


## ModSecurity WAF 실습 환경 설명

### 실습 가상 환경

### 실습 환경 버전 및 파일 경로

### 주요 설정 파일 역할

### 실습 환경 준비 — 룰 적용 파일 확인 (CentOS5)
```bash
# 룰 파일 디렉토리 이동
cd /etc/httpd/modsecurity.d/

# vi 편집기로 룰 파일 확인
vi tortix_waf.conf
```

### tortix_waf.conf 주요 설정 내용

#### SecAuditEngine (Line 43)
```plain text
SecAuditEngine RelevantOnly
```

- 감사 로그(Audit Log) 작동 여부 제어
- RelevantOnly: 규칙과 일치하는 요청만 로그에 기록 → 로그 양을 줄여 효율적 운영 가능
```plain text
# Line 49
SecAuditLogType Serial       # 보안 이벤트마다 고유 번호 부여, 개별 기록 → SIEM 연동 시 이벤트 식별 용이

# Line 50
SecAuditLog logs/modsec_audit.log   # 감사 로그 저장 경로
```

#### SecDefaultAction (Line 40)
```plain text
SecDefaultAction "pass,log,auditlog,phase:4,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase"
```

- Phase 4(Response Body)에서 룰 매칭 시 기본 동작: 통과(pass) + 로그 기록 + URL/HTML 디코딩 + 소문자 변환 전처리

#### Custom Rule (Line 63)
```plain text
SecRule REQUEST_METHOD "(PUT|DELETE|TRACE)" "deny,log"
```

- HTTP 요청 메서드 중 PUT, DELETE, TRACE 요청을 차단하고 로그 기록
- 불필요한 HTTP 메서드를 제한하는 기본 보안 정책

#### SecRequestBodyAccess / SecResponseBodyAccess (Line 65~68)
```plain text
SecRequestBodyAccess On        # 요청 본문 검사 활성화
SecResponseBodyAccess On       # 응답 본문 검사 활성화
SecResponseBodyMimeType (null) text/html text/plain text/xml
                               # 검사할 응답 MIME 타입 지정 (지정 타입만 검사)
SecResponseBodyLimit 524288    # 응답 본문 최대 크기 제한 (512KB)
```
> 포인트: 기본적으로 ModSecurity는 요청 헤더만 검사. SecRequestBodyAccess On을 설정해야 POST body, 파일 업로드 등 요청 본문까지 검사 가능. SecResponseBodyAccess On은 응답 본문에서 민감 정보 유출 탐지에 사용.

### 환경 설정 파일 구조 (00_mod_security.conf)
```plain text
# ModSecurity 모듈 로드
LoadModule security2_module modules/mod_security2.so
LoadModule unique_id_module modules/mod_unique_id.so

<IfModule mod_security2.c>
    # 기본 설정 — 커스텀 룰 파일 포함
    Include modsecurity.d/tortix_waf.conf

    # ASL(Application Security Library) 룰 관리
    Include modsecurity.d/00*exclude.conf
    Include modsecurity.d/*asl*.conf
    Include modsecurity.d/99*exclude.conf
</IfModule>
```

### vi 편집기 주요 명령어 (실습 참고)
```plain text
:43     # 43번째 줄로 이동
:63     # 63번째 줄로 이동
:q!     # 저장하지 않고 종료
:wq     # 저장 후 종료
```

### 실습 연계 포인트
> ModSecurity 로그(modsec_audit.log)를 Wazuh로 수집하면 WAF 탐지 이벤트를 SIEM에서 자동 분석·알람 가능. SecAuditLogType Serial 설정으로 각 이벤트에 고유 ID가 부여되므로 Wazuh 룰에서 이벤트 추적이 용이함.


## Modesecurity

> 📷 웹 해킹 실습 사이트(192.168.10.20/webhack) Q&A 게시판 글쓰기(qna_write_ok.php) 요청이 'Forbidden — You don't have permission' 403으로 차단됨.

> 📷 `tail -f /var/log/httpd/modsec_audit.log`: Action: Intercepted (phase 2). WAF는 ModSecurity for Apache 2.6.6 + OWASP CRS 2.2.6, 서버 Apache 2.2.3(CentOS).


## ModSecurity WAF - 룰셋 문법 (ARGS & REQUEST_URI)

### SecRule 문법 구조
```plain text
SecRule  VARIABLES  OPERATOR  [ACTIONS]
```

웹 요청의 변수 값을 분석하고, 해당 값이 미리 정의된 패턴과 일치하는지 검사하여 ACTION을 수행한다.

### 주요 지시자 정리

#### SecAuditLogParts 항목 코드표

### VARIABLES (변수)

검사 대상을 지정하는 변수. HTTP 요청의 어느 부분을 분석할지 결정한다.

### OPERATOR (연산자)

### ACTIONS

### Part 1 — ARGS 변수 실습

#### 개념

ARGS는 GET/POST 파라미터 전체를 검사하는 변수. 쇼핑몰 검색창, 로그인 폼 등 사용자 입력값을 통한 공격(SQLi, XSS, 셸코드 등) 탐지에 사용.

#### 룰 추가 (CentOS5)
```bash
vi /etc/httpd/modsecurity.d/tortix_waf.conf

# ARGS 섹션 이동
/ARGS

# insert 모드 진입 후 룰 입력
i
SecRule ARGS ^shell. "id:7,redirect:/error.html"

# 저장 후 httpd 재시작
:wq!
service httpd restart
```

룰 해설:

#### 테스트 (Kali)
```bash
Firefox http://192.168.10.20/coremall
# 검색창에 'shellcode' 입력 → /error.html 리다이렉트
# "Attack is detected.. This is redirected page by modsecurity..."
```

#### 로그 확인 (CentOS5)
```bash
cat /var/log/httpd/modsec_audit.log | grep id[[:space:]]\"7\"
```
```plain text
Message: [file "tortix_waf.conf"] [line "73"] [id "7"]
Access denied with redirection to /error.html using status 302 (phase 4).
Pattern match "^shell." at ARGS:ps_search.
```

### Part 2 — REQUEST_URI 변수 실습

#### 개념

REQUEST_URI는 HTTP 요청의 URI(경로 + 쿼리 문자열) 부분을 검사하는 변수.
```plain text
http://www.webserver.com/main.php?page=hello
         │                  │          │
      Authority           Path       Query
    (호스팅 서버)      (디렉토리/파일)  (파라미터)
```

REQUEST_URI = /main.php?page=hello (Path + Query 부분)

#### REQUEST_URI 주요 탐지 목표

- URI의 파일 경로/확장자 분석 → 시스템 파일 다운로드 시도 차단
- 웹 셸(Web Shell) 업로드 시도 사전 탐지·차단
- XSS, SQL Injection 등 URI 경로 기반 공격 탐지

#### 룰 추가 #1 — 정규식 패턴 탐지 (CentOS5)
```bash
vi /etc/httpd/modsecurity.d/tortix_waf.conf

# ARGS 섹션 아래에 추가
SecRule REQUEST_URI "@rx patt+ern" "id:7,redirect:/error.html"

:wq!
service httpd restart
```

룰 해설:

#### 테스트 #1 (Kali)
```bash
Firefox 192.168.10.20/webhack/pattttttttttern
# → /error.html 리다이렉트
```

#### 로그 확인 #1
```bash
vi /var/log/httpd/modsec_audit.log
```
```plain text
GET /webhack/pattern HTTP/1.1
Message: [id "7"] Access denied with redirection to /error.html using status 302 (phase 4).
Pattern match "patt+ern" at REQUEST_URI.
```

#### 룰 추가 #2 — Admin 페이지 접근 차단 (CentOS5)
```bash
vi /etc/httpd/modsecurity.d/tortix_waf.conf

# 기존 룰 아래에 추가
SecRule REQUEST_URI "admin" "msg:'Admin',redirect:/error.html"

:wq!
service httpd restart
```

룰 해설:

#### 테스트 #2 (Kali)
```bash
Firefox 192.168.10.20/webhack/admin.php
# → /error.html 리다이렉트
```

#### 로그 확인 #2
```bash
vi /var/log/httpd/modsec_audit.log
# /admin 검색
```
```plain text
GET /webhack/admin.php HTTP/1.1
Message: [line "75"] [msg "Admin"] Access denied with redirection to /error.html
using status 302 (phase 4). Pattern match "admin" at REQUEST_URI.
```

### 실습 시 주의사항

### 강의 요약

- ARGS: GET/POST 파라미터 검사 → 셸코드, SQLi, XSS 등 사용자 입력 기반 공격 탐지
- REQUEST_URI: URI 경로 검사 → 어드민 페이지 접근, 웹 셸 업로드, 민감 경로 접근 차단
- @rx 정규식 연산자로 patt+ern 같은 변형 패턴도 탐지 가능
- msg Action으로 로그에 식별 메시지를 남겨 사후 분석 용이
> 실습 연계: REQUEST_URI 룰로 /admin, /.env, /.git 등 민감 경로 접근 차단이 실무 WAF 기본 정책. Wazuh에서 ModSecurity 로그 수집 시 msg 필드로 공격 유형 분류 가능.
