# [수업 노트] 정보보호제품군 실습훈련 기본1 — 스노트 content·PCRE 룰과 브라우저 익스플로잇 탐지

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## 사전질문

1. IDS/IPS의 인라인 모드와 미러링 모드의 기술적 차이점에 대해서 이해하고 있다.
1. 스노트 룰의 RTN(Rule Tree Node)과 OTN(Option Tree Node)의 역할과 구조를 설명할 수 있다.
1. 신뢰하지 않는 외부 네트워크에서 내부 웹서버 관리자 페이지에 접근하는 트래픽을 탐지하는 스노트 룰을 작성할 수 있다.
1. 스노트의 content 옵션의 정의와 사용 목적(웹 요청/응답 탐지, 악성 스크립트 탐지 등)을 설명할 수 있다.
1. content 옵션에서 ASCII, 16진수 시퀀스, 혼합 형식의 문자열 표현 방법을 이해하고 있다.
1. Content 옵션의 주요 modifier(nocase, rawbytes, offset, depth, distance, within)의 역할과 차이를 설명할 수 있다.
1. offset과 depth 옵션을 조합하여 페이로드의 특정 범위에서만 문자열을 탐지하는 룰을 작성할 수 있다.
1. distance와 within을 병행하여 다중 문자열 간의 거리와 위치 관계를 정밀하게 제어하는 방법을 설명할 수 있다.
1. content 옵션만으로는 숫자 값 비교가 불가능한 한계를 이해하고, byte_test 옵션의 필요성을 설명할 수 있다.
1. byte_test 옵션의 주요 파라미터(bytes, operator, value, offset, relative)의 역할을 알고 있다.
1. STRUCTURE 자료구조와 CHUNK 자료구조의 구성(Signature, fld2, fld3, SIZE)을 이해하고 있다.
1. 가상 취약점의 익스플로잇 파일 패턴을 분석하여 Snort 탐지 룰을 설계하고 적용할 수 있다.
1. T1189 Drive-By Compromise 기법의 공격 원리와 브라우저 취약점 감염 과정을 이해하고 있다.
1. iframe 태그를 이용한 랜딩 페이지 → 리다이렉트 → 익스플로잇의 공격 흐름을 설명할 수 있다.
1. ANI 파일의 RIFF 구조(ID, Size, Contents)와 chunk 기반 파일 포맷의 원리를 이해하고 있다.
1. ANI 파일 익스플로잇 탐지를 위한 Snort 룰셋(RIFF, ACON, anih 및 byte_test 활용)을 설계할 수 있다.
1. 정규표현식의 주요 문법(^, $, ., ?, *, +, [], |)과 플래그(i, m, s, u)의 역할을 알고 있다.
1. PCRE를 활용하여 동적 생성 URL 패턴을 탐지하는 Snort 룰을 작성할 수 있다.
1. threshold, limit, both 세 가지 type의 동작 방식 차이를 비교하여 설명할 수 있다.
1. DDoS, Brute-Force, 스캐닝 등 비정상 대량 트래픽을 탐지하기 위한 Threshold 룰을 작성할 수 있다.


## Snort

- 오픈 소스
- IDS : Intrusion Detection System 네트워크 탐지 시스템
- IPS: 침입 방지 시스템
- 주요기능
  - 패킷 스니퍼(Packet Sniffer)
  - 패킷 로커( Packet Logger)
  - 침입 탐지(IDS)
  - 침입 방지(IPS)
- 인라인 모드, 미러링 모드
- 롤셋


## 실습 환경

> 📷 실습 구성도: WAN(192.168.57.0/24)에 attacker(Kali), web server01(CentOS 4.4), web server02(CentOS 5.3)가 있고, snort IDS(CentOS 6.4)가 WAN 192.168.57.2 / LAN 192.168.56.2 두 인터페이스로 두 망 사이에 위치. LAN(192.168.56.0/24)에 사용자 PC(Windows XP).

> 📷 같은 구성을 텍스트로 정리: WAN 192.168.57.0/24 — Kali_x86, CentOS4.4(Web), CentOS5.3(Web) / 가운데 CentOS6.4(Snort) / LAN 192.168.56.0/24 — WindowsXP_Eng.

ATTACKER- 위협

WEB SERVER - 피해 서비스 역활

구버전의 가상머신은

실습 내용

명령어

GUI모듈을 설치하지 않아 원격 클라이언트 프로그램 설치

PUTTY 사용

> 📷 스노트 관리 주요 명령: `vim /etc/snort/rules/exam.rules`로 룰 작성(예: `alert tcp 192.168.57.0/24 any -> 192.168.56.0/24 80 (msg:"HTTP Test"; sid:1000002;)`), `snort -i eth0 -c /etc/snort/snort.conf`로 구동, ``kill -SIGHUP `pidof snort` ``로 룰 다시 읽기, `tail -f /var/log/snort/alert`로 실시간 로그 확인.

window 가상 머신

> 📷 Windows XP 사용자 PC `ipconfig`: IP 192.168.56.8, 마스크 255.255.255.0, 게이트웨이 192.168.56.2(스노트 LAN 인터페이스).

snort ids 랜 쪽 주소;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

kali server, attacker

> 📷 Kali 공격자 `ifconfig`: eth0 192.168.57.11/24.

Kali의 default 랜카드 역시 192.168.56.2가 될 것이다.

snort 의 랜카드 옵션을 2로하든 3으로 하든 룰셋의 적용에는                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;상관이 없다 왜냐하면 일직선으로 트래픽이 흐르기 때문이다.


> 📷 강의 'Content 옵션의 개념과 HTTP 페이로드 탐지': content는 패킷 페이로드에서 지정한 패턴을 찾는 핵심 키워드이고 nocase, rawbytes, depth, offset, distance, within, http_client_body 같은 보조 키워드로 동작을 바꾼다. 실습: 'normal'과 'malicious' 패턴이 든 48바이트 바이너리 파일을 HxD로 만들어 HFS로 공유 → `alert tcp any any -> any any (msg:"Content Option Basic Rule"; content:"malicious"; sid:1000003;)` 추가 → Kali에서 Wireshark로 HTTP를 보며 두 파일을 내려받고 스노트 로그 확인. 판서는 HTTP 요청(GET URI·Cookie)과 패킷 계층(Ethernet·IP·TCP·HTTP·Body) 구조.

snort dp


> 📷 강의 'Content 옵션 활용 실습 Part1' — file_data 옵션: HTTP·SMTP·POP·IMAP 트래픽이면 탐지 커서를 해당 버퍼로 옮긴다. HTTP는 응답 본문(디청킹·gzip 해제·정규화된 본문 포함), SMTP/POP/IMAP은 메일 본문과 Base64·Quoted-Printable 등으로 디코딩된 MIME 첨부. 해당하지 않으면 일반 페이로드로 설정.

depth옵션

snort가 처리할 패킷이 e-ip-tcp-http-body 만약 tcp 패킷을 찾겠다고 할때 http와 같은 응용계층 프로토콜이 페이로드에 언혀서 등장 file data 옵션

offset 에서 지정한 바이트는 스킵하겠다.

offset : 3byte 라면 이만큼은 스킵하고 뒤에서 패턴을 찾겠다.

depth option : 5byte 뒤에서 5byte안에서 찾아라

3개의 snort 예제 -i 옵션은 대소문자 구분하지 않겠다.

> 📷 offset(페이로드 시작 N바이트 이후부터 탐색)과 depth(처음 N바이트 안에서만 탐색)는 앞의 content를 수식하므로 content 뒤에 와야 한다. 예제 룰: `file_data; content:"SIG"; depth:8;`(SIG1-1), `depth:24`(SIG1-2), `file_data; pcre:"/foo/i";`(정규식, i는 대소문자 무시). 판서: 8바이트 범위 vs 24바이트 범위 안에 SIG가 있는지.

> 📷 룰 문법 요약: `file_data; content:"<검색할 문자열>";` 또는 `file_data; pcre:"/<정규표현식>/";`.

> 📷 offset·depth 판서: 클라이언트-서버 통신의 페이로드에서 offset:3이면 앞 3바이트를 건너뛰고, depth:5면 그 지점부터 5바이트 안에서만 패턴을 찾는다.

실습

> 📷 실습 절차: 스노트 alert 로그 모니터링 → exam.rules에 RULE-1(file_data; content:"SIG"; depth:8), RULE-2(depth:24), RULE-3(offset:8; depth:8) 추가 → `snort -i eth2 -c /etc/snort/snort.conf` 재구동 → WindowsXP에서 SIG 위치가 다른 exam1~3.bin을 만들어 HFS로 공유 → Kali 브라우저로 내려받아 어떤 룰이 맞는지 확인. 예상: exam1(SIG가 0바이트 위치)=RULE-1·2, exam2(17바이트 이후)=RULE-2, exam3(8바이트 위치)=RULE-2·3. 판서로 각 범위를 그림.

바이너리 파일은 총3개

> 📷 같은 실습 절차 화면(판서 없는 버전). 참고로 pkt_data 옵션은 탐지 커서를 다시 TCP 페이로드로 되돌린다: `file_data; content:"foo"; pkt_data; content:"bar";`.


## content 옵션의 활용 part2

> 📷 강의 목표(Content Part2): distance와 within 옵션의 역할과 둘을 함께 쓰는 방법 이해.

네트워크 상의 파일을 탐지

offset

depth option

파일 내에서 offset depth

distance within

옵션은 중첩 할 때 - contents 옵션 이후에 다시 탐지를 할 때

> 📷 실습 목표: content·distance·within으로 HTTP 페이로드 안 악성 문자열의 탐지 범위와 시작 위치를 세밀하게 제어하고, 같은 문자열도 위치에 따라 탐지 여부가 달라지는 것을 alert 로그로 확인.

> 📷 실습 룰: RULE-4 `file_data; content:"SIG"; depth:24; content:"SIG2"; within:4;`(첫 SIG 끝에서 4바이트 안에 SIG2), RULE-5는 여기에 `content:"SIG3"; within:4; distance:9;`(SIG2 끝에서 9바이트 건너뛴 뒤 4바이트 안에 SIG3) 추가. exam4.bin(SIGSIG2 … SIG3)은 RULE-4만, exam5.bin은 RULE-4·5 히트 예상. 판서: depth 24 범위 안의 SIG와 그 뒤 4바이트 within 범위.

> 📷 강의 목표(Content Part3): 스노트 byte_test 옵션 이해.

> 📷 content의 한계: 패킷에 특정 문자열·바이트가 있는지만 빠르게 볼 뿐 숫자 값 비교 같은 정밀한 조건은 검사할 수 없다(예: `content:"GET /admin"`으로 관리자 페이지 접근만 탐지) → 이를 보완하는 것이 byte_test.

byte_test - operator

지정한 값을 오퍼레이터를 활용해서 테스트하는데 사용이 된다.

프로그래밍 기반의 오퍼레이터를  제공해 주지 않는다.

자료구조

> 📷 강의 목표(자료구조): STRUCTURE와 CHUNK 자료구조, 그리고 이를 이용한 익스플로잇 패턴 이해.

Structure

CHUNK


## 브라우저 익스프로잇 탐지

> 📷 강의 목표(브라우저 익스플로잇 탐지 Part1): CVE-2007-0038 개요, ANI 파일과 CHUNK 자료구조 이해.

cve-2007-0038

> 📷 CVE 개요: Common Vulnerabilities and Exposures, MITRE가 운영하는 취약점 표준 식별 체계(형식 CVE-연도-번호). 업체마다 다른 이름을 막고 검색·공유·보안 도구 연동을 쉽게 하려고 쓴다.

> 📷 CVE-2007-0038(Windows Animated Cursor Stack Overflow): 웹 페이지나 HTML 메일로 로드되는 애니메이션 커서(.ANI)를 USER32.DLL이 처리할 때 스택 버퍼 오버플로가 발생해 로그인 사용자 권한으로 원격 코드 실행. Vista까지 모든 윈도우와 탐색기·IE·Firefox·Outlook 등 표준 커서 API를 쓰는 프로그램이 영향. 앞선 MS05-002 패치가 불완전해 우회된 사례. 2006년 12월 제보, 2007년 3월 공개, 4월 3일 패치.

USER32.DDL 공격대상

브러우저는 애니메이션 커서 기능을 이용하기 위해서는 ANI파이을 서버 쪽에 요청을 하고 그 파일이 브라우저에 전달이 되어야 한다.


> 📷 강의 목표(Part2): Drive-By Compromise 기법 이해 — MITRE ATT&CK 개요, 기법 설명, 실습 인프라 설명.

> 📷 MITRE ATT&CK: 공격 전술(Tactics)과 기법(Techniques)을 체계적으로 정리한 지식 기반 프레임워크. 탐지·대응·위협 분석·침해사고 대응에 쓰인다.

> 📷 전술(공격자의 목적) 표: Initial Access(최초 접근), Execution(코드 실행), Persistence(지속성), Privilege Escalation(권한 상승), Defense Evasion(탐지 회피), Collection(데이터 수집), Exfiltration(외부 유출), Command and Control(외부 서버와 통신), Reconnaissance(사전 정보 수집), Resource Development(도구·인프라 준비), Credential Access(자격증명 탈취), Discovery(내부 정보 탐색), Lateral Movement(수평 이동), Impact(파괴·암호화).

> 📷 Initial Access 기법 표: Drive-by Compromise(T1189, 웹사이트 방문만으로 브라우저 취약점 감염), Phishing(T1566)·첨부파일(.001)·링크(.002), Exploit Public-Facing Application(T1190), Supply Chain Compromise(T1195), Trusted Relationship(T1199), Valid Accounts(T1078), Replication Through Removable Media(T1091, USB), External Remote Services(T1133).

> 📷 T1189 Drive-By Compromise: 사용자가 공격자에게 장악된 웹사이트를 방문하면 악성코드가 내려받아지거나 실행되는 기법. 흐름은 ① 사용자 브라우저가 피해 웹사이트 접속 → ② 랜딩 서버로 이동 → ③ 정보 수집 후 익스플로잇/페이로드 서버로 이동 → ④ 취약점 익스플로잇. 특정 대상이 자주 찾는 사이트를 미리 감염시키는 워터링 홀과 비슷하다.

> 📷 브라우저 공격 인프라 3종: 피해가 발생한 웹사이트(해킹된 서버, 코드를 수정해 랜딩 서버로 보냄), 랜딩 서버(브라우저 종류·버전을 식별한 뒤 익스플로잇 서버로 보냄), 익스플로잇/페이로드 배포 서버(수집 정보를 바탕으로 실제 공격 수행).

> 📷 실습 인프라: WAN 192.168.57.0/24에 Attacker_Kali(.11, 익스플로잇/페이로드 서버), WAS02_CentOS5(.80, 랜딩 서버), WAS01_CentOS4(.70, 피해 웹사이트), Snort_CentOS6(57.2/56.2), OPNSense(57.1/56.1). LAN 192.168.56.0/24에 Desktop_WinXP(.8, 시나리오상 HFS로 TCP 80 웹 서버도 구동), Desktop_Win10(.10).

> 📷 같은 구성에서 Attacker_Kali가 공격용 스크립트로 애니메이션 커서 취약점을 익스플로잇하는 역할, 대상 PC는 Desktop_WinXP.

> 📷 랜딩 서버(WAS02_CentOS5, 192.168.57.80) 역할: 접속한 브라우저의 종류·버전·플러그인을 식별해 취약점이 있으면 익스플로잇 서버로 넘긴다.

> 📷 피해 웹사이트(WAS01_CentOS4, 192.168.57.70) 역할: 대상 PC가 처음 접속하는 사이트로, 공격자에게 감염돼 접속한 PC를 랜딩 서버로 보낸다.

> 📷 강의 요약: 브라우저 취약점 기반 공격(Drive-By Compromise)은 방문만으로 브라우저를 익스플로잇해 악성코드를 실행하는 초기 접근 기법이며, 스노트 같은 IDS/IPS로 HTTP 트래픽을 분석해 탐지·차단할 수 있다.


> 📷 브라우저 익스플로잇 탐지 Part3(페이로드 분석 및 룰 제작) 목표: ANI 파일 구조와 버퍼 오버플로 원리를 이해하고 Wireshark로 악성 chunk를 분석.


> 📷 정규표현식(PCRE) 주요 문법: `^` 시작, `$` 끝, `.` 아무 문자 1개, `?` 0~1회, `*` 0회 이상, `+` 1회 이상, `{n}` 정확히 n회, `{n,m}` n~m회, `[^0-9]` 숫자 제외. 예: `n\d{2}$`는 "n12"만 매칭. 스노트는 펄 호환 정규식(PCRE)을 채택.

> 📷 강의 'PCRE를 이용한 C2 통신의 동적 생성 패턴 탐지' — 정규식 플래그는 /패턴/플래그 형식: i 대소문자 무시(/pHp/i → php·PHP 모두), m 여러 줄(^·$가 줄마다 적용), s dotAll(.이 줄바꿈 포함), u 스노트에서 URI 검사, x 공백·주석 허용, A 문자열 시작에서만 매칭.

> 📷 문법 예: `^http`는 http://·https://로 시작하면 매칭, myhttp://는 불일치. `[ ]` 안의 ^는 부정. `String$`는 myString만 매칭(StringCopy, String\n은 불일치).

> 📷 `.`은 줄바꿈을 뺀 임의 1문자(A.B → ACB·"A B" 매칭, AB 불일치, s 플래그면 줄바꿈 포함). `?`는 0~1회(Bananas? → Banana·Bananas 매칭).

> 📷 `*`는 0회 이상(n\d* → n·n2·n123 모두), `+`는 1회 이상(n\d+ → n1·n123 매칭, n 불일치).

> 📷 `{n}` 정확히 n회(a\d{2}$ → a12 매칭; $ 없이 a\d{2}면 a123에서 a12까지만 매칭), `{n,m}` n~m회(a\d{2,3}$ → a12 매칭, a1 불일치), m 생략 시 n회 이상.

> 📷 룰 예시(공식 문서): `alert tcp any any -> any 80 (content:"/foo.php?id="; pcre:"/\/foo.php?id=[0-9]{1,10}/iU";)` — URI의 /foo.php?id=숫자 요청 탐지. 목적지 80 포트 TCP 페이로드(HTTP 헤더+본문)를 보고, 가볍고 빠른 고정 문자열 content로 먼저 거른 뒤 PCRE로 정밀 검사. 성능을 위해 PCRE에는 content를 최소 하나 함께 쓰는 것이 권장.

> 📷 pcre 옵션 해설: `\/foo.php\?id=`는 URI가 정확히 /foo.php?id= 형식(?는 \로 이스케이프), `[0-9]{1,10}`은 1~10자리 숫자, /i는 대소문자 무시, /U는 URI 데이터만 검사. /foo.php?id=1234567890은 매칭, /foo.php?id=abcdef는 불일치.

> 📷 강의 요약: PCRE는 펄 스타일 정규식 라이브러리로 복잡한 문자열 패턴을 정밀하게 매칭할 수 있어, 동적으로 바뀌는 C2 통신 패턴도 유연한 룰로 탐지할 수 있다.
