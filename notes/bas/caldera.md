# [수업 노트] BAS — CALDERA 에이전트 연결과 어빌리티 제작

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## CALDERA Agent 연결

> 📷 CALDERA 'Deploy an agent' 창: windows 플랫폼, 기본 에이전트 sandcat(Go로 작성, HTTP로 서버와 통신). app.contact.http=http://192.168.56.80:8888, implant 이름 splunkd. 생성된 PowerShell 명령은 서버에서 sandcat.go를 받아 C:\Users\Public\splunkd.exe로 저장하고 숨김 창으로 실행한다.

> 📷 윈도우10 관리자 PowerShell ISE에서 에이전트 연결 스크립트 실행. 스크립트 파일로 실행하려다 CommandNotFoundException이 나서, 명령을 콘솔에 직접 붙여넣어 `-server http://192.168.56.80:8888 -group red`로 에이전트를 숨김 실행했다.

> 📷 CALDERA 5.2.0 Agents 화면: 에이전트 1개 연결(1 alive, 1 trusted). host Windows10, group red, platform windows, contact HTTP, privilege Elevated, status alive/trusted.

> 📷 Adversaries 화면에서 새 Adversary 프로필 생성. 프로필은 ATT&CK TTP 묶음이며 Add Ability로 어빌리티를 추가한다(아직 비어 있음).

> 📷 'Start New Operation' 설정 창: Adversary, Fact Source(basic), Group(All groups/red), Planner(atomic), Obfuscator(plain-text 선택, base64·caesar cipher 등 선택 가능), 자동 실행/수동 승인, 기본 파서 사용, Jitter 2/8초.

•Operations 탭-> 새Operation 생성-> Start 실행-> 에이전트동작

[옵션상세설명]

Adversary: 이전에생성한 ‘adversary’ 선택

Group: 윈도우Sandcat agent가속한그룹, 즉 윈도우에서에이전트실행할때사용한그룹선택

실행모드: manual / autonomous 중선택


## CALDERA - 어빌리티(Ability) 분석 및 제작실습

- [ ] 어빌리티 Find files (T1005) YAML 구조분석
- [ ] Executor, Parsers(source/edge/target), Requirements, delete_payload 설명
- [ ] 신규Ability identify current user (T1033)제작

#### 어빌리티(Ability)

- Caldera에서가장작은실행단위로, ATT&CK 프레임워크의개별기술(Technique)에매핑된단일공격/작업명령
- Tatic

> 📷 Kali에서 `find / -name abilities -type d`로 어빌리티 저장 위치 확인: ~/calderaVENV/caldera/data/abilities 와 plugins/(stockpile, atomic, manx, sandcat, training 등)/data/abilities. stockpile 아래는 collection, discovery, persistence, privilege-escalation 등 전술별 폴더로 나뉜다.

> 📷 Operation 실행 결과: 직접 만든 어빌리티 'identify current user'(tactic discovery)가 Windows10 에이전트에서 success. 표준 출력은 호스트 이름(host1), 수집된 Fact는 없음.

> 📷 CALDERA 대시보드(localhost:8888): Agent 1, Operations 4, Abilities 1,847, Adversaries 32. 서버는 0.0.0.0:8888에서 동작.

•CALDERA의Ability는ATT&CK Technique 하나에대응하는최소실행단위이며, YAML 파일로정의됩니다.

•Executor는OS별실행환경(psh/층/sh)을지정하고, Command에Facts 변수)를활용해동적명령을구성합니다.

•Parsers는실행결과를Facts 객체로저장하며, source → edge → target 구조로Facts 간관계를표현합니다.

•Requirements로선행Fact 조건을설정해Ability 간의존성을정의하고, delete_payload로페이로드흔적을자동으로제거할수있습니다
