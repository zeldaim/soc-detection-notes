# [수업 노트] 스노트 IDS/IPS 룰셋 기본 구조

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

> 📷 강의 자료(스노트 IDS 룰셋 기본 구조): 룰은 RTN(Rule Header)과 OTN(Rule Option)으로 나뉜다. 헤더는 `action protocol SRC_IP SRC_PORT -> DST_IP DST_PORT` 형식이고 action은 alert/log/pass, 방향은 `->` 또는 양방향 `<>`. 옵션에는 content, msg, depth, sid, threshold 등이 들어간다.

> 📷 스노트 룰 예시: `alert tcp 192.168.57.0/24 any -> 192.168.56.0/24 80 (msg:"HTTP Test"; sid:1000002;)`, threshold로 출발지별 10초 30회 이상을 DDoS로 보는 룰, `content:"SIGNAL"; depth:24`로 페이로드 앞 24바이트에서 문자열을 찾는 룰. content 보조 옵션으로 within(매칭 끝에서 N바이트 이내), distance(N바이트 건너뛴 뒤 탐색), byte_test가 있다.

LA

> 📷 강의 판서: 공격자(A)와 일반 사용자(U)가 IPS를 거쳐 웹 서버(80/443)로 접속하는 구성. IPS가 두 네트워크(57/56 대역) 사이 인라인에 위치한다.

스노트는 네트워크 인터페이스가 2개가 있다.

snor
