# [수업 노트] OPNSense — PF 패킷 처리 순서와 NAT

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

> 📷 강의 슬라이드: OPNSense는 FreeBSD 기반이라 패킷 통제에 PF(Packet Filter) 커널 모듈을 쓰고 pfctl로 제어한다(리눅스의 netfilter/iptables에 해당). PF 처리 순서는 정규화(조각 재조립·TTL 정리) → NAT(rdr-to 목적지 변환, nat-to 출발지 변환, binat-to 양방향) → 필터링(block/pass) → 라우팅 테이블로 출력 NIC 결정.

NAT에서 헤더의 주소를 변환한다.
