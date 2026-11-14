# [수업 노트] 패킷 분석 — ZUI/ZED로 Zeek 로그 질의

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

- ZUI 에서 ZED 기본 쿼리 실습
- Zeek 로그 조히 하고 필드 선택, 조건 필터링, 정렬, 집계, 중복 제거 문자열 검색을 수행할 수 있다.
- ZED는 오픈 소스 데이터 질의, 분석 도구

> 📷 강의 슬라이드(ZUI 화면 구성): ZUI는 ZED 쿼리를 데스크톱에서 쓰는 도구. pcap이나 Zeek 로그를 열면 데이터 Pool로 들어가고, 상단 Query 세션에 쿼리를 입력하면 아래 데이터 윈도우(_path, ts, uid, id, proto, duration, conn_state 등 Zeek conn 필드)가 바로 갱신된다.

> 📷 ZED 쿼리 기본 구조: `where 조건 | cut 필드 | sort 기준 | head 개수`처럼 파이프로 단계적으로 좁힌다. 예: `where proto=="tcp" | cut ts, id.orig_h, id.resp_h, id.resp_p, service | head 10`.

> 📷 실습 준비: btlo1-webshell.pcap(465KB)을 ZUI Pool 영역에 드래그해 등록한 뒤 'Query Pool' 클릭.

> 📷 실습 1 `head 10`: 앞쪽 레코드 10개 조회. 결과에 capture_loss, stats, conn, dhcp 등 여러 _path(4 Shapes)가 섞여 나온다.

> 📷 `where _path=="conn" | head 10`: conn 로그만 남김. icmp(IPv6 멀티캐스트), udp dhcp/dns 연결이 보인다.

> 📷 `cut ts, uid, id.orig_h, id.resp_h, id.resp_p, proto, service, duration, conn_state` 추가로 분석에 필요한 필드만 표시. conn_state는 OTH, SHR, S0 등.

> 📷 `where _path=="conn" and (id.resp_p==80 or id.resp_p==443)`: 웹 포트 연결만 필터링. 172.20.10.5→172.20.10.2, 10.251.96.4→10.251.96.5 사이 http 연결이 대부분 SF(정상 종료).

1. SORT, -R

> 📷 `sort -r duration`: 연결 시간이 긴 순으로 정렬. 최장 3분 21초(S1), 다음 2분 14초 http(S2), 2분 ssh(172.20.10.5→172.20.10.2) 순.

> 📷 실습 2 `count() by id.resp_p | sort -r count`: 도착지 포트별 연결 수. 80번 258건으로 압도적, 이어서 5353(23), 53(19), 67(12), 137/133/0(각 10), 22(3).

> 📷 `cut id.resp_p | sort | uniq`: conn 로그에 나온 도착지 포트를 중복 없이 나열(0, 1, 2, 3 … 순으로 이어짐 — 연속된 낮은 포트가 많은 건 스캔 흔적일 수 있음).

> 📷 `where _path=="dns" and grep(/[0-9a-z]{10,}/, query)`: 영숫자 10자 이상 이어진 DNS 질의 검색. 결과는 connectivity-check.ubuntu.com(172.20.10.2, 127.0.0.1)뿐.
