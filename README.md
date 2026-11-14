# SOC Detection & Troubleshooting Notes

Wazuh SIEM 기반 홈 SOC 랩에서 직접 구현한 **탐지 룰**과 운영 중 겪은 **장애 대응 기록**을 정리한 레포입니다.
개인 학습 노트(Notion)에 쓰던 기록을 옮겨 왔습니다. 스크린샷은 이미지 대신 📷 표시로 화면 내용(알림, 룰 ID, 명령 결과)을 글로 옮겼습니다.

- 환경: Rocky Linux 9 + Docker (Wazuh 4.x single-node), Windows 10/11 + Sysmon 에이전트, Kali Linux(공격 VM)
- 관련 레포: [wazuh-slack-alertbot](https://github.com/zeldaim/wazuh-slack-alertbot) · [kisa-windows-hardening-lab](https://github.com/zeldaim/kisa-windows-hardening-lab) · [home-soc-lab](https://github.com/zeldaim/home-soc-lab)
- Wazuh 공식 이슈 리포트: [#35707](https://github.com/wazuh/wazuh/issues/35707) (Sysmon EventID 13 알림 미생성) · [#36029](https://github.com/wazuh/wazuh/issues/36029) (`if_sid` 체인 동작 변경)

## 탐지 (detection/)

| MITRE | 내용 | 문서 |
|---|---|---|
| T1547 Boot or Logon Autostart | Sysmon 레지스트리(Run 키)·서비스 등록 이벤트로 지속성 탐지. 룰 체인 미발동 원인 추적 → 부분 완성 → 탐지 성공까지 5편 | [T1547-persistence/](detection/T1547-persistence/) |
| T1046 Network Service Discovery | iptables PORTSCAN 로그 → `/var/log/secure` 파이프라인, 커스텀 룰 100004, Kali Nmap 스캔 실탐지 | [T1046-nmap-portscan.md](detection/T1046-nmap-portscan.md) |

## 장애 대응 (troubleshooting/)

### Wazuh 룰
| 증상 | 원인 요약 | 문서 |
|---|---|---|
| SSH 브루트포스 커스텀 룰(100001) 미발동 | 기본 룰 5763과 조건 중복, 실제 적용된 룰이 의도와 다름 | [ssh-bruteforce-rule-100001.md](troubleshooting/wazuh-rules/ssh-bruteforce-rule-100001.md) |
| SQL Injection 커스텀 룰(100005) 미발동 | 부모 룰 31103은 정상 → 룰 수정 후 매니저 재시작·새 트래픽 없이 이전 로그를 확인한 것이 원인. 룰 파일은 호스트가 아니라 컨테이너 내부에 있음 | [sqli-custom-rule-not-firing.md](troubleshooting/wazuh-rules/sqli-custom-rule-not-firing.md) |
| Nmap 스캔 로그는 `/var/log/secure`에 찍히는데 알림(100004) 없음 | 에이전트 `ossec.conf`의 `/var/log/secure` 블록에 `<log_format>` 누락 → 수정 중 중복 삽입(XML 구조 오류). 정리 후 100004 발동 | [rule-xml-structure-error.md](troubleshooting/wazuh-rules/rule-xml-structure-error.md) |

### 인프라 운영
| 증상 | 문서 |
|---|---|
| Wazuh Indexer 중단 + VM 디스크 풀 | [wazuh-indexer-disk-full.md](troubleshooting/infra/wazuh-indexer-disk-full.md) |
| 디스크 100% → Docker 초기화 | [disk-100-docker-reset.md](troubleshooting/infra/disk-100-docker-reset.md) |
| Hydra 실습 중 로그 폭증으로 VM 디스크 풀 | [vm-disk-full-recovery.md](troubleshooting/infra/vm-disk-full-recovery.md) |
| Logstash → Elasticsearch 연결 실패 | [logstash-elasticsearch-connection.md](troubleshooting/infra/logstash-elasticsearch-connection.md) |
| Wazuh 재설치 시 남은 SSL 인증서로 인증 실패 | [wazuh-ssl-certificate-leftover.md](troubleshooting/infra/wazuh-ssl-certificate-leftover.md) |
| Docker volume mount 오류 (설정 파일 누락) | [docker-volume-mount-error.md](troubleshooting/infra/docker-volume-mount-error.md) |

## 하드닝 (hardening/)

- [KISA 윈도우 보안 점검 스크립트 정리](hardening/kisa-windows-check-script.md)

## 수업 노트 (notes/)

교육 과정에서 듣고 실습한 내용을 정리한 노트입니다. 강의 슬라이드는 제 말로 요약했습니다.

| 분야 | 문서 |
|---|---|
| 네트워크 보안 | [OPNSense PF·NAT](notes/network-security/opnsense-pf.md) · [방화벽·WAF 실습](notes/network-security/firewall-waf.md) · [스노트 IDS/IPS 룰](notes/network-security/snort-ips-rules.md) · [ZED 패킷 분석](notes/network-security/zed-packet-analysis.md) |
| BAS | [CALDERA 에이전트·어빌리티](notes/bas/caldera.md) |
| MITRE ATT&CK | [T1218.005 Mshta 프록시 실행·탐지](notes/mitre-attack/t1218-005-mshta.md) |
| 악성코드 | [C2·지속성·은닉](notes/malware/c2-persistence-evasion.md) |
| Security Gym | [위협 이벤트 분석](notes/security-gym/threat-events.md) |

## 배운 점

- 룰을 고치기 전에 **현재 상태를 먼저 측정**한다 (`wazuh-logtest`, `archives.json`, 실제 적용된 `local_rules.xml` 확인).
- 커스텀 룰은 **기본 룰과의 체인·조건 중복**부터 의심한다.
- 보안 실습은 로그를 대량으로 만든다. **디스크 용량과 로그 로테이션**도 관제 환경의 일부다.
