# Wazuh Indexer & VM 디스크 풀

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

## 2026-05-01 Troubleshooting — Wazuh Indexer & VM Disk Full

### 환경

- Rocky Linux 9 (VMware Workstation Pro)
- Wazuh 4.9.0 Single-node Docker
- Host OS: Windows 11

### 🔴 Issue 1: Wazuh Indexer curl 접속 불가

#### 증상
```bash
$ curl localhost:9200
curl: (52) Empty reply from server

$ curl -k https://localhost:9200
# 아무 응답 없음

$ curl -k -u admin:특수문자포함된비밀번호 https://localhost:9200
# 아무 응답 없음
```

#### 원인 분석

#### 디버깅 과정
```bash
# 1. docker logs로 원인 파악
docker logs single-node-wazuh.indexer-1 --tail 50
# → NotSslRecordException 확인 (HTTP로 요청했기 때문)

# 2. -v 옵션으로 상세 확인
read -s PW 
curl -kv -u "admin:$PW" https://localhost:9200
# → 401 Unauthorized 확인, SSL 연결 자체는 정상

# 3. Base64 디코딩으로 비밀번호 확인
echo "YWRtaW46..." | base64 -d
# → 비밀번호가 제대로 전달됐는지 확인
```

#### 해결

Firefox about:logins 에서 저장된 비밀번호 확인 후:
```bash
curl -k -u "admin:SecretPassword" https://localhost:9200
# → 200 OK, 정상 응답
```

#### 핵심 교훈

- Wazuh Indexer는 반드시 https:// + k 옵션 사용
- 비밀번호에 특수문자 있으면 작은따옴표 또는 변수로 전달
- 비밀번호 분실 시 Firefox about:logins 확인

### 🔴 Issue 2: VMware VM 디스크 공간 부족 (D 드라이브 0바이트)

#### 증상
```plain text
The operation on the file "...vmdk" failed
The file system where disk resides is full.
```

VM이 강제 리셋됨. 스냅샷 삭제 시도 → There is not enough space 에러.

#### 원인 분석
```powershell
# D 드라이브 상태 확인
Get-PSDrive -PSProvider FileSystem | Select Name, Used, Free
# D: Used=212GB, Free=2GB (사실상 0)

# 가장 큰 파일 확인
Get-ChildItem D:\ -Recurse -File | Sort-Object Length -Descending | Select-Object -First 20
```

#### 해결 순서

1단계: .vmem 파일 삭제 (11GB 확보)
```powershell
Remove-Item 'D:\VM\Rockey9\564d85b8-cabb-41cd-3d80-49e1f9a35d7d.vmem'
Remove-Item 'D:\Windows\Windows 10 x64-ba4e1c0a.vmem'
```

2단계: VMware 스냅샷 삭제 (추가 공간 확보)

- VMware → VM 우클릭 → 스냅샷 관리자
- Rocky9, Kali, Windows VM 스냅샷 전부 삭제
- 병합 완료 후 000001-sXXX.vmdk 파일들 자동 제거

결과
```plain text
Before: D: Free = 2GB
After:  D: Free = 32GB
```

#### 핵심 교훈

- .vmem 파일은 VM 실행 중 메모리 덤프. VM 꺼져 있으면 삭제 가능
- 스냅샷은 000001, 000002 형태로 누적되며 디스크를 빠르게 소진
- 스냅샷 병합도 최소 수 GB 여유 공간 필요 → 평소에 10GB 이상 유지 권장
- 주기적으로 Get-ChildItem -Recurse | Sort-Object Length 로 큰 파일 점검

### 관련 링크

- home-soc-lab
- Wazuh Docker 공식 문서
