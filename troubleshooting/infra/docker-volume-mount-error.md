# Docker volume mount 오류 (Wazuh 설치)

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

설정파일 누락으로 인한 연쇄 오류

## [Troubleshooting] Docker Volume Mount 오류

### 환경

- OS: Rocky Linux 9
- Docker CE
- Wazuh 4.7.0

### 오류 메시지
```text
mount src=/home/yhc/wazuh/config/wazuh_indexer/wazuh.indexer.yml
not a directory
```

### 원인

curl로 docker-compose.yml만 받으면

참조하는 설정파일이 없어서

Docker가 파일 자리에 빈 디렉토리 생성

→ 파일이 있어야 할 자리에 디렉토리가 있으니

mount 실패

### 해결 방법

curl 대신 git clone으로 전체 파일 받기
```text
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node
docker compose up -d
```

### 배운 것

- curl은 단일 파일만 받음
- git clone은 전체 프로젝트 구조를 받음
- Docker volume mount시 파일/디렉토리 타입 일치 필요
