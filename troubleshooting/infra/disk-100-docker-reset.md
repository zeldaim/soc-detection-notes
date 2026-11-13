# 디스크 100% 풀 & Docker 초기화

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 📷 표시로 화면 내용을 글로 옮겼습니다.

### 증상
```plain text
/dev/mapper/rl-root   48G   48G   136K  100%  /
```

- dnf install 불가 (Errno 28: 장치에 남은 공간이 없음)
- Docker 컨테이너 시작 불가 (failed to mount)
- docker system prune 0B 반환

### 원인 분석
```plain text
/var/lib/docker      29G  ← Wazuh queue 누적
/var/lib/containerd  12G  ← 컨테이너 레이어
/var/lib/mysql      124M
```

근본 원인: Wazuh가 처리 못한 이벤트를 queue 볼륨에 누적 저장.

Kali에서 지속적인 Nmap 스캔 → iptables 로그 폭증 → Wazuh queue 30GB 누적

### 왜 일반 rm으로 안 지워졌나?

Docker가 containerd + overlay 파일시스템 방식을 사용하기 때문.
```plain text
예전 Docker (단순)
/var/lib/docker/volumes/wazuh-queue/_data/ → 파일 직접 존재

현재 Docker + containerd (복잡)
Docker 메타데이터 → /var/lib/docker/
실제 데이터      → /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/
                   (수백 개 레이어에 분산 저장)
```

docker volume ls에는 보이지만 ls /var/lib/docker/volumes/wazuh-queue/_data/가 없는 이유:

볼륨 포인터만 있고 실제 데이터는 containerd 스냅샷 레이어 안에 분산되어 있기 때문.

### 시도한 방법들 (실패)

### 해결 방법 — Docker + containerd 완전 초기화
```bash
# 1. 서비스 완전 중지
sudo systemctl stop docker docker.socket containerd

# 2. 데이터 완전 삭제
sudo rm -rf /var/lib/docker
sudo rm -rf /var/lib/containerd

# 3. 디렉토리 재생성
sudo mkdir /var/lib/docker
sudo mkdir /var/lib/containerd

# 4. 서비스 재시작
sudo systemctl start containerd
sudo systemctl start docker

# 5. 용량 확인
df -h /
```

결과:
```plain text
/dev/mapper/rl-root   48G   7.6G   41G   16%   /
```

### Wazuh 재설치 후 복구 순서
```bash
# 1. 인증서 생성
cd ~/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator

# 2. Wazuh 시작
docker compose up -d

# 3. local_rules.xml 재적용
cat > /tmp/local_rules.xml << 'EOF'
<group name="nmap,recon,">
  <rule id="100004" level="10">
    <if_sid>4100</if_sid>
    <match>PORTSCAN</match>
    <description>Nmap port scan detected via iptables</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
EOF
docker cp /tmp/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart

# 4. iptables PORTSCAN 룰 재적용
sudo iptables -I INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST \
  -m limit --limit 1/s \
  -j LOG --log-prefix "PORTSCAN: "

# 5. iptables 영구 적용
sudo dnf install iptables-services -y
sudo iptables-save | sudo tee /etc/sysconfig/iptables
sudo systemctl enable --now iptables
```

### 재발 방지

Kali에서 자동 스캔이 돌지 않도록 주의. iptables rate limit(--limit 1/s)이 설정되어 있지만 장시간 스캔 시 queue가 누적될 수 있음.

Wazuh queue 모니터링:
```bash
docker exec single-node-wazuh.manager-1 du -sh /var/ossec/queue/
```


## 2026-04-15 Trouble shooting 상세 리포트

1. 문제 발생
- iptables.service does not exist
  - Rocky Linux 9는 iptables 서비스 대신 nftables를 기본으로 사용
  - systemclt enable iptables 실패
- 디스크 공간 부족 - 다음 단계인 SQL 인젝션 전에 정리 필요
1. iptables 고정화 해결
```bash
# iptables-services 패키지 설치
sudo dnf install iptables-services -y

# 현재 룰 저장
sudo iptables-save | sudo tee /etc/sysconfig/iptables

# 서비스 활성화
sudo systemctl enable --now iptables
```

1. PORTSCAN 룰 확인 및 iptables 고정 확인

iptables 영구 적용 ✅

- enabled — 부팅 시 자동 시작
- active (exited) — 정상. iptables는 규칙 적용 후 프로세스가 종료되는 게 정상
- Applying firewall rules: OK

PORTSCAN 룰 확인 ✅

- 1번 라인에 PORTSCAN 룰 등록됨

3-1.Wazuh 룰 확인

컨테이너 내부에 있음
```bash
docker exec single-node-wazuh.manager-1 grep -r "PORTSCAN\|portscan" /var/ossec/ruleset/rules/ --include="*.xml" -l
```

롤 확인
```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/rules/local_rules.xml
```

1. 디스크 부족 원인은 Docker이고 ELK+Wazuh 컨테이너들이 로그를 계속 쌍으면서 용량을 먹고 있음

확인
```bash
df -h
docker system df
```
```bash
# 안 쓰는 Docker 이미지/컨테이너/볼륨 정리
sudo docker system prune -f

# Wazuh 알럿 로그 크기 확인
sudo du -sh /var/log/
```

원인
```bash
/dev/mapper/rl-root   48G   48G   136K  100%  /
Local Volumes         15개  30.37GB
```

/var/log는 16MB

하지만 Docker 볼륨이 30GB

볼륨 상세확인
```bash
docker volume ls
docker system df -v | grep -A 20 "Local Volumes"
```

큰 볼륨 찾기
```bash
sudo du -sh /var/lib/docker/volumes/* | sort -rh | head -10
```

문제 볼륨 발견
```bash
single-node_wazuh-queue    30.2GB  ← 여기가 문제
single-node_wazuh-logs     61.23MB
single-node_wazuh-indexer-data  103.9MB
```

wazuh-queue Wazuh가 처리 못한 이벤트를 큐에 쌓는데, Kali에서 계속 스캔을 때린 게 여기 누적

1. 큐 정리 (Wazuh 컨테이너 내부에서):
```bash
# Wazuh manager 중지
docker stop single-node-wazuh.manager-1

# 큐 비우기
docker run --rm -v single-node_wazuh-queue:/data alpine sh -c "rm -rf /data/sockets/* /data/diff/* /data/fim/db/*"

# 재시작
docker start single-node-wazuh.manager-1
```

재발 방지 — Kali 스캔 빈도 제한:

iptables 룰에 rate limit이 이미 있긴 한데(--limit 1/s), Kali에서 자동 스캔이 돌고 있다면 중지시켜야 한다.
```bash
# Kali에서 실행 중인 nmap 프로세스 확인
ps aux | grep nmap

```

1. Queue 비우기가 안됨 -디스크가 100% 꽉 차서 alpine 이미지 자체를 받을 공간이 없기 때문이다.

Alpine 이미지란 Alpine Linux라는 초경량 Linux 배포판의 Docker 이미지를 말함

Alpine 이미지는 Docker 컨테이너의 베이스 이미지로 자주 쓰임

Docker에서 컨테이너를 실행하건 이미지를 빌드할 때, 내부적으로 Alpine같은 작은 이미지를 임시 작업용으로 pull해서 사용하는 경우가 많다. 디스크가 꽉 차면 이 5MB짜리 작은 이미지 조차도 받을 수 없어서 작업 전체가 막힘.

Queue를 비우는 Docker 내부 작업이 Alpine 이미지를 필요로 했는데 → 디스크 100% → pull 불가 → 작업 실패한 흐름

해결은 디스크 공간 확보를 먼저 해야함- 미사용 이미지/컨테이너/ 볼륨 모두 삭제)
```bash
docker system prune -a6. 

```

1. queue를 비우는 다른 해결책 - 컨테이너 안으로 직접 들어가서 비우기- 하지만 manager가 죽어있음
```bash
# Wazuh manager 컨테이너 내부에서 직접 큐 비우기
docker exec -it single-node-wazuh.manager-1 bash -c "rm -rf /var/ossec/queue/sockets/* /var/ossec/queue/diff/* /var/ossec/queue/fim/db/*"
```

안되면 볼륨 마운트 경로 직접 접근:
```bash
# 볼륨 실제 경로 확인
sudo find /var/lib/docker -name "wazuh-queue" -type d 2>/dev/null
```

실행 후 용량 확인 :
```bash
df -h /
```

이전에 매니저가 살아있다고 생각함.

하지만 docker ps 가 캐시된 상태를 보여준 경우임.

특히 컨테이너가 종료 직전이거나 좀비 상태일 때는 ps 에는 up으로 찍히지만 실제 exec는 불가능한 타이밍이 존재한다.

<참고>

Wazuh Manager는 내부 watchdog이 있어서 특정 조건에서 스스로 종료합니다. 5일 업타임이면 메모리 누수나 큐 overflow로 죽는 경우도 흔합니다.

원인파악- 로그확인
```bash
docker logs single-node-wazuh.manager-1 --tail 50

```

1. Manager 다시 켜고 볼륨삭제 시도 - 컨테이너가 가득차있고 볼륨 경로가 containd방식이라 달라 실패함
```bash
docker start single-node-wazuh.manager-1
```

시작 후 바로:
```bash
docker exec single-node-wazuh.manager-1 bash -c "rm -rf /var/ossec/queue/diff/* /var/ossec/queue/fim/db/* /var/ossec/queue/alerts/*"
```

만약 디스크 공간 문제로 안되면
```bash
# 볼륨 직접 접근해서 삭제
sudo ls /var/lib/docker/volumes/single-node_wazuh-queue/_data/
```

1. Wazuh queue 경로 찾기
```bash
/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/183/fs/var/ossec/queue
```

큰 디렉토리 확인:
```bash
sudo du -sh /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/183/fs/var/ossec/queue/*
```

경로가 실행 파일로 인식이 됨

1. du 명령어 제대로 실행
```bash
sudo du -sh /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/183/fs/var/ossec/queue/*
```

스냅샷 183 : 실제 데이터가 없는 레이어, containerd는 overlay 방식이라 실제 데이터가 다른 레이어에 있음

1. 실제 데이터가 있는 볼륨 찾기
```bash
sudo du -sh /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs/var/ossec/queue 2>/dev/null | sort -rh | head -5
```

하지만 아무것도 못찾음

1. 다시 30GB의 위치를 찾기

실제 큐 데이터는 overly의 upperdir에 있을 것 같음
```bash
sudo du -sh /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs/var/ossec/ 2>/dev/null | sort -rh | head -10 
```
```bash
sudo du -sh /var/lib/containerd/* 2>/dev/null | sort -rh | head -10ls 시도
```
```bash
sudo ls /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/183/fs/var/ossec/queue/
```

1. 전체 경로 탐색
```bash
sudo du -sh /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/ 2>/dev/null
```

snapshots는 7.8G뿐이기 때문에 여기에는 30GB 없음.
```bash
sudo du -sh /var/lib/containerd/*
```

Docker가 containerd를 사용하지만 실제 볼륨 데이터는 다른 경로에 있다. 그레서 찾지 못함
```bash
sudo du -sh /var/lib/docker/*
```

Docker 데이터가 기본 경로에는 없다.

1. Docker 기본 경로 찾기
```bash
sudo docker info | grep "Docker Root Dir"
```

하지만 경로가 맞지만 단지 접근이 안될 뿐임을 확인
```bash
sudo ls /var/lib/docker/
```

1. single-node_wazuh-queue 의 볼륨 존재 확인하고 그 안의 내용 확인
```bash
sudo ls /var/lib/docker/volumes/
```
```bash
sudo ls /var/lib/docker/volumes/single-node_wazuh-queue/_data/
```

볼륨 목록에는 있는데 실제 디렉토리가 없는 것은 Docker가 containerd 볼륨 플러그인을 쓰기 때문이다.

실제 데이터는 containerd의 스냅샷 안에 있음

1. 공간을 조금이라도 확보 시도
```bash
# 안 쓰는 Docker 이미지 강제 삭제
sudo docker image prune -a -f
```

모든 이미지가 실행 중인 컨테이너에 연결이되어 있어 삭제가 되지 않음

1. /home 에 있는 23G에 Docker 데이터를 옮기기 시도 - 실패
```bash
# 1. 모든 컨테이너 중지
docker stop $(docker ps -q)

# 2. Docker 서비스 중지
sudo systemctl stop docker

# 3. /home에 새 Docker 디렉토리 생성
sudo mkdir /home/docker-data

# 4. 기존 Docker 데이터 복사
sudo cp -r /var/lib/docker/* /home/docker-data/

# 5. Docker 설정 변경
sudo nano /etc/docker/daemon.json
```

daemon.json에 추가:
```bash
{
  "data-root": "/home/docker-data"
}
```
```bash
# 6. Docker 재시작
sudo systemctl start docker

# 7. 정상 확인
docker ps
```

컨테이너가 하나도 없음 =docker root는 이동이 되었는데 컨테이너들의 안 옮겨짐

확인
```bash
df -h /
docker info | grep "Docker Root Dir"
```

- Docker Root Dir: /home/docker-data ✅ 변경 성공
- / 여전히 100% — cp가 실패해서 기존 데이터가 안 옮겨진 것
- 컨테이너 없음 — 새 Docker root가 비어있기 때문

그래서 cp를 위해서 기존 데이터 삭제해서 공간 확보

Docker root가 /home/docker-data로 바뀌었으니 /var/lib/docker 구 데이터가 /를 잡고 있고,  아까 Docker가 containerd를 쓰고 있어서  ls /var/lib/docker는 됐는데 du가 안되었다.
```bash
sudo ls /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/ | wc -l

```
```bash
sudo du -sh /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/
```
```bash
sudo rm -rf /var/lib/docker/volumes/*
```

volumes 삭제
```bash
df -h /
```

하지만 아직도 데이터가 삭제가 안됨.

진짜 데이터는 containerd에 있기때문이다.

1. 1GB 이상 파일 모두 찾기 시도
```bash
sudo find / -xdev -size +1G -ls 2>/dev/null
```

하나도 없음

데이터가 수많은 작은 파일로 분산되어 있다는 뜻

-xdev 옵션이 마운트 경계를 넘지 않아서 /home을 못 봤을 수도 있음
```bash
sudo du -sh /home/docker-data/

```

/home/docker-data는 152K뿐이고, /는 48G 꽉 찼는데 1G 이상 파일도 없음

이건 수많은 작은 파일들이 inode를 꽉 채운 경우
```bash
df -i /
```

inode는 76%

inode란?

- 파일 하나 = 블록(내용) + inode(메타데이터) 두 가지가 필요
- 블록이 남아도 inode가 꽉 차면 파일 생성 불가

"디스크 공간은 있는데 파일 못 만든다" 는 증상이 inode 고갈의 전형적 패턴이지만 그게 원인은 아님을 확

그러면 실제 블록이 꽉 참

containerd가 있는  /var/lib/containerd 를 확인

Docker/containerd가 쓰는 디렉토리를 먼저 본 이유:
> Wazuh 같은 컨테이너 환경에서 디스크를 제일 많이 먹는 주범이 컨테이너 이미지/레이어이기 때문

결과: 1.2G → 범인 아님.
```bash
sudo du -sh /var/lib/containerd/
```

48G를 다 쓰고 있는데 어디 있는지 전체 탐색
```bash
sudo du -sh /* 2>/dev/null | sort -rh | head -15
```

/var 임을 확인
```bash
sudo du -sh /var/* 2>/dev/null | sort -rh | head -10
```

/var/lib 41G, /var/cache 2.5G
```bash
sudo du -sh /var/lib/* 2>/dev/null | sort -rh | head -10
```
```bash
/var/lib/docker      29G  ← 아직 여기 있음
/var/lib/containerd  12G  ← 여기도
```

daemon.json 변경했는데도 /var/lib/docker가 그대로

Docker root가 /home/docker-data로 바뀌었지만 기존 데이터가 삭제가 안 된 것

Docker가 /home/docker-data를 쓰고 있으니 /var/lib/docker 구 데이터 삭제
```bash
sudo rm -rf /var/lib/docker/*
```
```bash
sudo rm -rf /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*
```

실패
```bash
sudo du -sh /var/lib/* 2>/dev/null | sort -rh | head -5
```

rm이 실행됐는데도 여전히 29G + 12G가 남아있다.

삭제된 파일인데 Docker/containerd 프로세스가 파일 핸들을 잡고 있어서 실제로 공간이 반환이 안됨

Docker 서비스를 완전히 중지
```bash
sudo systemctl stop docker
sudo systemctl stop docker.socket
sudo systemctl stop containerd

```
```bash
df -h /
```

여전히 100%

du로는 29G 있지만 df 로는 공간이 안 풀리고 있음

한 가지 가능성은 /var/lib/docker와 /var/lib/containerd가 실제로는 다른 파티션이나 마운트해 있어서 데이터가 이동이 안되는 것 일 수 있다.
```bash
df -h /var/lib/docker
df -h /var/lib/containerd

```

하지만,

둘 다 같은 / 파티션에 있음

재부팅하면 파일 핸들이 전부 해제되면서 공간이 풀릴 수도 있지만..

리부팅이후에도 여전히 100%
```bash
sudo du -sh /var/lib/* 2>/dev/null | sort -rh | head -5
```

rm 명령어가 실제로 삭제를 안했음을 확인 -/var/lib/docker가 여전히 29G

이유: Docker가 containerd 스냅샷을 overlay 마운트로 쓰고 있어서 일반 rm으로는 안 지워짐

1. 초기화
```bash

# containerd 완전 초기화
sudo systemctl stop docker docker.socket containerd

sudo rm -rf /var/lib/docker
sudo rm -rf /var/lib/containerd

sudo mkdir /var/lib/docker
sudo mkdir /var/lib/containerd

sudo systemctl start containerd
sudo systemctl start docker

df -h /

```
```bash
/ : 48G → 7.6G 사용, 41G 여유 (16%)
```

공간 확보는 성공

1. Wazuh + ELK 재설치

daemon.json도 원래대로 수정
```bash
# daemon.json 초기화 (data-root 설정 제거)
sudo bash -c 'echo "{}" > /etc/docker/daemon.json'

# Docker 재시작
sudo systemctl restart docker

```

그 다음 Wazuh single-node 재설치를 위해 Wazuh 설치 파일 경로 확
```bash
cd ~/단일노드_디렉토리
# 기존 Wazuh docker-compose 디렉토리로 이동
ls ~
```
```bash
cd ~/wazuh-docker
ls
```

single-node로 이동해서 재설치:
```bash
cd single-node

# 인증서 생성
docker compose -f generate-indexer-certs.yml run --rm generator

# Wazuh 시작
docker compose up -d
```
```bash
docker ps
```

3개 컨테이너 모두 정상 실행 중

1. 컨테이너 초기화 전 상태로 복구하기

19-1.  local_rules.xml 재적용 (Nmap 룰)
```bash
docker exec -it single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << EOF
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>

<group name="nmap,recon,">
  <rule id="100004" level="10">
    <if_sid>4100</if_sid>
    <match>PORTSCAN</match>
    <description>Nmap port scan detected via iptables</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>
</group>
EOF'
```

19-2.Wazuh manager 재시작
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

확인:
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
```

정상

1. ptables PORTSCAN 룰 복구:
```bash
sudo iptables -I INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST \
  -m limit --limit 1/s \
  -j LOG --log-prefix "PORTSCAN: "
```

적용 후 확인 :
```bash
sudo iptables -L INPUT --line-numbers | grep PORTSCAN
```

PORTSCAN 룰 1번으로 등록

iptables 영구 적용:
```bash
sudo dnf install iptables-services -y
sudo iptables-save | sudo tee /etc/sysconfig/iptables
sudo systemctl enable --now iptables
```

1. Wazuh 에이전트 재연결 확인
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

Rocky Linux 에이전트(yhc) 1개만 연결

재설치로 manager가 초기화되면서 에이전트 등록 정보가 날아감

1. 각 VM에서 에이전트를 재등록
```bash

Rocky Linux IP(192.168.190.128)가 맞는지 확인

```

Kali Linux에서:
```bash
sudo /var/ossec/bin/agent-auth -m 192.168.190.128
sudo systemctl restart wazuh-agent
```

Windows 10에서:

PowerShell 관리자 권한으로:
```bash
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 192.168.190.128
```
```bash
Restart-Service WazuhSvc
```

Windows 에이전트 이름이 manager에 남아있음.
```bash
# Rocky Linux에서 기존 Windows 에이전트 확인
docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -l
```

DESKTOP-5408CBA가 ID 002로 이미 등록

Windows에서 서비스만 재시작

agent_control에는 안 보이는 건 아직 연결이 안 된 것뿐

Windows에서 서비스만 재시작
```bash
Restart-Service WazuhSvc
```
```bash
# Rocky Linux에서 
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

DESKTOP-5408CBA가 Active확인

22-1. agent_control -l , manage_agents -l

### 두 리스트의 차이

agent_control -l — 현재 접속 중인 에이전트
```bash
Active = 지금 manager와 통신 중
```

manage_agents -l — manager에 등록된 에이전트 전체 목록
```bash
등록만 되어 있고 접속 안 한 것도 보임
```

에이전트 등록 과정 정리
```bash
1. agent-auth.exe 실행
        ↓
   Windows가 Manager에게 "나 등록해줘" 요청
        ↓
   Manager가 에이전트 이름(DESKTOP-5408CBA)과 
   ID(002)를 부여하고 인증키 발급
        ↓
2. Restart-Service WazuhSvc
        ↓
   에이전트가 인증키로 Manager에 접속
        ↓
   Active 상태가 됨
```

등록(agent-auth) → 연결(서비스 시작)
