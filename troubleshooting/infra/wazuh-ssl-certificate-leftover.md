# SSL 인증서 잔여물로 인한 인증 문제 (Wazuh 설치)

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 생략했습니다.

설정파일 누락으로 인한 연쇄 오류

#### curl로 Wazuh 설치 시

설정파일 누락으로 인한 연쇄 오류
```text
docker ps
```
```text
[yhc@localhost single-node]$ docker compose up -d
WARN[0000] /home/yhc/wazuh-docker/single-node/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion 
[+] up 3/3
 ✔ Container single-node-wazuh.manager-1   Running                                                                                                                                                        0.0s
 ✔ Container single-node-wazuh.indexer-1   Started                                                                                                                                                        0.1s
 ✔ Container single-node-wazuh.dashboard-1 Started                                                                                                                                                        0.2s
[yhc@localhost single-node]$ docker ps
CONTAINER ID   IMAGE                         COMMAND                   CREATED         STATUS                                  PORTS                                                                                                                                                                 NAMES
befa70f6e712   wazuh/wazuh-dashboard:4.9.0   "/entrypoint.sh"          8 minutes ago   Up Less than a second                   443/tcp, 0.0.0.0:443->5601/tcp, [::]:443->5601/tcp                                                                                                                    single-node-wazuh.dashboard-1
c00d079c5608   wazuh/wazuh-indexer:4.9.0     "/entrypoint.sh open…"   8 minutes ago   Restarting (1) Less than a second ago                                                                                                                                                                         single-node-wazuh.indexer-1
3f4ac2459330   wazuh/wazuh-manager:4.9.0     "/init"                   8 minutes ago   Up 17 seconds                           0.0.0.0:1514-1515->1514-1515/tcp, [::]:1514-1515->1514-1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp, 1516/tcp   single-node-wazuh.manager-1
[yhc@localhost single-node]$
```
```text
wazuh.indexer-1 → Restarting (1) ❌
```

indexer가 계속 재시작

로그 확인
```text
docker logs single-node-wazuh.indexer-1
```

직접 파일 확인 시도
```text
docker exec single-node-wazuh.indexer-1 cat /var/log/wazuh-indexer/opensearch.log | tail -30
```
```text

[yhc@localhost single-node]$ docker exec single-node-wazuh.indexer-1 cat /var/log/wazuh-indexer/opensearch.log | tail -30
Error response from daemon: Container c00d079c560870b56420708cd7ccd2b40c4c93e50a79d5b0723ebe9075154a28 is restarting, wait until the container is running
[yhc@localhost single-node]$
```

하지만 컨테이너가 재시작 중이라 접근이 안됨
```text
docker logs single-node-wazuh.indexer-1 --tail 50 2>&1 | grep -i "error\|exception\|fatal"
```
```text
[yhc@localhost single-node]$ docker exec single-node-wazuh.indexer-1 cat /var/log/wazuh-indexer/opensearch.log | tail -30
Error response from daemon: Container c00d079c560870b56420708cd7ccd2b40c4c93e50a79d5b0723ebe9075154a28 is restarting, wait until the container is running
[yhc@localhost single-node]$ docker logs single-node-wazuh.indexer-1 --tail 50 2>&1 | grep -i "error\|exception\|fatal"
uncaught exception in thread [main]
java.lang.IllegalStateException: failed to load plugin class [org.opensearch.security.OpenSearchSecurityPlugin]
Likely root cause: OpenSearchException[Is a directory: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem Expected a file for plugins.security.ssl.transport.pemcert_filepath]
	at org.opensearch.cli.Command.mainWithoutErrorHandling(Command.java:138)
For complete error details, refer to the log at /var/log/wazuh-indexer/opensearch.log
[yhc@localhost single-node]$
```

원인은
```text
Is a directory: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
Expected a file
```

이 부분으로봐

인증서가 있어야 할 자리에 디렉토리가 생성이 된 것이다. curl을 받았을 때 생긴 찌꺼기가 남아 있음

해결 시도
```text
# Wazuh 전부 내리기
docker compose down -v

# 찌꺼기 볼륨 전부 삭제
docker volume prune -f

# 다시 올리기
docker compose up -d
```

결과-실패
```text
CONTAINER ID   IMAGE                         COMMAND                   CREATED          STATUS                              PORTS                                                                                                                                                                 NAMES
befa70f6e712   wazuh/wazuh-dashboard:4.9.0   "/entrypoint.sh"          19 minutes ago   Restarting (1) 48 seconds ago                                                                                                                                                                             single-node-wazuh.dashboard-1
c00d079c5608   wazuh/wazuh-indexer:4.9.0     "/entrypoint.sh open…"   19 minutes ago   Restarting (1) About a minute ago                                                                                                                                                                         single-node-wazuh.indexer-1
3f4ac2459330   wazuh/wazuh-manager:4.9.0     "/init"                   19 minutes ago   Up 5 seconds                        0.0.0.0:1514-1515->1514-1515/tcp, [::]:1514-1515->1514-1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp, 1516/tcp   single-node-wazuh.manager-1
[yhc@localhost single-node]$
```

해결시도
```text
# 강제로 전부 내리기
docker compose down -v --remove-orphans

# 모든 컨테이너 강제 삭제
docker rm -f $(docker ps -aq)

# 모든 볼륨 삭제
docker volume rm $(docker volume ls -q)

# 다시 올리기
docker compose up -d
```
```text
CONTAINER ID   IMAGE                         COMMAND                   CREATED         STATUS         PORTS                                                                                                                                                                 NAMES
831096d6daea   wazuh/wazuh-dashboard:4.9.0   "/entrypoint.sh"          6 seconds ago   Up 1 second    443/tcp, 0.0.0.0:443->5601/tcp, [::]:443->5601/tcp                                                                                                                    single-node-wazuh.dashboard-1
ae635e876cd0   wazuh/wazuh-indexer:4.9.0     "/entrypoint.sh open…"   6 seconds ago   Up 1 second    0.0.0.0:9200->9200/tcp, [::]:9200->9200/tcp                                                                                                                           single-node-wazuh.indexer-1
1d5e94b2675d   wazuh/wazuh-manager:4.9.0     "/init"                   6 seconds ago   Up 5 seconds   0.0.0.0:1514-1515->1514-1515/tcp, [::]:1514-1515->1514-1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp, 1516/tcp   single-node-wazuh.manager-1
[yhc@localhost single-node]$
```

하지만
```text
https://localhost:443
```

연결이 안됨

원인 찾기
```text
docker logs single-node-wazuh.dashboard-1 --tail 20
```

결과
```text
[yhc@localhost single-node]$ docker logs single-node-wazuh.dashboard-1 --tail 20
    at readFileSync (node:fs:490:19)
    at readFile (/usr/share/wazuh-dashboard/src/core/server/http/ssl_config.js:170:31)
    at new SslConfig (/usr/share/wazuh-dashboard/src/core/server/http/ssl_config.js:130:18)
    at new HttpConfig (/usr/share/wazuh-dashboard/src/core/server/http/http_config.js:174:16)
    at MapSubscriber.project (/usr/share/wazuh-dashboard/src/core/server/http/http_service.js:67:177)
    at MapSubscriber._next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/operators/map.js:49:35)
    at MapSubscriber.Subscriber.next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/Subscriber.js:66:18)
    at CombineLatestSubscriber.notifyNext (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/observable/combineLatest.js:97:34)
    at InnerSubscriber._next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/InnerSubscriber.js:28:21)
    at InnerSubscriber.Subscriber.next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/Subscriber.js:66:18)
    at MapSubscriber._next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/operators/map.js:55:26)
    at MapSubscriber.Subscriber.next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/Subscriber.js:66:18)
    at DistinctUntilChangedSubscriber._next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/operators/distinctUntilChanged.js:69:30)
    at DistinctUntilChangedSubscriber.Subscriber.next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/Subscriber.js:66:18)
    at MapSubscriber._next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/operators/map.js:55:26)
    at MapSubscriber.Subscriber.next (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/Subscriber.js:66:18)
    at ReplaySubject._subscribe (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/ReplaySubject.js:80:28)
    at ReplaySubject.Observable._trySubscribe (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/Observable.js:44:25)
    at ReplaySubject.Subject._trySubscribe (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/Subject.js:102:51)
    at ReplaySubject.Observable.subscribe (/usr/share/wazuh-dashboard/node_modules/rxjs/internal/Observable.js:30:22)
[yhc@localhost single-node]$
```

#### 인증서 문제
```text
at readFileSync (node:fs:490:19)
at readFile (.../ssl_config.js:170:31)
at new SslConfig (.../ssl_config.js:130:18)
```

를 통해
```text
ssl_config → SSL 설정 파일
readFile 실패 → 파일을 못 읽음
```

SSL 설정 읽다가 실패한 것임을 알 수 있음.

하지만 down-v 후 다시 올리면
```text
Wazuh 처음 실행할 때
→ 자동으로 SSL 인증서 생성해요
→ 근데 볼륨이 남아있으면
  이전 찌꺼기 인증서가 남아있음
→ down -v 로 볼륨까지 삭제
→ 다시 올리면 인증서 새로 생성
→ 정상 작동
```

오래된 인증서는 삭제 되고 새 인증서가 발급이 되어 정상 접속이 된다.

하지만 지금 down-v가 제대로 안되어 인증서가 새로 발급이 안되는 상황이다.

근본 원인은
```text
처음에 curl로 yml만 받음
        ↓
설정파일 없으니 빈 디렉토리 생성
        ↓
그 찌꺼기가 볼륨에 남아있음
        ↓
인증서 자리에도 디렉토리가 생성됨
        ↓
SSL 인증서 읽기 실패
        ↓
dashboard 실행 실패
```

하지만 여전히 안됨
```text
CONTAINER ID   IMAGE                         COMMAND                   CREATED         STATUS                          PORTS                                                                                                                                                                 NAMES
bf944ce83715   wazuh/wazuh-dashboard:4.9.0   "/entrypoint.sh"          3 minutes ago   Restarting (1) 7 seconds ago                                                                                                                                                                          single-node-wazuh.dashboard-1
922679db6162   wazuh/wazuh-manager:4.9.0     "/init"                   3 minutes ago   Up 14 seconds                   0.0.0.0:1514-1515->1514-1515/tcp, [::]:1514-1515->1514-1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp, 1516/tcp   single-node-wazuh.manager-1
ad8c3db0ca59   wazuh/wazuh-indexer:4.9.0     "/entrypoint.sh open…"   3 minutes ago   Restarting (1) 11 seconds ago                                                                                                                                                                         single-node-wazuh.indexer-1
```

완전 초기화
```text
# 전부 내리기
docker compose down -v

# Wazuh 관련 볼륨 전부 확인
docker volume ls | grep wazuh

# 전부 삭제
docker volume ls | grep wazuh | awk '{print $2}' | xargs docker volume rm

# 다시 올리기
docker compose up -d
```

여전히 같은 오류가 남
```text
                                                                                   single-node-wazuh.indexer-1
[yhc@localhost single-node]$ docker logs single-node-wazuh.indexer-1 --tail 10 2>&1 | grep -i "error\|fatal\|cause"
	at org.opensearch.cli.Command.mainWithoutErrorHandling(Command.java:138)
For complete error details, refer to the log at /var/log/wazuh-indexer/opensearch.log
[yhc@localhost single-node]$ 

```

방법을 바꿔 Wazuh 공식 인증서 생성 스크립터를 먼저 실행함
```text
# 완전히 내리기
docker compose down -v

# 인증서 먼저 생성
docker compose -f generate-indexer-certs.yml run --rm generator

# 그 다음 실행
docker compose up -d
```

하지만
```text
71002859e21e   wazuh/wazuh-dashboard:4.9.0   "/entrypoint.sh"          About a minute ago   Restarting (1) 38 seconds ago                                                                                                                                                                         single-node-wazuh.dashboard-1
02ec18294d33   wazuh/wazuh-manager:4.9.0     "/init"                   About a minute ago   Up 38 seconds                   0.0.0.0:1514-1515->1514-1515/tcp, [::]:1514-1515->1514-1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp, 1516/tcp   single-node-wazuh.manager-1
bab1606b179c   wazuh/wazuh-indexer:4.9.0     "/entrypoint.sh open…"   About a minute ago   Restarting (1) 40 seconds ago                                                                                                                                                                         single-node-wazuh.indexer-1
```

실패

완전 다 지우고 다시 함
```text
# 전부 내리기
docker compose down -v

# wazuh-docker 폴더 전체 삭제
cd ~
rm -rf wazuh-docker

# 다시 clone
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node

# 인증서 먼저 생성
docker compose -f generate-indexer-certs.yml run --rm generator

# 실행
docker compose up -d
```
```text
[yhc@localhost single-node]$ docker ps
CONTAINER ID   IMAGE                         COMMAND                   CREATED          STATUS          PORTS                                                                                                                                                                 NAMES
f3d0840511cb   wazuh/wazuh-dashboard:4.9.0   "/entrypoint.sh"          52 seconds ago   Up 51 seconds   443/tcp, 0.0.0.0:443->5601/tcp, [::]:443->5601/tcp                                                                                                                    single-node-wazuh.dashboard-1
7b3a19593090   wazuh/wazuh-indexer:4.9.0     "/entrypoint.sh open…"   52 seconds ago   Up 52 seconds   0.0.0.0:9200->9200/tcp, [::]:9200->9200/tcp                                                                                                                           single-node-wazuh.indexer-1
d228ce1b65be   wazuh/wazuh-manager:4.9.0     "/init"                   52 seconds ago   Up 52 seconds   0.0.0.0:1514-1515->1514-1515/tcp, [::]:1514-1515->1514-1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp, 1516/tcp   single-node-wazuh.manager-1
[yhc@localhost single-node]$
```

성공~~
```text
https://localhost:443
```
