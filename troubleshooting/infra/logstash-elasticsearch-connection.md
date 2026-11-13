# Logstash → Elasticsearch 연결 실패

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 생략했습니다.

### 오류 : 포트 충돌
```bash
[yhc@localhost elk]$ docker ps -a
CONTAINER ID   IMAGE                                                  COMMAND                   CREATED         STATUS                     PORTS                                                                                                                                                                 NAMES
8e9f105d98bd   docker.elastic.co/kibana/kibana:8.12.0                 "/bin/tini -- /usr/l…"   7 minutes ago   Up 5 minutes               0.0.0.0:5601->5601/tcp, [::]:5601->5601/tcp                                                                                                                           kibana
6db7e5705db1   docker.elastic.co/logstash/logstash:8.12.0             "/usr/local/bin/dock…"   7 minutes ago   Up 5 minutes               0.0.0.0:5044->5044/tcp, [::]:5044->5044/tcp, 9600/tcp                                                                                                                 logstash
a15d6da3df31   docker.elastic.co/elasticsearch/elasticsearch:8.12.0   "/bin/tini -- /usr/l…"   7 minutes ago   Exited (1) 5 minutes ago                                                                                                                                                                         elasticsearch
f3d0840511cb   wazuh/wazuh-dashboard:4.9.0                            "/entrypoint.sh"          3 days ago      Up 12 minutes              443/tcp, 0.0.0.0:443->5601/tcp, [::]:443->5601/tcp                                                                                                                    single-node-wazuh.dashboard-1
7b3a19593090   wazuh/wazuh-indexer:4.9.0                              "/entrypoint.sh open…"   3 days ago      Up 12 minutes              0.0.0.0:9200->9200/tcp, [::]:9200->9200/tcp                                                                                                                           single-node-wazuh.indexer-1
d228ce1b65be   wazuh/wazuh-manager:4.9.0                              "/init"                   3 days ago      Up 12 minutes              0.0.0.0:1514-1515->1514-1515/tcp, [::]:1514-1515->1514-1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp, 1516/tcp   single-node-wazuh.manager-1
```

elasticsearch → Exited (1) ❌   Elasticsearch가 죽어았음.

docker-compose.yml 확인
```bash
cat ~/elk/docker-compose.yml | grep 9200
```

"9201:9200"  으로 설정

## [Troubleshooting] Logstash → Elasticsearch 연결 실패

상황: kali가 공격을 하고 있지만 데이터가 없음.

Wazuh → Logstash → Elasticsearch 연동 실패!!

Logstash 로그 확인
```bash
docker logs logstash --tail 20
```
```bash
tp://localhost:9201/][Manticore::SocketException] Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused"}
[2026-04-10T02:12:01,183][INFO ][logstash.outputs.elasticsearch][main] Failed to perform request {:message=>"Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused", :exception=>Manticore::SocketException, :cause=>#<Java::OrgApacheHttpConn::HttpHostConnectException: Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused>}
[2026-04-10T02:12:01,183][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error {:url=>"http://localhost:9201/", :exception=>LogStash::Outputs::ElasticSearch::HttpClient::Pool::HostUnreachableError, :message=>"Elasticsearch Unreachable: [http://localhost:9201/][Manticore::SocketException] Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused"}
[2026-04-10T02:12:06,188][INFO ][logstash.outputs.elasticsearch][main] Failed to perform request {:message=>"Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused", :exception=>Manticore::SocketException, :cause=>#<Java::OrgApacheHttpConn::HttpHostConnectException: Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused>}
[2026-04-10T02:12:06,189][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error {:url=>"http://localhost:9201/", :exception=>LogStash::Outputs::ElasticSearch::HttpClient::Pool::HostUnreachableError, :message=>"Elasticsearch Unreachable: [http://localhost:9201/][Manticore::SocketException] Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused"}
[2026-04-10T02:12:11,195][INFO ][logstash.outputs.elasticsearch][main] Failed to perform request {:message=>"Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused", :exception=>Manticore::SocketException, :cause=>#<Java::OrgApacheHttpConn::HttpHostConnectException: Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused>}
[2026-04-10T02:12:11,196][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error {:url=>"http://localhost:9201/", :exception=>LogStash::Outputs::ElasticSearch::HttpClient::Pool::HostUnreachableError, :message=>"Elasticsearch Unreachable: [http://localhost:9201/][Manticore::SocketException] Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused"}
[2026-04-10T02:12:16,201][INFO ][logstash.outputs.elasticsearch][main] Failed to perform request {:message=>"Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused", :exception=>Manticore::SocketException, :cause=>#<Java::OrgApacheHttpConn::HttpHostConnectException: Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused>}
[2026-04-10T02:12:16,202][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error {:url=>"http://localhost:9201/", :exception=>LogStash::Outputs::ElasticSearch::HttpClient::Pool::HostUnreachableError, :message=>"Elasticsearch Unreachable: [http://localhost:9201/][Manticore::SocketException] Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused"}
[2026-04-10T02:12:21,206][INFO ][logstash.outputs.elasticsearch][main] Failed to perform request {:message=>"Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused", :exception=>Manticore::SocketException, :cause=>#<Java::OrgApacheHttpConn::HttpHostConnectException: Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused>}
[2026-04-10T02:12:21,206][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error {:url=>"http://localhost:9201/", :exception=>LogStash::Outputs::ElasticSearch::HttpClient::Pool::HostUnreachableError, :message=>"Elasticsearch Unreachable: [http://localhost:9201/][Manticore::SocketException] Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused"}
[2026-04-10T02:12:26,211][INFO ][logstash.outputs.elasticsearch][main] Failed to perform request {:message=>"Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused", :exception=>Manticore::SocketException, :cause=>#<Java::OrgApacheHttpConn::HttpHostConnectException: Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused>}
[2026-04-10T02:12:26,211][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error {:url=>"http://localhost:9201/", :exception=>LogStash::Outputs::ElasticSearch::HttpClient::Pool::HostUnreachableError, :message=>"Elasticsearch Unreachable: [http://localhost:9201/][Manticore::SocketException] Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused"}
[2026-04-10T02:12:31,217][INFO ][logstash.outputs.elasticsearch][main] Failed to perform request {:message=>"Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused", :exception=>Manticore::SocketException, :cause=>#<Java::OrgApacheHttpConn::HttpHostConnectException: Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused>}
[2026-04-10T02:12:31,217][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error {:url=>"http://localhost:9201/", :exception=>LogStash::Outputs::ElasticSearch::HttpClient::Pool::HostUnreachableError, :message=>"Elasticsearch Unreachable: [http://localhost:9201/][Manticore::SocketException] Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused"}
[2026-04-10T02:12:36,221][INFO ][logstash.outputs.elasticsearch][main] Failed to perform request {:message=>"Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused", :exception=>Manticore::SocketException, :cause=>#<Java::OrgApacheHttpConn::HttpHostConnectException: Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused>}
[2026-04-10T02:12:36,221][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error {:url=>"http://localhost:9201/", :exception=>LogStash::Outputs::ElasticSearch::HttpClient::Pool::HostUnreachableError, :message=>"Elasticsearch Unreachable: [http://localhost:9201/][Manticore::SocketException] Connect to localhost:9201 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused"}
[yhc@localhost elk]$ 
```

### 오류

Connect to localhost:9201 failed: Connection refused

### 원인

컨테이너 안에서 localhost는 자기 자신을 가리킴

Elasticsearch는 다른 컨테이너에 있어서 연결 불가
```bash
컨테이너 안에서 localhost
→ 컨테이너 자기 자신을 가리킴
→ Elasticsearch는 다른 컨테이너에 있음
→ 연결 실패
```

### 해결

hosts를 localhost:9201 → elasticsearch:9200 으로 변경
```bash
cat > ~/elk/logstash.conf << 'EOF'
input {
  beats {
    port => 5044
  }
}

filter {
  if [agent][type] == "filebeat" {
    json {
      source => "message"
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "wazuh-alerts-%{+YYYY.MM.dd}"
  }
}
EOF
```

### 배운 것

Docker 컨테이너끼리 통신할 때

localhost 대신 컨테이너 이름으로 접속해야 함

하지만 여전히 데이터가 없음

로그 다시 확인
```bash
docker logs logstash --tail 20
```
```bash
                                                                                                 0.0s[yhc@localhost elk]$ docker logs logstash --tail 20
[2026-04-10T02:15:44,419][ERROR][logstash.monitoring.internalpipelinesource] Failed to fetch X-Pack information from Elasticsearch. This is likely due to failure to reach a live Elasticsearch cluster.
[2026-04-10T02:15:44,512][INFO ][logstash.agent           ] Successfully started Logstash API endpoint {:port=>9600, :ssl_enabled=>false}
[2026-04-10T02:15:44,717][INFO ][org.reflections.Reflections] Reflections took 69 ms to scan 1 urls, producing 132 keys and 468 values
[2026-04-10T02:15:44,971][INFO ][logstash.javapipeline    ] Pipeline `main` is configured with `pipeline.ecs_compatibility: v8` setting. All plugins in this pipeline will default to `ecs_compatibility => v8` unless explicitly configured otherwise.
[2026-04-10T02:15:44,995][INFO ][logstash.outputs.elasticsearch][main] New Elasticsearch output {:class=>"LogStash::Outputs::ElasticSearch", :hosts=>["http://elasticsearch:9200"]}
[2026-04-10T02:15:45,007][INFO ][logstash.outputs.elasticsearch][main] Elasticsearch pool URLs updated {:changes=>{:removed=>[], :added=>[http://elasticsearch:9200/]}}
[2026-04-10T02:15:45,180][WARN ][logstash.outputs.elasticsearch][main] Restored connection to ES instance {:url=>"http://elasticsearch:9200/"}
[2026-04-10T02:15:45,185][INFO ][logstash.outputs.elasticsearch][main] Elasticsearch version determined (8.12.0) {:es_version=>8}
[2026-04-10T02:15:45,185][WARN ][logstash.outputs.elasticsearch][main] Detected a 6.x and above cluster: the `type` event field won't be used to determine the document _type {:es_version=>8}
[2026-04-10T02:15:45,190][ERROR][logstash.outputs.elasticsearch][main] Could not connect to a compatible version of Elasticsearch {:url=>"http://elasticsearch:9200/"}
[2026-04-10T02:15:45,201][INFO ][logstash.outputs.elasticsearch][main] Not eligible for data streams because config contains one or more settings that are not compatible with data streams: {"index"=>"wazuh-alerts-%{+YYYY.MM.dd}"}
[2026-04-10T02:15:45,201][INFO ][logstash.outputs.elasticsearch][main] Data streams auto configuration (`data_stream => auto` or unset) resolved to `false`
[2026-04-10T02:15:45,207][INFO ][logstash.filters.json    ][main] ECS compatibility is enabled but `target` option was not specified. This may cause fields to be set at the top-level of the event where they are likely to clash with the Elastic Common Schema. It is recommended to set the `target` option to avoid potential schema conflicts (if your data is ECS compliant or non-conflicting, feel free to ignore this message)
[2026-04-10T02:15:45,228][INFO ][logstash.javapipeline    ][main] Starting pipeline {:pipeline_id=>"main", "pipeline.workers"=>4, "pipeline.batch.size"=>125, "pipeline.batch.delay"=>50, "pipeline.max_inflight"=>500, "pipeline.sources"=>["/usr/share/logstash/pipeline/logstash.conf"], :thread=>"#<Thread:0x7985e45f /usr/share/logstash/logstash-core/lib/logstash/java_pipeline.rb:134 run>"}
[2026-04-10T02:15:45,753][INFO ][logstash.javapipeline    ][main] Pipeline Java execution initialization time {"seconds"=>0.52}
[2026-04-10T02:15:45,761][INFO ][logstash.inputs.beats    ][main] Starting input listener {:address=>"0.0.0.0:5044"}
[2026-04-10T02:15:45,774][INFO ][logstash.javapipeline    ][main] Pipeline started {"pipeline.id"=>"main"}
[2026-04-10T02:15:45,798][INFO ][logstash.agent           ] Pipelines running {:count=>1, :running_pipelines=>[:main], :non_running_pipelines=>[]}
[2026-04-10T02:15:45,850][INFO ][org.logstash.beats.Server][main][2e780f46ed32abece5c1265c7b7143d50d063f05825826473fdecb0effbc650b] Starting server on port: 5044
[2026-04-10T02:15:50,223][WARN ][logstash.outputs.elasticsearch][main] Restored connection to ES instance {:url=>"http://elasticsearch:9200/"}
```

Logstash 연결 성공
```bash
Restored connection to ES instance ✅
Pipeline started ✅
Starting server on port: 5044 ✅
```

Wazuh에서 Logstash로 로그 전송 설정
```bash
sudo dnf install -y filebeat
```

Filebeat 설정
```bash
sudo vi /etc/filebeat/filebeat.yml
```

내용 바꾸
```bash
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/ossec/logs/alerts/alerts.json
  json.keys_under_root: true
  json.add_error_key: true

output.logstash:
  hosts: ["localhost:5044"]
```
```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat
```

Filebeat 실행 성공
```bash
Active: active (running) ✅
```

하지만 공격 로그는 없다.

Wazuh alerts 파일 확인
```bash
sudo ls -la /var/ossec/logs/alerts/
sudo tail -5 /var/ossec/logs/alerts/alerts.json
```

Wazuh가 Docker 컨테이너 안에 있어서 Rocky Linux 호스트에 alerts.json 파일이 없음

### 해결 방법

컨테이너 안의 alerts 파일 경로 확인
```bash
sudo docker exec -it single-node-wazuh.manager-1 ls /var/ossec/logs/alerts/
```

### 문제

Filebeat가 호스트의 파일을 보고 있는데 실제 파일은 컨테이너 안에있음.

Wazuh docker-compose.yml을 수정해야 해서 복잡

### 해결 방법

docker-compose.yml에서 Wazuh Manager 볼륨을 호스트에 마운트

### 더 쉬운 방법

Filebeat를 컨테이너 안에 설치하는 대신 Wazuh Manager에서 직접 Logstash로 전송
```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```
```bash
cat /var/ossec/logs/alerts/alerts.json | tail -5
```

alerts.json 데이터 확인-SSH 브루트포스 로그

Wazuh Manager 볼륨을 호스트에 마운트
```bash
sudo docker cp single-node-wazuh.manager-1:/var/ossec/logs/alerts/alerts.json /tmp/alerts.jsonㄲ
```

Filebeat 설정 바꾸기
```bash
sudo vi /etc/filebeat/filebeat.yml
```
```bash
paths:
  - /tmp/alerts.json
```

으로 바꾸기
```bash
sudo systemctl restart filebeat
```

하지만 여전히 로그데이터가 확인이 안됨

Filebeat 로그 확인
```bash
sudo filebeat -e -c /etc/filebeat/filebeat.yml 2>&1 | tail -20
```
```bash
[yhc@localhost elk]$ sudo docker cp single-node-wazuh.manager-1:/var/ossec/logs/alerts/alerts.json /tmp/alerts.json
Successfully copied 12.8MB (transferred 12.8MB) to /tmp/alerts.json
[yhc@localhost elk]$ sudo vi /etc/filebeat/filebeat.yml
[yhc@localhost elk]$ sudo systemctl restart filebeat
[yhc@localhost elk]$ sudo tail -20 /var/log/filebeat/filebeat
tail: cannot open '/var/log/filebeat/filebeat' for reading: 그런 파일이나 디렉터리가 없습니다
[yhc@localhost elk]$ sudo filebeat -e -c /etc/filebeat/filebeat.yml 2>&1 | tail -20
rbx    0x7ffb8d409640
rcx    0x7ffbb6a8d02c
rdx    0x6
rdi    0x629d
rsi    0x62a3
rbp    0x62a3
rsp    0x7ffb8d4087b0
r8     0x7ffb8d408880
r9     0x7ffbb6bb1d20
r10    0x8
r11    0x246
r12    0x6
r13    0x0
r14    0x2cf0118
r15    0x0
rip    0x7ffbb6a8d02c
rflags 0x246
cs     0x33
fs     0x0
gs     0x0
```

Filebeat 크래시 확인

## [Troubleshooting] Filebeat 크래시

### 오류

Filebeat 실행 시 메모리 덤프 발생

### 원인

Rocky Linux 9와 Filebeat 버전 호환성 문제

### 해결
```bash
curl로 직접 Elasticsearch에 데이터 삽입
head -1 /tmp/alerts.json | curl -X POST "http://localhost:9201/wazuh-alerts/_doc" \
-H "Content-Type: application/json" \
-d @-
```

### 배운 것

Filebeat 크래시 시 curl bulk API로 대체 가능

## [Troubleshooting] Wazuh alerts.json 경로 문제

### 오류

/var/ossec/logs/alerts/ 경로 없음

### 원인

Wazuh가 Docker 컨테이너 안에서 실행되어

호스트에서 직접 파일 접근 불가

### 해결

docker cp single-node-wazuh.manager-1:/var/ossec/logs/alerts/alerts.json /tmp/alerts.json

### 배운 것

컨테이너 안의 파일은 docker cp로 호스트로 복사
