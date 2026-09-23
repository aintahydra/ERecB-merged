# Ubuntu 가상 머신용 tar.gz 설치·운영 안내서

이 문서는 ERecB Triage의 소스 배포본(`erecb_triage-<version>.tar.gz`)을 Ubuntu 가상
머신으로 옮겨 설치하고, 설정한 뒤 단발 실행 또는 감시 모드로 운영하는 방법을 설명한다.
ERecB Triage는 `in/`에 놓인 아카이브를 신뢰 경계 안에서 `middle-earth/`로 풀고,
IPIntel, FileIntel, GHIntel, YaraRuler 결과를 `output/`의 Markdown 보고서로 만든다.

## 1. 배포본 전송과 무결성 확인

배포를 만든 시스템에서 다음 파일을 가상 머신으로 전송한다.

```text
erecb_triage-<version>.tar.gz
SHA256SUMS
```

가상 머신에서 전송한 위치로 이동한 뒤 해시를 검증한다.

```bash
cd /tmp/erecb-transfer
sha256sum -c SHA256SUMS
```

검증 결과가 `OK`가 아니면 설치하지 말고 배포 파일을 다시 전송한다. wheel도 함께
전달받았다면 이 문서는 tar.gz 설치 절차를 기준으로 하되, Python 패키지 설치 단계만
wheel 파일 경로로 바꾸면 된다.

## 2. Ubuntu 준비

Python 3.10 이상과 가상환경 도구를 설치한다.

```bash
sudo apt update
sudo apt install -y python3 python3-venv
```

서비스 전용 계정과 운영 디렉터리를 만든다. 아래 예시는 `/opt`에는 프로그램과
가상환경을, `/var/lib`에는 변경되는 운영 데이터를 둔다.

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin erecb-triage
sudo install -d -o erecb-triage -g erecb-triage /opt/erecb-triage
sudo install -d -o erecb-triage -g erecb-triage /var/lib/erecb-triage/in
sudo install -d -o erecb-triage -g erecb-triage /var/lib/erecb-triage/middle-earth
sudo install -d -o erecb-triage -g erecb-triage /var/lib/erecb-triage/output
sudo install -d -o erecb-triage -g erecb-triage /var/lib/erecb-triage/data
sudo install -d -o erecb-triage -g erecb-triage /var/lib/erecb-triage/logs
sudo install -d -m 0750 /etc/erecb-triage
```

아카이브를 `in/`에 넣는 계정 또는 수집 시스템에는 `in/`에 파일을 생성할 권한만
부여한다. Triage 서비스에는 producer DB나 YARA 규칙 캐시에 쓰기 권한을 주지 않는다.

## 3. tar.gz에서 설치

배포본을 풀고 전용 가상환경에 설치한다.

```bash
cd /tmp/erecb-transfer
tar -xzf erecb_triage-<version>.tar.gz
cd erecb_triage-<version>
sudo python3 -m venv /opt/erecb-triage/.venv
sudo /opt/erecb-triage/.venv/bin/pip install .
sudo /opt/erecb-triage/.venv/bin/erecb-triage --help
```

모든 Intel 어댑터를 실행하려면 선택 의존성도 설치한다.

```bash
sudo /opt/erecb-triage/.venv/bin/pip install '.[fileintel,yara]'
```

FileIntel의 magic 기반 식별을 사용할 경우 Ubuntu 릴리스에 맞는 libmagic 런타임도
설치한다. 기본 `watcher_all.yaml`은 확장자 기반 보조 식별을 사용하므로 libmagic이
없어도 실행할 수 있지만, 보고서에는 해당 가용성 상태가 기록된다.

```bash
sudo apt install -y libmagic1
```

## 4. 운영 프로필 만들기

소스 배포본에 포함된 통합 프로필을 운영 위치로 복사한다.

```bash
sudo install -m 0640 config/watcher_all.yaml /etc/erecb-triage/watcher_all.yaml
sudo chown root:erecb-triage /etc/erecb-triage/watcher_all.yaml
```

`/etc/erecb-triage/watcher_all.yaml`을 열어 다음 상대 경로를 **절대 경로**로 바꾼다.
명령을 어느 현재 디렉터리에서 실행하더라도 동일하게 동작하도록 하기 위함이다.

```yaml
watch:
  path: "/var/lib/erecb-triage/in"

dispatcher:
  staging_index_path: "/var/lib/erecb-triage/data/staging.sqlite3"
  staging_root: "/var/lib/erecb-triage/middle-earth"
  output_root: "/var/lib/erecb-triage/output"

logging:
  file_path: "/var/lib/erecb-triage/logs/erecb-triage.log"
  max_bytes: 10485760
  backup_count: 10

processors:
  ip_retriever:
    db_path: "/srv/erecb-producers/dbs/ipintel.sqlite3"
    ip_singularity_threshold: 20
    max_observations_per_file: 1024
    max_observations_per_capture: 10000
  file_retriever:
    db_path: "/srv/erecb-producers/dbs/fileintel.sqlite3"
  ghintel:
    db_path: "/srv/erecb-producers/dbs/ghintel.sqlite3"
  yara_scan:
    cache_dir: "/srv/yararuler/cache"
```

`dbs/*.sqlite3`와 YARA cache는 ERecB Triage가 생성하거나 갱신하지 않는 별도
producer 애플리케이션의 산출물이다. 검증된 producer 산출물을 위 경로에 배치하고,
Triage 서비스 계정에는 읽기 권한만 준다. API 키나 토큰은 이 YAML, 보고서, 로그에
넣지 않는다. ERecB Triage 런타임 자체는 외부 API를 호출하지 않는다.

YARA를 사용하려면 별도 ERecB YaraRuler 애플리케이션을 clone/configure하여 실행하고,
컴파일된 cache를 생성해야 한다. 규칙 repository만 clone한 상태는 충분하지 않다.
YaraRuler가 만든 cache 디렉터리를 `yara_scan.cache_dir`에 지정한 뒤 `--check`로
`active`, `generations/<UUID>/manifest.json`, `rules.yac`를 확인한다. Triage 서비스는
그 디렉터리에 읽기 권한만 가져야 한다.

## 5. 대용량 아카이브 용량 계획

현재 프로필은 아카이브 최대 **100 GiB**, 압축 해제된 데이터 최대 **200 GiB**,
파일 최대 **200,000개**를 허용한다. 따라서 10–80 GB 아카이브가 약 150 GB와
20,000개 항목으로 풀리는 경우와 제공된 134,077개 항목 sample을 지원한다.

그러나 최종 `middle-earth/` 크기만 계산하면 부족하다. 입력은 `in/`에 유지되고,
처리 중에는 `middle-earth/.partial/`에 아카이브 사본을 만든 뒤 그곳에서 압축을
푼다. `in/`과 `middle-earth/`가 같은 파일시스템이면 최대 설정 기준으로 최소
**450 GiB의 여유 공간**을 확보하고, 보관할 기존 입력·스테이징·보고서 공간을
추가한다. 서로 다른 파일시스템이면 `in/`에는 아카이브 크기만큼,
`middle-earth/`에는 아카이브 사본과 압축 해제 결과를 합친 공간을 확보한다.

설정의 크기 제한을 무제한으로 바꾸지 않는다. 이 제한은 압축 폭탄과 디스크 고갈을
막는 안전 경계다.

## 6. 실행 전 점검

아래 명령은 읽기 전용 점검이다. 디렉터리 접근성, 설정, 선택한 processor 구성,
producer DB 스키마, YARA cache, 여유 공간을 확인하지만 입력을 처리하지 않는다.

```bash
sudo -u erecb-triage /opt/erecb-triage/.venv/bin/erecb-triage \
  --config /etc/erecb-triage/watcher_all.yaml --check
```

`fatal` 상태를 해결한 뒤 실행한다. producer DB 또는 cache가 없을 때의 `degraded`
상태는 스테이징과 독립 processor 실행을 막지 않을 수 있으나, 해당 보고서는
불완전한 상태를 기록하고 단발 실행은 오류 상태로 끝날 수 있다.

## 7. 단발 처리

처리할 아카이브를 `in/`의 직접 하위 경로에 복사한 뒤 `--once`를 실행한다.

```bash
sudo install -o erecb-triage -g erecb-triage -m 0600 \
  /path/to/capture.en_dec /var/lib/erecb-triage/in/capture.en_dec

sudo -u erecb-triage /opt/erecb-triage/.venv/bin/erecb-triage \
  --once --config /etc/erecb-triage/watcher_all.yaml
```

실행 중 다음과 같은 `INFO` 진행 로그가 표준 오류로 출력된다.

```text
INFO processor ready phase=analysis processor=ip_retriever type=ip_retriever
INFO target queued target='capture.en_dec'
INFO target start target='capture.en_dec'
INFO processor start target='capture.en_dec' phase=preprocessor processor=stage_input
INFO processor complete target='capture.en_dec' phase=preprocessor processor=stage_input elapsed_ms=... errors=0
INFO processor start target='capture.en_dec' phase=analysis processor=ip_retriever
```

대용량 입력에서는 `stage_input`이 해시 계산, 사본 생성, 안전성 검증, 압축 해제를
수행하는 동안 오래 실행될 수 있다. 완료 전에는 백분율 추정치를 제공하지 않으며,
`processor start` 로그가 현재 활성 processor를 나타낸다.

일반 실행의 모든 운영 로그는 터미널뿐 아니라 기본적으로 `logs/erecb-triage.log`에도
기록된다. 위 설정처럼 절대 경로를 지정하면 가상 머신에서는
`/var/lib/erecb-triage/logs/erecb-triage.log`에 저장된다. 로그는 10 MiB마다 회전하고
이전 파일 10개를 보관한다. `--check`는 읽기 전용이므로 로그 파일을 만들지 않는다.

지원되는 ZIP/TAR 아카이브는 사본·압축 해제 전에 파일 수, 압축 해제 예상 크기,
필요한 private staging 공간, 현재 사용 가능한 공간을 로그에 남긴다. 공간 또는
예상 제한이 부족하면 `outcome=rejected`와 이유를 기록하고, 사본 생성·압축 해제를
시작하지 않는다.

한 파일에서 유효한 서로 다른 IP가 20개를 초과하면 IPIntel은 이를 IP 목록
singularity로 취급한다. 21번째 IP에서 해당 파일의 읽기와 조회를 멈추며, 그 파일의
경로를 IPIntel 보고서와 최종 summary에 기록한다. 이 값은
`ip_singularity_threshold`로 조정할 수 있다. 이와 별도로 IPIntel은 보고서용 IP 증거를
기본적으로 파일당 1,024개, 캡처당 10,000개로 제한한다. singularity 임계값은 파일당
제한보다 클 수 없다. VM 메모리 예산을 확인하지 않은 상태에서 이 제한을 크게 올리지
않는다.

정상 처리 후에는 다음과 같은 파일이 생긴다.

```text
/var/lib/erecb-triage/middle-earth/<capture>-<timestamp>/
/var/lib/erecb-triage/output/capture.en_dec-ipintel.md
/var/lib/erecb-triage/output/capture.en_dec-fileintel.md
/var/lib/erecb-triage/output/capture.en_dec-ghintel.md
/var/lib/erecb-triage/output/capture.en_dec-yara.md
/var/lib/erecb-triage/output/capture.en_dec-summary.md
```

각 보고서는 탐지 결과와 처리 상태를 보여 주는 증거 문서이며, `match 없음`, DB 조회
실패, `degraded` 상태는 안전하거나 무해하다는 판정이 아니다.

## 8. 계속 감시하는 모드

계속 실행하려면 `--once` 없이 실행한다.

```bash
sudo -u erecb-triage /opt/erecb-triage/.venv/bin/erecb-triage \
  --config /etc/erecb-triage/watcher_all.yaml
```

운영 환경에서는 이 명령을 systemd 서비스로 실행하는 것을 권장한다. 서비스 계정은
`in/`, `middle-earth/`, `output/`, `data/`에 필요한 최소 권한만 가져야 한다.
producer DB, 규칙 source/cache, 자격 증명에는 쓰기 권한을 부여하지 않는다.

## 9. 재시작과 문제 해결

- 중단되면 같은 프로필로 다시 시작한다. dispatcher는 스테이징 manifest와
  `data/staging.sqlite3` 상태를 검증하여 완료된 캡처만 재사용한다.
- `archive size exceeds configured limit`이 보이면 실제로 사용 중인 YAML의
  `unarchive_all_supported.max_archive_size_bytes`가 `107374182400` 이상인지 확인한다.
- 다른 dispatcher가 실행 중일 때 staging lock 오류가 나면 해당 프로세스를 정상 종료한
  뒤 재시도한다. 잠금 파일이나 SQLite 상태를 임의로 삭제하지 않는다.
- producer DB 스키마 또는 YARA cache 오류는 해당 producer를 통해 복구한다. Triage가
  producer DB를 수정하도록 권한을 늘리지 않는다.
- 쉘에 `killed`만 표시되면 일반적인 Python 오류가 아니라 OS의 SIGKILL일 수 있다.
  Ubuntu에서는 `sudo journalctl -k -b | grep -Ei 'out of memory|killed process'`로 OOM
  killer 기록을 확인한다. VM 메모리 또는 swap을 늘리고, IPIntel 증거 제한은 유지한다.
- 완료된 `middle-earth/` 캡처는 입력 SHA-256 검증 후 재사용된다. 이후 processor만
  다시 실행할 때는 새 아카이브 사본·압축 해제 공간을 요구하지 않는다.
- 캡처, `middle-earth/`, `output/`, `data/staging.sqlite3`는 감사·재현에 필요한 기간
  동안 함께 보관한다. 삭제 전에는 dispatcher를 멈추고 복구 가능한 백업을 만든다.

## 10. 버전 갱신

새 tar.gz를 받으면 현재 가상환경에 설치된 버전과 설정 파일을 확인한 뒤, 서비스가
처리 중이 아닐 때 갱신한다. 배포본 안의 `config/watcher_all.yaml`과
`/etc/erecb-triage/watcher_all.yaml`을 비교해 새 제한값·processor 설정을 검토하고,
`--check`를 다시 실행한 후 운영을 재개한다.
