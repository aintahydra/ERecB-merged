# 우분투 배포 및 설치 가이드

## 릴리스 아티팩트

`dist/` 디렉터리에는 다음 항목이 포함됩니다:

```text
erecb_triage-<version>-py3-none-any.whl  # 설치 가능한 휠
erecb_triage-<version>.tar.gz            # 소스 배포본 및 YAML 프로파일
SHA256SUMS                               # 전송 검증 파일
```

설치 전에 아티팩트를 검증하십시오:

```bash
cd /path/to/dist
sha256sum -c SHA256SUMS
```

## 기본 설치

우분투에서 Python 3.10 이상을 사용하는 경우:

```bash
sudo apt update
sudo apt install -y python3-venv
python3 -m venv /opt/erecb-triage/.venv
. /opt/erecb-triage/.venv/bin/activate
python -m pip install /path/to/erecb_triage-<version>-py3-none-any.whl
erecb-triage --help
```

`erecb-triage --once`를 `--config` 없이 실행하면 기본 내장 스테이징/해제 디폴트를 사용합니다.
YAML 프로파일을 명시적으로 지정하려면 소스 배포본을 풀고 필요한 `config/*.yaml` 파일을 운영자 소유의 구성 디렉터리로 복사하십시오:

```bash
tar -xzf erecb_triage-<version>.tar.gz
install -D -m 0640 erecb_triage-<version>/config/watcher_all.yaml /etc/erecb-triage/watcher_all.yaml
```

복사된 프로필에서 경로를 조정하세요; 비밀은 절대 저장하지 마십시오.

## 선택적 어댑터 의존성

활성화된 프로세서에 대해선 선택적으로 Python extras만 설치하십시오:

```bash
python -m pip install 'erecb-triage[fileintel,yara]'
```

FileIntel 매직 분류를 위해서는 배포 이미지에 맞는 우분투 `libmagic` 런타임/개발 패키지를 설치합니다 (일반적으로 `libmagic1`; 패키지 이름은 릴리스마다 다를 수 있음). YARA의 경우 호환되는 `yara-python` 휠을 사용하거나 libyara가 포함된 빌드 환경을 활용하십시오. 설치 후 선택한 프로파일을 검증합니다:

```bash
erecb-triage --config /etc/erecb-triage/watcher_all.yaml --check
```

## 운영자 소유 배포 입력

릴리스 아티팩트는 캡처, 보고서, 스테이징 상태, 생산자 데이터베이스, YARA 캐시 및 자격 증명을 제외합니다. 별도로 제공하고 최소 권한을 부여하십시오:

```text
/var/lib/erecb-triage/in/                 쓰기 가능 (드롭 메커니즘에 의해)
/var/lib/erecb-triage/middle-earth/       쓰기 가능 (triage 서비스에 의해)
/var/lib/erecb-triage/output/             쓰기 가능 (triage 서비스에 의해)
/var/lib/erecb-triage/data/               쓰기 가능 (triage 서비스에 의해)
/srv/erecb-producers/dbs/*.sqlite3        읽기 전용, triage 서비스에서 수정 불가
/srv/yararuler/cache/                     읽기 전용, triage 서비스에서 수정 불가
```

권한 없는 서비스 계정을 사용하십시오. triage 서비스는 생산자 데이터베이스, 규칙 캐시/소스 또는 자격 증명에 대한 쓰기 권한을 갖지 않아야 합니다. 복구 및 보존 지침은 `../docs/OPERATOR_RUNBOOK.md`를 참조하십시오.

## 소스에서 릴리스 빌드

검토된 소스 체크아웃에서 빌드 도구가 이미 설치된 상태라면:

```bash
python -m pip wheel --no-deps --no-build-isolation . --wheel-dir dist
python -c "from setuptools.build_meta import build_sdist; print(build_sdist('dist'))"
cd dist
sha256sum erecb_triage-*.whl erecb_triage-*.tar.gz > SHA256SUMS
```

검증 스위트 실행 후 클린 휠 설치/가져오기/CLI 스모크 테스트를 수행한 뒤 배포하십시오. `.env`, 토큰 파일, 생산자 DB, 캐시, 캡처, 보고서 또는 생성된 임시 상태를 공개하지 마십시오.
