# ERecB-IPIntel 설치 및 사용 안내서

이 문서는 한국어 사용자를 위한 ERecB-IPIntel `0.1.1` 설치 및 실행 안내서입니다. ERecB-IPIntel은 파일에서 IPv4/IPv6 주소를 추출하고, CTX.IO에서 IP 정보를 조회한 뒤, 결과를 로컬 SQLite 데이터베이스에 누적합니다.

## 1. 준비 사항

- Python 3.11 이상
- `pip`
- IP 정보 조회 기능을 사용할 경우 CTX.IO API 키

기본 설치에는 별도의 서드파티 런타임 패키지가 필요하지 않습니다. YAML 설정 파일을 사용할 때만 PyYAML이 필요합니다. TOML 또는 JSON 설정 파일은 추가 패키지 없이 사용할 수 있습니다.

Python 버전을 확인합니다.

```bash
python3 --version
```

## 2. 설치

### 배포용 wheel에서 설치

`dist/erecb_ipintel-0.1.1-py3-none-any.whl` 파일을 사용할 컴퓨터로 복사한 뒤 다음 명령을 실행합니다.

Linux 또는 macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install erecb_ipintel-0.1.1-py3-none-any.whl
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install erecb_ipintel-0.1.1-py3-none-any.whl
```

YAML 설정 파일이 필요한 경우 다음 패키지도 설치합니다.

```bash
python3 -m pip install PyYAML
```

### 소스 코드에서 설치

저장소 최상위 디렉터리에서 실행합니다.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
```

개발 목적으로 소스 변경 내용을 즉시 반영하려면 편집 가능 모드로 설치합니다.

```bash
python3 -m pip install -e .
```

설치 결과를 확인합니다.

```bash
erecb-ipintel --help
```

## 3. 작업 디렉터리 준비

별도 설정이 없으면 명령을 실행한 현재 디렉터리를 기준으로 입력, 출력, 데이터베이스 경로를 결정합니다. 권장 구조는 다음과 같습니다.

```text
workdir/
  in/                    검사할 입력 디렉터리
  output/                추출된 IP 튜플 파일
  dbs/                   SQLite 데이터베이스
  ctx_io_api_key.txt     선택 사항: CTX.IO API 키
  config.toml            선택 사항: 실행 설정
```

작업 디렉터리에서 필요한 디렉터리와 데이터베이스를 만듭니다.

```bash
mkdir -p in output dbs
erecb-ipintel init-db
```

기본 데이터베이스 경로는 `dbs/ipintel.sqlite3`입니다.

## 4. CTX.IO API 키 설정

API 키는 다음 순서로 검색합니다.

1. 설정 파일의 `providers.ctx_io.api_key`
2. `CTX_IO_API_KEY` 환경 변수
3. 작업 디렉터리의 `ctx_io_api_key.txt`

환경 변수 사용 예:

```bash
export CTX_IO_API_KEY='YOUR_CTX_IO_API_KEY'
```

키 파일 사용 예:

```bash
printf 'YOUR_CTX_IO_API_KEY\n' > ctx_io_api_key.txt
chmod 600 ctx_io_api_key.txt
```

API 키를 Git에 커밋하거나 로그, 테스트 파일, 공유 데이터베이스에 포함하지 마십시오.

## 5. 설정 파일

전체 설정 예시는 저장소의 [`config.example.toml`](../config.example.toml)을 참고하십시오. 필요한 경우 이를 작업 디렉터리에 `config.toml`이라는 이름으로 복사하여 수정합니다.

기본 설정의 주요 경로는 다음과 같습니다.

```toml
[paths]
input_root = "in"
output_root = "output"
db_path = "dbs/ipintel.sqlite3"
```

특정 설정 파일을 직접 지정할 수도 있습니다.

```bash
erecb-ipintel --config /path/to/config.toml status
```

## 6. 디렉터리 수동 검사

지정한 디렉터리 아래의 일반 파일을 재귀적으로 검사합니다.

```bash
erecb-ipintel scan in/sample
```

진행률은 파일마다 출력하지 않고 대략 10% 단위로 표준 오류에 표시됩니다.

```text
scan directories: 40% (4/10)
```

검사가 끝나면 다음 형식의 파일이 `output/` 아래에 생성됩니다.

```text
output/ips_sample_YYMMDD-HHMMSS.txt
```

파일의 각 행은 다음 형식입니다.

```text
IP_ADDRESS; SOURCE_PATH
```

동일한 `(IP, 경로)` 튜플은 한 번만 기록됩니다. 같은 IP가 서로 다른 파일에서 발견되면 각 경로가 별도 튜플로 유지됩니다.

## 7. 자동 검색 및 감시

새 입력 디렉터리를 한 번 검색하고 처리합니다.

```bash
erecb-ipintel discover
```

기본 인식 깊이는 `1`입니다. 따라서 `in/a`, `in/b`와 같은 바로 아래 디렉터리를 각각 하나의 처리 단위로 인식합니다. 이미 처리한 디렉터리 정보는 SQLite 데이터베이스에 저장됩니다.

주기적으로 새 디렉터리를 확인하려면 다음 명령을 사용합니다.

```bash
erecb-ipintel watch
```

`watch`는 `discovery.watch_interval_seconds` 간격으로 검색을 반복합니다. 중지하려면 `Ctrl+C`를 누릅니다.

## 8. IP 정보 조회

검사 결과 파일을 CTX.IO로 조회합니다.

```bash
erecb-ipintel enrich output/ips_sample_YYMMDD-HHMMSS.txt
```

조회 전에 모든 튜플의 IP를 표준 형식으로 변환하고 중복을 제거합니다. 예를 들어 하나의 IP가 서로 다른 세 경로에서 발견되어 세 튜플이 있더라도 CTX.IO API는 해당 IP에 대해 한 번만 호출됩니다. 세 경로는 모두 데이터베이스의 관측 정보로 보존됩니다.

진행률은 고유 IP 수를 기준으로 대략 10% 단위로 표시됩니다.

```text
enrich ctx_io unique IPs: 70% (700/1000)
```

특정 공급자만 사용하려면 다음과 같이 지정합니다.

```bash
erecb-ipintel enrich output/ips_sample_YYMMDD-HHMMSS.txt --provider ctx_io
```

### 일일 API 한도가 있는 경우

예를 들어 처리할 고유 IP가 2,500개이고 이번 실행에서 사용할 수 있는 CTX.IO 호출 수가 1,000회라면 다음 명령을 사용합니다.

```bash
erecb-ipintel enrich output/ips_sample_YYMMDD-HHMMSS.txt --max-ips 1000 --consume
```

- `--max-ips 1000`: 활성화된 공급자마다 이번 실행에서 조회할 고유 IP를 최대 1,000개로 제한합니다.
- `--consume`: 정상 처리된 IP에 속한 모든 튜플을 입력 파일에서 제거합니다.
- 아직 선택되지 않은 IP, 실패한 IP, HTTP 429를 받은 IP는 입력 파일에 남습니다.
- 입력 파일은 임시 파일을 이용해 원자적으로 교체되므로 중간 상태의 파일이 남을 가능성을 줄입니다.
- 알 수 없는 형식의 행이나 주석은 그대로 보존됩니다.

첫 실행에서 고유 IP 1,000개가 정상 처리되면 해당 IP들의 모든 튜플이 제거되고, 나머지 고유 IP 1,500개에 해당하는 튜플만 남습니다. 공급자의 일일 한도가 초기화된 뒤 같은 명령을 다시 실행하면 이어서 처리할 수 있습니다.

`--consume`은 입력 파일을 변경하는 명시적 옵션입니다. 원본 추출 결과를 보관해야 한다면 먼저 파일을 복사하거나 `--consume` 없이 실행하십시오.

프로그램은 다른 도구나 사용자가 같은 API 키로 수행한 호출 수를 알 수 없으므로, `--max-ips` 값에는 이번 실행에서 실제로 사용할 수 있는 잔여 한도를 지정해야 합니다.

명령이 끝나면 다음 항목을 포함한 JSON 요약을 출력합니다.

- `tuples`: 입력에서 읽은 중복 제거 튜플 수
- `ips`: 전체 고유 IP 수
- `selected_ips`: 이번 실행에서 선택한 고유 IP 수
- `completed_ips`: 모든 선택 공급자에서 처리가 완료된 고유 IP 수
- `remaining_tuples`: 완료되지 않은 튜플 수
- `remaining_ips`: 완료되지 않은 고유 IP 수
- `rate_limited`: HTTP 429 발생 여부

## 9. 단일 IP 조회

공급자 연결이나 API 키를 간단히 확인할 때 사용할 수 있습니다.

```bash
erecb-ipintel enrich-ip 8.8.8.8 --provider ctx_io
```

## 10. 상태 확인

데이터베이스 경로, 저장된 IP 수, 자동 검색 상태, 최근 공급자 오류를 JSON으로 확인합니다.

```bash
erecb-ipintel status
```

## 11. 일반적인 작업 순서

수동 검사와 일일 1,000개 제한 조회 예:

```bash
erecb-ipintel scan /path/to/evidence
erecb-ipintel enrich output/ips_evidence_YYMMDD-HHMMSS.txt --max-ips 1000 --consume
erecb-ipintel status
```

다음 할당량 주기에 동일한 `enrich` 명령을 반복합니다. 입력 파일이 비어 있으면 처리할 튜플이 모두 완료된 것입니다.

자동 수집 예:

```bash
mkdir -p in/batch-001
cp /path/to/files/* in/batch-001/
erecb-ipintel discover
```

## 12. 데이터베이스 백업

누적 데이터는 기본적으로 `dbs/ipintel.sqlite3`에 저장됩니다. 복사하기 전에 실행 중인 `watch` 프로세스를 중지하십시오. SQLite WAL 보조 파일이 존재한다면 함께 복사하거나 SQLite 백업 기능을 사용해야 합니다.

API 키 파일, `dbs/`, `output/`은 일반적으로 버전 관리에 포함하지 않습니다.

## 13. 문제 해결

### `erecb-ipintel` 명령을 찾을 수 없음

가상 환경이 활성화되어 있는지 확인한 뒤 wheel 또는 소스 패키지를 다시 설치합니다.

```bash
. .venv/bin/activate
python3 -m pip install --upgrade erecb_ipintel-0.1.1-py3-none-any.whl
```

### `ModuleNotFoundError: erecb_ipintel`

현재 사용하는 Python 환경과 패키지를 설치한 환경이 서로 다릅니다. 올바른 가상 환경을 활성화한 뒤 다시 실행하십시오.

### `CredentialError: CTX.IO API key is not configured`

설정 파일, `CTX_IO_API_KEY` 환경 변수, 작업 디렉터리의 `ctx_io_api_key.txt` 중 어느 곳에서도 API 키를 찾지 못했습니다. 키 위치와 현재 작업 디렉터리를 확인하십시오.

### 검사 결과가 0개임

파일에 유효한 공인 IP 주소가 없거나, 발견된 주소가 더 큰 문자열 내부에 포함되어 있거나, 사설·예약·문서용 IPv4 제외 범위에 속하면 결과가 0개일 수 있습니다.

### HTTP 429가 발생함

공급자 호출 한도에 도달한 상태입니다. `--consume`을 사용했다면 완료되지 않은 IP 튜플은 입력 파일에 남아 있습니다. 공급자의 한도가 초기화된 뒤 같은 명령을 다시 실행하십시오.
