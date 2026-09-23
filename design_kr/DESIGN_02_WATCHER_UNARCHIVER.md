# 설계 02: 감시자, 디스패처 및 압축 해제기

> 수정 기준: 2026-09-20. 이 문서는 모든 분석 어댑터가 의존하는 신뢰 경계를 정의합니다. 전달 상태와 검증 증거는 오직 [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)에서만 추적됩니다; 프로세서 문서의 과거 단계 기록은 실행 가능한 테스트를 대체하지 않습니다.
> 자세한 배포 작업은 [`IMPLEMENTATION_02_TRUSTED_INGESTION_DISPATCHER.md`](IMPLEMENTATION_02_TRUSTED_INGESTION_DISPATCHER.md)에 있습니다.

## 1. 범위

이 문서는 `DESIGN_01_SKELETON.md`의 첫 번째 구현 슬라이스를 정제하고 이후 분석 프로세서가 사용하는 스테이징 동작을 정의합니다.

구현 내용은 다음과 같습니다:

- 새로 드롭된 압축 파일을 모니터링하는 디렉터리 감시자, `in/`에 대한 예외적 지원으로 드롭된 디렉터리 또는 비압축 파일.
- 정규화된 파일 시스템 이벤트를 수신하고 구성된 프로세서를 실행하는 디스패처.
- 첫 번째 구현이 동기식으로 큐를 처리하더라도 감시자와 디스패처 간의 enqueuing 경계.
- `middle-earth/`에 지정된 압축 파일을 추출하는 unarchiver 프로세서.
- 디스패처가 소유한 스테이징 단계는 수락된 모든 입력에 대해 `middle-earth/` 아래에 작업 디렉터리를 보장합니다.

`DESIGN_03_PROCESSOR_IPINTEL.md` 부터 `DESIGN_06_PROCESSOR_YARARULER.md`까지는 이 기반 위에서 `middle-earth/`에 있는 스테이징된 디렉터리에서 독립적인 분석 프로세서를 실행합니다.

## 2. 첫 번째 구현 동작

기본 로컬 워크플로우(스케줄링 시작 시각은 `2026-09-07T12:34:56Z`):

```text
copy testdata/2023-08-13_09-02-04.zip.en_dec in/
  -> middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/<extracted contents>

copy testdata/212.212.212.212_8080.enc in/
  -> middle-earth/212.212.212.212_8080-260907-123456/<extracted contents>

copy testdata/213.213.213.213_99.zip in/
  -> middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt

copy testdata/214.214.214.214.tar.gz in/
  -> middle-earth/214.214.214.214.tar.gz-260907-123456/<extracted contents>
```

예외적 스테이징 워크플로우:

```text
copy testdata/case-directory in/
  -> middle-earth/case-directory/<copied contents>

copy testdata/single-log.txt in/
  -> middle-earth/single-log.txt/single-log.txt
```

규칙:

- `in/`는 감시되는 입력 디렉터리입니다.
- `middle-earth/`는 추출 결과 루트입니다.
- `in/`에 직접 드롭된 압축 파일은 정상 캡처 입력입니다.
- `.en_dec`, `.enc`, `.zip`, 그리고 `.tar.gz`는 활성화된 프로덕션 압축 포맷입니다. 다른 tar 및 압축 스트림 별칭은 컨테이너, 크기 제한, 원자 공개, 적대적 시나리오 테스트가 완료될 때까지 비활성화됩니다.
- `.en_dec`은 기본 캡처 접미사이며 `.en_dec`과 `.enc`는 일반 ZIP 콘텐츠로 검증 및 추출됩니다. 암호 해독 요청이 없습니다.
- `in/`에 직접 드롭된 디렉터리는 예외적인 비압축 캡처입니다. `middle-earth/`로 복사되고, 필요 시 중첩된 매칭 압축을 검색할 수 있습니다.
- 직접 드롭된 비압축 파일은 개발 또는 분석가 주도 사례를 위한 예외 입력이며, 활성화되면 동일한 이름의 스테이징 디렉터리로 복사됩니다.
- 각 직접 압축 파일은 `middle-earth/` 아래에 타임스탬프가 붙은 래퍼 디렉터리를 가집니다. 존재하면 최종 `.en_dec` 또는 `.enc`만 제거하고, `.zip`과 `.tar.gz`는 보존합니다. UTC 스케줄링 시작 시각의 `-YYMMDD-HHMMSS`를 부착합니다.
- 래퍼 내부의 원본 압축 멤버 경로(최상위 `IP:PORT` 디렉터리 포함)를 보존합니다. 평평화하거나 래퍼 이름으로 사용하지 않습니다.
- 중복을 해결하기 전에 이름을 정합니다; 충돌하는 고유 식별자는 타임스탬프 뒤에 카운터(`-2`, `-3`, …)를 붙입니다(섹션 5.1 및 6.3 참조).
- 드롭된 디렉터리 안에 압축이 있으면, `middle-earth/` 아래에서 상대 경로 소스를 보존해 충돌을 방지합니다.
- Unarchiver는 추출된 내용을 실행하거나 가져오거나 마운트하거나 신뢰해서는 안 됩니다.

## 3. 구성

`config/watcher_unarchiver.yaml`에 집중 구성 파일 추가:

```yaml
watch:
  path: "./in"
  recursive: false
  event_debounce_ms: 500
  stable_check:
    enabled: true
    interval_ms: 250
    unchanged_checks: 3

dispatcher:
  max_workers: 1
  duplicate_policy: "skip_if_output_exists"
  staging_index_path: "./data/staging.sqlite3"
  staging_root: "./middle-earth"
  output_root: "./output"

pipelines:
  on_added:
    preprocessors:
      processors:
        - "stage_input"
    analysis:
      processors: []

processors:
  stage_input:
    type: "input_stager"
    output_root: "./middle-earth"
    unarchiver: "unarchive_all_supported"
    copy_directories: true
    copy_files: true
    archive_output_naming:
      strip_final_suffixes: [".en_dec", ".enc"]
      timestamp_format: "%y%m%d-%H%M%S"
      timezone: "UTC"
      collision_policy: "append_counter"

  unarchive_all_supported:
    type: "archive_unarchiver"
    output_root: "./middle-earth"
    max_depth_from_event_root: 2
    filename_regex: ".*\\.(en_dec|enc|zip|tar\\.gz)$"
    supported_formats:
      - ".en_dec"
      - ".enc"
      - ".zip"
      - ".tar.gz"
    max_archive_size_bytes: 107374182400
    max_total_extracted_bytes_per_archive: 214748364800
    max_extracted_files_per_archive: 200000
    overwrite: false
```

주요 참고 사항:

- 모든 상대 경로는 하나의 애플리케이션 기반 디렉터리를 기준으로 해결되며, 이를 디스패처에 전달합니다. 현재 CLI는 시작 시 작업 디렉터리를 기본값으로 정의하므로 프로덕션 실행은 프로젝트 루트에서 시작됩니다. 프로세서 내부 또는 캡처된 콘텐츠에 대해 독립적으로 경로를 해석하지 마십시오.
- `watch.recursive: false`는 `in/`의 직계 자식 추가만 상위 이벤트를 생성합니다. 예외적인 디렉터리일 경우, 프로세서는 재귀적으로 탐색할 수 있습니다.
- `max_depth_from_event_root`는 추가된 디렉터리 아래에서 unarchiver가 검색하는 깊이를 제한합니다. 이는 유효한 압축 안의 경로 깊이를 제한하지 않습니다.
- `filename_regex`는 정규 표현식이며, 쉘 glob이 아닙니다.
- `duplicate_policy: skip_if_output_exists`는 아카이브에 대한 영구 스테이징 인덱스를 사용합니다. 원본 입력 상대 경로와 SHA‑256을 일치시켜 새 이름을 생성하기 전에 매칭합니다. 완료된, 사용 가능한 추출만 재사용합니다(원래 타임스탬프 포함).
- `dispatcher.staging_index_path`는 이 도구가 소유하며, 다른 도구가 만든 `dbs/`와 별개입니다.
- `archive_output_naming`은 `strip_archive_suffix_for_output`를 대체합니다. 재귀적 접미사 제거는 없습니다. `.zip.en_dec` 파일 이름은 `.zip-YYMMDD-HHMMSS` 형태이며, `-YYMMDD-HHMMSS`나 `.zip.en_dec-YYMMDD-HHMMSS`가 아닙니다.
- `.en_dec`와 `.enc`는 ZIP 검증 및 추출을 선택합니다. 암호 해독은 요청하지 않습니다.
- `input_stager`는 디스패처 전처리기로, 직접 압축 파일을 unarchiver에 전달하고 예외적인 비압축 파일/디렉터리를 `middle-earth/`로 복사합니다.
- `pipelines.on_added.analysis`는 빈 배열이며, 이는 DESIGN 03‑06에서 사용되는 확장 포인트입니다. 표준 조합 순서는 `ip_retriever`, `file_retriever`, `ghintel`, 이후 `yara_scan`이며, 모두 동일한 신뢰 스테이징 캡처를 소비하고 무관한 기록은 무시합니다.
- 현재 체크인된 `config/watcher_unarchiver.yaml`은 unarchiver 전용 호환 프로필이며, `archive_unarchiver`를 직접 사용합니다. 통합 파이프라인이 배포되기 전에 이 문서의 `input_stager` 프로필과 조정해야 합니다.

## 4. 런타임 구성 요소

### 4.1 감시자

책임:

- 설정을 로드.
- `in/` 존재 여부 확인.
- `in/`에 직접 추가된 자식만 감시.
- 원시 파일 시스템 알림을 `WatchEvent` 객체로 변환.
- 추가된 압축 파일, 파일 또는 디렉터리가 안정적으로 나타날 때까지 대기 후 디스패처에 전달.
- 감시 대상 외부에서 생성된 파일 무시.

#### `WatchEvent`

```text
WatchEvent
  id: unique event id
  kind: added
  root_path: absolute path to ./in
  path: absolute path to added file or directory
  relative_path: path relative to ./in
  source_name: original input basename, including all suffixes
  is_directory: boolean
  observed_at: UTC timestamp
```

#### 안정성 검사

- 파일은 크기와 수정 시간이 `unchanged_checks`만큼 변하지 않으면 안정.
- 예외 디렉터리는 재귀적 파일 수, 총 크기 및 최신 수정 시간이 `unchanged_checks`동안 변하지 않으면 안정.
- 경로가 안정화 전에 사라지면 이벤트를 버리고 기록.

#### 구현 라이브러리

- 첫 번째 구현은 테스트가 OS별 알림 동작에 의존하지 않도록 polling watcher 사용.
- 작은 인터페이스 뒤에 감시자를 두어 향후 `watchdog` 구현을 추가할 수 있도록 함.

### 4.2 디스패처

책임:

- `dispatcher.enqueue(event)`를 통해 감시자에서 `WatchEvent` 객체를 수신.
- `pipelines.on_added.preprocessors` 및 `pipelines.on_added.analysis`에 정의된 프로세서를 선택.
- `ProcessingContext` 생성.
- 전처리기를 순서대로 실행한 뒤, 분석 프로세서를 순서대로 실행.
- 모든 수락된 입력을 `middle-earth/`에 스테이징 한 후 분석 프로세서가 실행되도록 함.
- 부분 출력이나 원본 실패 압축은 분석하지 않고 오류를 기록.
- 하나의 나쁜 이벤트가 감시자 과정을 종료시키지 않음. 전처리 실패 시만 디스패처 중단; 분석 예외는 이후 독립적인 분석 어댑터에 영향을 주지 않음.
- 감시자는 콘텐츠 무관: 스테이징, 압축 해제, IP 스캔, 실행 파일 스캔, 인텔리전스 DB 조회 결정은 모두 디스패처가 선택한 프로세서가 담당.

#### `ProcessingContext`

```text
ProcessingContext
  event: WatchEvent
  config: resolved config
  output_root: absolute path to ./middle-earth
  analysis_output_root: absolute path to ./output
  base_dir: absolute configuration base directory
  staging_state: dispatcher-owned StagingState used by InputStager
  report_specs: configured processor names mapped to (output directory, hyphenated suffix)
  report_path(capture, processor_name): validate source/report identity and return reserved path
  run_id: unique run id
  logger: logger
```

#### 첫 번째 버전 실행 모델

- 기본적으로 워커 한 개 사용.
- 이벤트를 순차적으로 처리.
- 테스트용으로 결정적 실행 유지.
- 감시자와 디스패처 사이에 큐 경계 도입, 향후 워커 수 증가 시 프로세서 계약 변경 없이 동작 가능하도록 함.
- 전처리기는 한 번 실행되고, 분석 프로세서는 설정된 순서대로 이전 기록 집합을 그대로 사용.

#### 대상 수명 주기

- `enqueue(event)`는 큐에 넣지만 처리하지 않음.
- `drain()`은 순서대로 큐를 처리하고 `ProcessorResults` 반환.
- `dispatch(event)`는 동기 호출자에게 제공.
- 디스패처를 컨텍스트 매니저로 사용하거나 `close()`를 호출해 대기 중인 작업을 모두 처리하고 스테이징 루트 락과 SQLite 연결 해제.
- CLI는 두 모드(`--once`와 지속 모드)에서 큐를 사용. 한 번 실행 모드는 draining 후 오류 발생 시 비정상 종료(0 이외). 지속 모드는 불안정 소스를 재스케줄링.

#### 의사코드

```text
watcher observes new direct child under ./in
  -> watcher waits for path stability
  -> watcher creates WatchEvent
  -> dispatcher.enqueue(event)
  -> dispatcher creates ProcessingContext
  -> dispatcher resolves stage_input
  -> stage_input extracts archive or copies exceptional non-archive inputs into middle-earth/
  -> dispatcher passes staged_capture records to analysis processors in configured order
  -> dispatcher logs records and errors
```

### 4.3 프로세서 인터페이스

이 슬라이스는 작은 동기식 프로세서 계약을 사용합니다.

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

@dataclass(frozen=True)
class ProcessorError:
    path: Path
    message: str
    code: str

@dataclass(frozen=True)
class ProcessorResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[ProcessorError] = field(default_factory=list)
    metrics: dict[str, int] = field(default_factory=dict)

class Processor(ABC):
    name: str

    @abstractmethod
    def process(
        self,
        input_records: list[dict[str, Any]],
        context: ProcessingContext,
    ) -> ProcessorResult:
        ...
```

Unarchiver는 source/preprocessor이므로 초기 구현에서는 `input_records`를 무시합니다.

## 5. 입력 스테이저 프로세서

목적:

- `in/`에 안정적으로 추가된 모든 직접 압축 파일을 `middle-earth/` 아래 하나의 스테이징 캡처 디렉터리로 변환.
- 감시자에서 라우팅 결정을 제외.
- downstream 분석 프로세서에게 `staged_capture` 레코드를 발행.

동작:

- `event.path`에 지원되는 압축 접미사가 있고, 구성된 정규식과 일치하면 압축 검증 및 추출로 라우트. 유효하지 않거나 암호화된 압축은 오류를 발생시키며, 복사 시 비압축으로 대체되지 않습니다(`copy_files`가 true라도).
- `event.path`가 디렉터리라면 예외적인 비압축 캡처로 간주하고 재귀적으로 `middle-earth/<sanitized-directory-name>/`에 복사.
- `event.path`가 비압축 파일이라면 예외적인 직접 파일 캡처로 간주하고 `middle-earth/<sanitized-file-basename>/`를 만들고 그 안에 파일을 복사.
- 압축 파일의 경우, 동일한 아카이브 정체성을 해결하고, 인덱스에 따라 이름을 보유하거나 재사용. 완성된 유효 출력만 새 타임스탬프와 함께 반환. 이미 존재하는 디렉터리는 중복이 아니다.
- 예외적 디렉터리/파일 입력은 같은 이름 스테이징 동작: 오버라이트 비활성 시 기존 사용 가능한 스테이징 디렉터리를 재사용. 다른 소스 또는 인덱스 아카이브가 점유한 이름을 거부.
- 스테이저 한 번에 예외적 스테이징 이름을 정규화(섹션 6.3의 파일명 규칙 사용). 별도로 `report_stem`을 원본 직접 자식 베이스네임으로 설정해 canonical 보고서 생성을 위한 정확한 값 제공.
- 복사 시 symlink를 따라가지 않음 (향후 구성에서 명시적으로 허용되지 않는 한).

스테이징 캡처 레코드:

```json
{
  "type": "staged_capture",
  "capture_name": "2023-08-13_09-02-04.zip-260907-123456",
  "report_stem": "2023-08-13_09-02-04.zip.en_dec",
  "source_name": "2023-08-13_09-02-04.zip.en_dec",
  "source_path": "/abs/path/in/2023-08-13_09-02-04.zip.en_dec",
  "source_sha256": "<64 lowercase hex characters>",
  "staging_started_at": "2026-09-07T12:34:56Z",
  "staged_path": "/abs/path/middle-earth/2023-08-13_09-02-04.zip-260907-123456",
  "staging_method": "archive_extracted",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

## 5.1 아카이브 정체성 및 영구 스테이징 할당

`dispatcher.staging_index_path`에 로컬 SQLite 인덱스를 사용합니다. 각 인덱스는 하나의 해석된 감시 루트와 스테이징 루트를 바인딩하며, 시작 시 두 루트가 저장된 메타데이터와 일치하지 않으면 실패합니다. 이 운영 상태는 인텔리전스 DB 스키마에 포함되지 않습니다.

동일 인덱스는 아카이브 정체성별 고유 `staged_path` 소유권과 표준 `report_path` 소유권을 저장합니다 (`source_relative_path + processor`). 보고서 경로는 정확한 직접 자식 베이스네임인 `report_stem`에 따라 지정되며, 후행 하이픈 접미어가 붙습니다. 예외 디렉터리/파일 소유권도 기록해 두고 복사 또는 보고 전에 충돌을 방지합니다.

각 아카이브 항목은 다음과 저장:

- `source_relative_path`: 감시 루트에 상대적인 원본 경로, 모든 접미사를 포함.
- `source_sha256`: 전체 압축 바이트의 SHA‑256(제한된 읽기로 계산).
- `capture_name`, `staged_path`, `staging_started_at`: 예약 출력 할당.
- `status`: `pending`, `ready`, 또는 `failed` + 추출 마니페스트 및 오류 세부사항.

신뢰 마니페스트는 각 추출된 상대 경로, 항목 유형, 파일 크기 및 내용 SHA‑256을 기록합니다. 수집 외부에 보관해 복구 시 게시 디렉터리를 검증할 수 있도록 합니다. 소스 해시와 마니페스트 해시는 제한된 읽기로 수행됩니다.

`(source_relative_path, source_sha256)`, `capture_name`, 및 `staged_path`의 고유성을 강제합니다. 이벤트 ID, 수정 시간, 파일명 타임스탬프는 아카이브 정체성이 아닙니다. 동일한 바이트를 같은 입력 경로에서 재복사하면 한 항목을 재사용; 변경된 바이트 또는 다른 경로에서는 새 항목 생성.

할당 및 복구:

1. 안정화 후, 압축을 해시하고 선택된 포맷을 검증합니다. 추출 중 소스가 변하면 스태징 아래에 오래된 다이제스트를 사용하지 않습니다. 불안정한 소스를 재스케줄링합니다.
2. `skip_if_output_exists` 및 `overwrite: false`와 함께, `ready` 항목이 있으면 저장된 스테이징 레코드를 반환합니다. 이름과 스태징 시작 시간을 보존하고 현재 이벤트/런 ID를 호출 출처로 기록합니다. 분석은 동일 캡처에 대해 다시 실행할 수 있습니다.
3. 새 정체성의 경우, 검증 및 해시 후 UTC를 한 번 샘플링해 스테이징 작업을 예약하고 타임스탬프와 이름(섹션 6.3)을 하나의 트랜잭션에서 저장합니다. 고유하게 스테이징 이름 보장. 보고서 경로는 스태지 명명 충돌 선택에 참여하지 않음.
4. `middle-earth/.partial/` 아래 개인 임시 디렉터리에서 추출. 검증된 추출 마니페스트를 저장하고 같은 파일 시스템에서 원자적으로 리네임해 완전한 디렉터리를 게시, 이후 항목을 `ready` 로 표시합니다. 완료 후에만 스테이징 레코드를 발행합니다. 캡처 파일은 스테이징 인덱스에 기록할 수 없습니다.
5. 실패 시, 미완성 출력이나 포기된 대기 중인 시도는 동일 저장 할당과 타임스탬프를 재시도합니다. 게시 직전 끊긴 경우만, 저장된 마니페스트와 비교해 복구 후 `ready` 로 표시합니다. 소유권 또는 완전성을 확립할 수 없으면 복구 오류를 기록하고 미지의 출력을 채택하거나 덮어쓰지 않습니다.
6. 스테이징 소유권을 프로세스 락으로 직렬화합니다. 두 번째 프로세스는 다른 인덱스를 복구하지 않고 시작에 실패해야 합니다.

인덱스 항목은 캡처 또는 보고가 유지되는 한 보존됩니다. 사용 불가능하거나 손상된 인덱스는 스테이징 오류이며, 새 이름을 생성할 이유가 아닙니다. 타임스탬프 디렉터리 이름으로부터 아카이브 정체성을 추측해서 재구성하지 마십시오.

## 6. Unarchiver 프로세서

### 6.1 대상 탐지

프로세서는 하나의 `WatchEvent`를 수신합니다.

- `event.path`가 파일인 경우:
  - 파일이 구성된 압축 확장자를 갖는지 확인.
  - `basename`이 `filename_regex`와 일치하는지 확인.
  - 내용이 선택된 압축 타입과 일치하는지 검증.
  - 모든 검사 통과 시 추출.

- `event.path`가 디렉터리인 경우:
  - 재귀적으로 탐색.
  - 각 파일에 대해 `event.path` 기준 깊이를 계산.
  - 지원되는 형식, regex 및 깊이 한계와 일치하는 파일을 추출.

깊이 예시:

```text
in/case/archive.zip                 depth 0
in/case/level1/archive.zip          depth 1
in/case/level1/level2/archive.zip   depth 2
```

### 6.2 압축 타입 감지

파일명만 신뢰하기보다 내용 기반 감지를 우선합니다:

- `.zip`: `zipfile.is_zipfile`로 검증.
- `.en_dec`, `.enc`: `zipfile.is_zipfile` 로 검증하고 ZIP 콘텐츠처럼 정확히 추출. `.zip.en_dec` 파일은 `.en_dec` ZIP 별칭을 선택하며 암호화 단계는 포함되지 않음.
- `.tar.gz`: tar 컨텐츠로 검증 후 gzip 압축으로 열기.
- 파일명 확장자는 후보를 빠르게 선택하는 데만 사용.
- 확장자와 내용이 일치하지 않을 경우 추출 없이 오류 레코드를 발생시킴. ZIP 별칭의 손상 또는 암호화된 항목은 비압축 캡처로 복사되지 않음. 동일한 안전 및 크기 제한을 적용.

포맷 정책:

- 체크인된 unarchiver 프로필은 위 네 개 생산 포맷만 활성화합니다. 추가 포맷은 호스트 시나리오 테스트가 승인되고 설정에 포함될 때까지 비활성 상태로 유지됩니다.
- `.xz` 및 `.7z` 같은 형식은 지원되지 않음. 형식을 추가하려면 후보 선택, 내용 검증, 안전 추출, 한계 및 테스트를 모두 확장해야 함.

### 6.3 출력 레이아웃

각 새 직접 압축 정체성에 대해:

```text
middle-earth/<archive-label>-<YYMMDD-HHMMSS>[-<counter>]/<archive-contents>
```

이름은 스테이저가 소유하며 모든 압축 항목에서 공유됩니다:

- 원본 파일명으로 시작. `strip_final_suffixes`(기본: `.en_dec`, `.enc`)에 최대 하나만 제거. 나머지 `.zip`는 그대로 보존. 일반 `.zip` 및 `.tar.gz` 파일은 전체 확장자를 유지.
- 래퍼 라벨만 정규화: ASCII 알파벳, 숫자, `.`, `_`, `-`를 제외한 문자는 `_`로 교체. 빈 레이블, `.` 또는 `..`는 `capture`로 대체. 최종 파일명을 파일 시스템 길이 제한과 검증하고 너무 길면 명명 오류 발생. 이 래퍼 규칙으로 압축 멤버를 평평화하거나 정규화하지 않음.
- 내부 임시 출력은 `middle-earth/.partial/`에 저장. 예외 입력의 정규화 스테이징 이름이 `.partial`인 경우는 분석 캡처가 되지 않도록 거부.
- UTC `staging_started_at`를 `%y%m%d-%H%M%S` 형식으로 부착. 이는 처리 시간이며, 소스 파일의 날짜, 수정 시간 또는 보고 생성 시간을 포함하지 않음.
- 첫 시도는 카운터 없이 이름을 사용하고, 이미 예약된 다른 정체성이나 대상이 존재하면 `-2`, `-3` 등을 순차적으로 시도.
- 트랜잭션으로 첫 번째 사용 가능한 이름을 보유. 이는 라벨 정규화 충돌과 시계 뒤로 이동에 대응.

`capture_name`은 최종 예약 디렉터리 베이스네임(카운터 포함)이며, downstream 프로세서에서 스테이징 출처를 추적하는 데 사용됩니다. `report_stem`은 원본 직접 자식 베이스네임을 그대로 유지하며, 보고 파일명을 생성할 때 사용합니다.

예시 (스케줄링 시작 시각 `2026-09-07T12:34:56Z`):

| 입력 파일명 | 할당된 디렉터리 베이스네임 |
| --- | --- |
| `2023-08-13_09-02-04.zip.en_dec` | `2023-08-13_09-02-04.zip-260907-123456` |
| `sample.en_dec` | `sample-260907-123456` |
| `sample.enc` | `sample-260907-123456-2` (전의 이름이 예약된 경우) |
| `sample.zip` | `sample.zip-260907-123456` |
| `sample.tar.gz` | `sample.tar.gz-260907-123456` |

스테이징 디렉터리와 보고 파일명은 의도적으로 다릅니다:

| 입력 압축 | 스테이징 디렉터리 | 정식 보고서 |
| --- | --- | --- |
| `sample.zip.en_dec` | `sample.zip-260907-123456/` | `sample.zip.en_dec-ipintel.md`, `sample.zip.en_dec-fileintel.md`, `sample.zip.en_dec-ghintel.md`, `sample.zip.en_dec-yara.md` |

보고서 접미어를 추가해 파일 시스템 이름 제한을 초과하면 명명 오류를 발생시키며, 트렁크하거나 해시하지 않음(운영자 가시성 계약 위반).

기본 배치:

```text
in/2023-08-13_09-02-04.zip.en_dec
middle-earth/2023-08-13_09-02-04.zip-260907-123456/
  185.17.40.153:85/
    <archive-contents>
```

Linux에서 상대 `IP:PORT` 멤버 디렉터리는 콜론을 그대로 유지합니다. 섹션 6.4의 모든 경로 검증이 적용됩니다. 이 멤버 디렉터리 자체는 별도 캡처가 아닙니다.

압축 파일이 예외 드롭된 디렉터리 안에 있는 경우, 상대 소스 상위 폴더를 보존하고 동일한 명명 및 정체성 규칙을 적용:

```text
in/case/subdir/toolkit.zip
middle-earth/case/subdir/toolkit.zip-260907-123456/<archive-contents>
```

출력은 부모 스테이징 캡처 내에 남으며, 그 부모의 기록 세트로 스캔됩니다. 중첩 추출은 기본적으로 추가 분석 캡처/보고를 생성하지 않습니다.

복제 및 덮어쓰기 동작:

- 인덱스에서 복제(섹션 5.1)로 해결; 새 이름을 만들고 존재 여부를 확인함.
- `overwrite: false`인 경우 동일 정체성의 완전한 추출만 재사용하고 `skipped_existing_output` 발행.
- 새로운 이름이 충돌하면 항상 카운터 할당; 기존 캡처는 건너뛰지 않음.
- `overwrite: true`가 명시적으로 구성된 경우, 같은 정체성을 저장된 경로와 타임스탬프에 재추출. 출력 교체 전 소유권 및 포함 여부를 검증하고 완전하게 검증된 대체만 게시. 다른 정체성은 영향받지 않음.
- 디렉터리 존재(부분 추출 포함)만으로는 완료 증명을 제공하지 못함.

현재 소스는 `overwrite: false`로 인덱싱 스테이징을 지원합니다; 수락 여부는 테스트가 완료될 때까지 검증되지 않습니다. `overwrite: true`는 향후 확장이며, 원자적 교체/복구가 구현되기 전에는 시작 시 거부됩니다.

### 6.4 안전 추출

모든 캡처된 콘텐츠는 적대적입니다. unarchiver는 다음 검사를 수행하고, 그 결과를 저장소에 쓰기 전에 실행:

- 대상 경로를 계산해 지정한 압축 출력 디렉터리 내부에 머무르는지 확인.
- 절대 경로 거부.
- `..` 트래버설 거부.
- tar 아카이브에서 symlink 및 hard link 거부.
- 장치 파일, FIFO 등 특수 파일 거부.
- 디렉터리는 제어된 권한으로 생성.
- 정규 파일만 기록.
- 파일 수와 총 추출 바이트 한계 적용.
- 절대로 실행 가능한 파일을 쓰지 않음.

Zip 파일:

- `ZipInfo` 엔트리 순회.
- 정상 경로가 출력 디렉터리를 벗어나는 엔트리 거부.
- symlink처럼 보이는 항목은 외부 속성 기반으로 거부.

Tar 파일:

- `TarInfo` 엔트리 순회.
- 디렉터리와 정규 파일만 허용.
- 시뮬링크, 하드링크, 기기, FIFO 등 특수 타입 거부.
- 대상 경로를 추출 전에 검증.
- `tar.extractall` 대신 하나씩 유효성 검사 후 추출.

단일 파일 bzip/gzip 내용:

- 청크 단위 스트림 압축 해제.
- 쓰는 동안 총 추출 바이트 한계 적용.
- 하나의 `extracted_artifact` 레코드를 생성.
- 정확한 접미사가 있을 때만 활성화(`supported_formats`에 포함).

### 6.5 기록

성공적 추출 기록:

```json
{
  "type": "archive_extracted",
  "archive_path": "/abs/path/in/212.212.212.212.tar.gz",
  "output_dir": "/abs/path/middle-earth/212.212.212.212.tar.gz-260907-123456",
  "archive_format": ".tar.gz",
  "files_extracted": 1,
  "bytes_extracted": 12345,
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

추출 아티팩트 기록:

```json
{
  "type": "extracted_artifact",
  "archive_path": "/abs/path/in/213.213.213.213_99.zip",
  "path": "/abs/path/middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt",
  "relative_path": "a/b/c/iplist.txt",
  "size_bytes": 67,
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

오류 기록:

```json
{
  "type": "archive_error",
  "archive_path": "/abs/path/in/bad.zip",
  "code": "path_traversal",
  "message": "archive member escapes output directory",
  "source_event_id": "evt-..."
}
```

## 7. 테스트 계획

### 7.1 단위 테스트

Watcher:

- `in/`에 새 직계 파일 추가 시 `added` 이벤트 생성.
- `in/`에 새 직계 디렉터리 추가 시 `added` 이벤트 생성.
- 중첩 자식 이벤트를 감시하지 않을 때 무시.
- 안정화 전에 경로가 사라지면 이벤트 버림.

Dispatcher:

- 구성된 전처리기를 순서대로 실행.
- 전처리 후 분석 프로세서를 실행.
- 전처리기에서 발행한 `staged_capture` 레코드를 분석 프로세서에 전달.
- 분석 프로세서 간에 누적 기록 집합을 전달.
- 유효한 `ProcessingContext`를 프로세서에 제공.
- 프로세서 오류를 로깅하고 중지하지 않음.
- 구성 또는 디스패치 시 알 수 없는 프로세서 이름은 빠르게 실패.

Input Stager:

- `.en_dec`, `.enc`, `.zip`, `.tar.gz` 콘텐츠를 unarchiver로 라우트.
- 예외 드롭된 디렉터리 `middle-earth/`에 복사.
- 비압축 파일을 동일한 이름의 스테이징 디렉터리에 복사.
- 각 수락된 입력마다 하나의 `staged_capture` 레코드 발행.
- `overwrite: false`일 때 완료된 인덱스 아카이브를 재사용; 예외 디렉터리/파일 동작 유지.
- 기본적으로 symlink 따라가지 않음.

Unarchiver:

- `testdata/212.212.212.212.tar.gz`를
  `middle-earth/212.212.212.212.tar.gz-260907-123456/malicious/malware.exe`에 추출.
- `testdata/213.213.213.213_99.zip`을
  `middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt`에 추출.
- `.en_dec`와 `.enc`를 ZIP 콘텐츠로 처리, `.zip.en_dec` 파일 포함.
- 기본 설정에서 `.en_dec`, `.enc`, `.zip`, `.tar.gz` 후보 지원.
- `overwrite: false`일 때 동일 정체성의 준비된 항목은 건너뛴다.
- 경로 트래버설 압축 거부.
- tar symlink 및 hardlink 멤버 거부.
- 파일 수와 바이트 한계 적용.
- `filename_regex` 준수.
- 드롭된 디렉터리 안의 압축에 대해 `max_depth_from_event_root` 준수.

Archive identity and naming:

- UTC 시계를 `2026-09-07T12:34:56Z`로 주입해 `.zip.en_dec` 피처를
  `middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/`에 추출.
- 최종 `.en_dec` 또는 `.enc`만 제거하고, 일반 `.zip`, `.tar.gz`는 보존.
- 손상, 암호화, 경로 트래버설 `.en_dec` 압축은 복사하지 않고 오류를 반환.
- 동일 바이트를 같은 입력 경로에서 재복사하면 동일 이름과 타임스탬프 재사용(프로세스 재시작 후에도).
- 다른 경로에 동일 바이트는 새로운 정체성 생성; 같은 바이트가 다른 경로에서 변경 시 새 캡처.
- 같은 초 내 충돌이 있으면 카운터 부착. 보고서 경로 충돌은 별도 처리: 동일 소스 상대 경로는 슬롯을 새로 고침, 미소유경로나 다른 논리적 소유자는 거부.
- 실패 시 재시도; 중단된 게시 이전 완전성 검증 후 `ready` 상태 표시. 저장 인덱스가 없거나 두 번째 프로세스가 같은 스테이징 루트를 점유하면 시작에 실패.

### 7.2 통합 테스트

설정:

```text
in/
middle-earth/
testdata/
  2023-08-13_09-02-04.zip.en_dec
  212.212.212.212.tar.gz
  213.213.213.213_99.zip
```

UTC 시계를 `2026-09-07T12:34:56Z`로 고정해 테스트의 결정성 확보. 실제 CLI 실행은 실제 UTC 스케줄 시작 시간을 사용.

테스트 단계:

```bash
cp testdata/2023-08-13_09-02-04.zip.en_dec in/
cp testdata/212.212.212.212.tar.gz in/
cp testdata/213.213.213.213_99.zip in/
python -m erecb_triage --once --config config/watcher_unarchiver.yaml
```

예상 파일:

```text
middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/<fixture files>
middle-earth/212.212.212.212.tar.gz-260907-123456/malicious/malware.exe
middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt
```

통합 테스트는 합성 `WatchEvent` 객체를 사용해 디스패처를 직접 호출하거나, 파일 시스템 알림 타이밍이 불안정한 경우 별도 스모크 테스트로 폴링 감시자를 실행합니다.

## 8. 구현 레이아웃

```text
config/
  watcher_unarchiver.yaml
src/
  erecb_triage/
    __init__.py
    __main__.py
    config.py
    dispatcher.py
    events.py
    watcher.py
    processors/
      __init__.py
      archive_unarchiver.py
      base.py
      input_stager.py
      ip_retriever.py
      file_retriever.py
tests/
  test_dispatcher.py
  test_unarchiver.py
  test_watcher.py
  test_watcher_unarchiver_integration.py
```

## 9. 구성 요소 작업 분해

이 시퀀스는 컴포넌트별이며, 현재 완료 상태를 나타내지 않음. 권위 있는 상태, 종속성 및 릴리스 게이트는 `IMPLEMENTATION_PLAN.md`에 있습니다.

1. `WatchEvent`, `ProcessingContext`, `ProcessorResult`, `ProcessorError` 데이터 클래스를 추가.
2. YAML 설정 로더와 검증기를 추가.
3. `archive_unarchiver`를 프로세서 레지스트리에 매핑.
4. `input_stager`를 추가하고 프로세서 레지스트리 업데이트.
5. 동기식 전처리 및 분석 실행을 갖춘 디스패처 구현.
6. 안전한 압축 후보 탐색 구현.
7. ZIP, `.en_dec`, `.enc` 안전 추출 구현.
8. tar‑gzip 안전 추출 구현.
9. 영구 스테이징 정체성, UTC 이름 예약, 충돌 카운터 및 복구 구현.
10. 안정성 검사와 함께 폴링 감시자 구현.
11. 디스패처, 감시자, 입력 스테이저, Unarchiver에 대한 단위 테스트 추가.
12. `testdata/`의 예제 압축을 사용한 통합 테스트 추가.
13. 명령행 진입점 추가:

```bash
python -m erecb_triage --config config/watcher_unarchiver.yaml
python -m erecb_triage --once --config config/watcher_unarchiver.yaml
```

## 10. 초기 수락 기준

- 감시자가 `in/`를 모니터링.
- 한 번 실행 모드가 `in/`의 기존 직계 자식을 스캔.
- `testdata/212.212.212.212.tar.gz`를 `in/`에 복사하면:

```text
middle-earth/212.212.212.212.tar.gz-260907-123456/malicious/malware.exe
```

- `testdata/213.213.213.213_99.zip`을 `in/`에 복사하면:

```text
middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt
```

- `.en_dec` 또는 `.enc` 파일이 ZIP 데이터를 포함하면 암호 해독 없이 일반 ZIP처럼 추출.
- 예시 UTC 스케줄 시각에서 `2023-08-13_09-02-04.zip.en_dec`는
  `middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/`를 생성.
- 직접 비압축 파일과 디렉터리는 `middle-earth/`에 스테이징.
- 디스패처는 이후 단계에서 분석 프로세서를 실행, 예컨대 `ip_retriever`, `file_retriever` 등.
- `.en_dec`, `.enc`, `.zip`, `.tar.gz` 파일은 기본 설정에서 지원되는 압축 후보로 인식.
- 동일 아카이브 바이트를 같은 입력 경로에 재복사하면 재시작 후에도 완성된 인덱스 출력과 타임스탬프가 재사용됨(`overwrite: false` 시).
- 내용이 변경되면 별도 캡처 생성; 같은 초 충돌은 카운터 추가.
- 스테이징 레코드는 고유 `capture_name`(스테이징 출처)과 원본 아카이브 `report_stem`을 모두 포함.
- 모든 프로세서가 활성화되면 `sample.zip.en_dec`는 정확히
  `sample.zip.en_dec-ipintel.md`, `sample.zip.en_dec-fileintel.md`,
  `sample.zip.en_dec-ghintel.md`, `sample.zip.en_dec-yara.md`를
  `output/`에 생성.
- 동일 파일명으로 성공적인 교체 시 보고서는 원자적으로 새로 갱신; 실패 시 이전 성공한 보고는 유지되고 별도 오류 기록을 남김.
- 불완전하거나 실패한 출력은 복제된 것으로 간주되지 않음.
- 악의적 압축 경로가 `middle-earth/` 외부에 쓸 수 없도록 보장.
- 감시자는 부정이나 지원되지 않는 압축에도 계속 실행.
