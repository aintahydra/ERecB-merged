# DESIGN 01: 사이버 보안 트리아지 파이프라인 아키텍처

> Revision baseline: 2026-09-20. 이 문서는 시스템 수준 계약입니다. 컴포넌트 세부 사항은 DESIGN 02‑06에 있으며, 인도 순서/상태는 [`IMPLEMENTATION_PLAN.md`](../design/IMPLEMENTATION_PLAN.md) 에 있습니다. [`providers/`](../providers/) 아래의 생산자 설계 문서가 생산자 소유 데이터베이스와 YARA 캐시 포맷의 기준입니다. 저장소 구성은 [`REPOSITORY_LAYOUT.md`](../design/REPOSITORY_LAYOUT.md)를 참조하세요. 프로듀서 스키마가 변경되면, 그 소비자 어댑터는 `incompatible` 로 실패해야 합니다; 이 파이프라인은 프로듀서 소유 상태를 절대로 마이그레이션해서는 안 됩니다.

### 용어 및 호환성

제품 전용 프로세서 이름은 **IPIntel**, **FileIntel**, **GHIntel** 그리고 **YaraRuler** 입니다. 기존 소스에서는 `IPRetriever`, `FileRetriever`, 그리고 `YaraScan` 이라는 호환성 명칭을 사용하고 있으며, 설정 타입은 `ip_retriever`, `file_retriever`, 그리고 계획 중인 `yara_scan` 입니다. 이는 어댑터 이름이지 별도 제품이 아닙니다. 신규 문서와 사용자-facing 출력은 제품 전용 이름을 사용해야 합니다; 공개 구성 키를 재명명하는 작업은 기존 프로파일이 유효하도록 보류합니다.

| 제품 기능 | 파이프라인 어댑터 | 생산자 소유 입력 | 캡처 분석 중 네트워크 |
|---|---|---|---|
| IPIntel | `IPRetriever` / `ip_retriever` | `dbs/ipintel.sqlite3` | 없음 |
| FileIntel | `FileRetriever` / `file_retriever` | `dbs/fileintel.sqlite3` | 없음 |
| GHIntel | `GHIntel` / `ghintel` | `dbs/ghintel.sqlite3` | 없음 |
| YaraRuler | `YaraScan` / `yara_scan` | 검증된 활성 YARA 캐시 생성 | 없음 |

YARA 규칙은 파일 내용과 일치하며, 미리 계산된 해시는 아닙니다. 일치하는 파일에 대해 SHA‑256 및 MD5가 계산되어 정확한 바이트를 식별합니다.

## 1. 목표

설정된 입력 디렉터리를 감시하고 캡처 아카이브 또는 예외적으로 캡처 디렉터리/파일이 추가될 때 구성 가능한 처리 파이프라인을 시작하는 디렉터리 워처를 구축합니다.

필수 아카이브 작업 흐름은 엄격히 순서대로 진행됩니다:

```text
stable new archive in in/
  -> 중간 단계에서 고유 디렉터리에 완전하고 안전하게 압축 해제
  -> 해당 해제된 디렉터리에서 각 구성된 프로세서를 실행
  -> Markdown 보고서를 output/ 에 원자적으로 게시
```

아카이브 분석 프로세서는 `in/` 로부터 직접 아카이브를 읽거나 스테이징 준비 전에 실행되지 않습니다.

시스템은 다음을 지원해야 합니다:

- 기본값이 `./in/` 인 감시 디렉터리를 정의하는 구성 파일.
- 주로 `.en_dec` ZIP 데이터가 포함된 `.en_dec` 파일을 비롯해 `.enc`, `.zip`, `.tar.gz` 를 포함한 새 캡처 아카이브 파일의 추가 탐지.
- `./in/` 아래 예외적으로 추가되는 압축 해제되지 않은 캡처 디렉터리 지원.
- 독립적인 처리 단계용 프로세서 인터페이스.
- 파이프라인을 실행하는 디스패처.
- 모든 수락된 입력을 `./middle-earth/` 아래 작업 디렉터리로 변환하는 디스패처 소유 스테이징 경계.
- 결과를 내보내고 다음 프로세서에 증강 레코드를 전달할 수 있는 프로세서.
- 초기 프로세서 패밀리는 다음과 같습니다:
  - 추가된 캡처에서 제어된 아카이브 추출.
  - 새 콘텐츠에서 IP 주소 추출.
  - `dbs/ipintel.sqlite3` 로부터 현지 IP 인텔리전스 검색.
  - 실행 파일 탐색 및 `dbs/fileintel.sqlite3` 로부터 로컬 파일 인텔리전스 검색.
  - GitHub 저장소 주소 발견 및 `dbs/ghintel.sqlite3` 로부터 현지 프로젝트 카드 검색.
  - 독립 YaraRuler 애플리케이션에서 생성한 검증된 캐시를 사용한 YARA 매칭.

예상 추가 아카이브 예:

```text
in/2023-08-13_09-02-04.zip.en_dec
  -> middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/
```

예시는 `2026-09-07T12:34:56Z` 에서 스테이징을 시작한다고 가정합니다. 파일 이름에서 마지막 `.en_dec` 만 제거하고, `.zip` 을 유지하며 UTC 스테이징 시작 시간을 `-YYMMDD-HHMMSS` 로 붙입니다. 동일한 초의 충돌은 `-2`, `-3` 등을 부여합니다. 예외 디렉터리/파일 스테이징은 같은 이름을 유지합니다.

아카이브 또는 디렉터리 이름에 IP 주소와 포트가 `_` 혹은 `:` 로 구분되어 있을 수 있지만, 이 규칙은 보장되지 않으며 자체적으로 증거로 신뢰해서는 안 됩니다. 트리아지용 약한 메타데이터로 저장될 수 있으나 모든 보안 결과는 검사된 내용이나 현지 인텔리전스 기록에서 가져와야 합니다.

캡처 아카이브는 수십 기가바이트에 확장될 수 있으며, 중첩 아카이브, 실행 파일, 연결 라이브러리, 스크립트, 로그, 구성 파일, 자격 증명, 문서, 펌웨어, 패킷 캡처 및 디스크 이미지 등 수천 개의 파일을 포함할 수 있습니다. 가끔 동일한 자료가 압축 해제되지 않은 디렉터리 형태로 제공되기도 합니다. 모든 캡처된 콘텐츠를 적대적으로 취급합니다.

## 2. 첫 번째 구현에서 목표하지 않는 사항

- 모든 파일 시스템 엣지 케이스에 대한 실시간 보장.
- 분산 처리.
- 분석용 최적화된 전체 데이터베이스 스키마.
- 관측된 파일의 자동 복구 또는 삭제.
- 명시적 한계 없이 재귀 추출.
- 캡처를 실행, 가져오기, 소스 지정, 마운트하거나 다른 방식으로 신뢰하는 것.
- 인텔리전스 제공자 호출, Git 저장소 클론, YARA 규칙 컴파일, 혹은 캡처 처리 중 프로듀서 소유 데이터베이스 업데이트.
- 데이터베이스 미스, nullable verdict, 실패 조회, 또는 0 YARA 매치가 자산이 무해하다는 증거라고 간주하는 것.

## 3. 구성

`config/watcher_localintel.yaml` 과 같은 구조화된 구성 파일을 사용합니다.

예시:

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
      processors:
        - "ip_retriever"
        - "file_retriever"
        - "ghintel"
        - "yara_scan"

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

  ip_retriever:
    type: "ip_retriever"
    db_path: "./dbs/ipintel.sqlite3"
    output_root: "./output"
    chunk_size_bytes: 1048576
    chunk_overlap_bytes: 256
    max_file_size_bytes: null
    follow_symlinks: false
    include_hidden_files: true
    include_hidden_directories: true
    report_suffix: "-ipintel.md"

  file_retriever:
    type: "file_retriever"
    db_path: "./dbs/fileintel.sqlite3"
    output_root: "./output"
    max_depth_from_staged_root: null
    max_file_size_bytes: null
    hash_block_size_bytes: 1048576
    follow_symlinks: false
    include_hidden_files: true
    include_hidden_directories: true
    classifier:
      use_magic: true
      extension_fallback: true
    report_suffix: "-fileintel.md"

  ghintel:
    type: "ghintel"
    db_path: "./dbs/ghintel.sqlite3"
    output_root: "./output"
    chunk_size_bytes: 1048576
    max_candidate_bytes: 512
    max_file_size_bytes: null
    max_depth_from_staged_root: null
    follow_symlinks: false
    include_hidden_files: true
    include_hidden_directories: true
    report_suffix: "-ghintel.md"

  yara_scan:
    type: "yara_scan"
    cache_dir: "./rules/cache"
    output_root: "./output"
    selector: "exec-only"
    max_depth_from_staged_root: null
    max_file_size_bytes: null
    follow_symlinks: false
    include_hidden_files: true
    include_hidden_directories: true
    threads: 1
    timeout_seconds: 30
    include_strings: false
    max_string_instances_per_rule: 10000
    report_suffix: "-yara.md"
```

이것이 목표 결합 프로파일입니다. 프로세서는 타입이 등록되고 의존성이 시작 시 검증을 통과한 후에만 구성에 나타날 수 있습니다. 현재 구현 기준 및 이 프로필이 실행 가능해지는 순서는 `IMPLEMENTATION_PLAN.md` 에 기록됩니다.

구성 책임:

- 모든 상대 경로는 명시적 애플리케이션 베이스 디렉터리에 대해 해결됩니다. 현재 CLI 는 시작 작업 디렉터리를 베이스로 사용하므로 운영자는 프로젝트 루트에서 실행합니다; 향후 `--base-dir` 가 이를 명시적으로 만들 수 있습니다. 오버랩 검사 전에 경로를 정규화하고 캡처 콘텐츠에 상대적인 프로세서 경로를 절대적으로 해결하지 마십시오.
- `watch.path` 는 모니터링할 디렉터리를 선택합니다.
- `watch.stable_check` 은 복사된 파일이나 예외 디렉터리가 언제 완전한 상태가 되는지 제어합니다.
- `dispatcher.staging_root` 는 캡처를 분석 전에 추출하거나 복사하는 위치를 지정합니다.
- `dispatcher.output_root` 는 분석 보고서를 작성할 위치를 지정합니다.
- `dispatcher.staging_index_path` 는 이 도구의 지속적인 아카이브 ID‑투‑스테이지 매핑을 저장하며, 외부에서 생성된 인텔리전스 DB(`dbs/`)와는 별개입니다.
- `duplicate_policy: skip_if_output_exists` 은 입력 상대 경로와 아카이브 바이트 SHA‑256 으로 일치하는 완성된 스테이지 항목을 재사용합니다. 같은 경로에 변경된 아카이브가 있으면 새로운 타임스탬프 이름이 부여됩니다. DESIGN 02, 섹션 5.1 을 참조하십시오.
- `archive_output_naming` 은 아카이브 작업 단위에 적용됩니다: 최대 한 개의 지정된 최종 접미사를 제거하고 `.zip`, `.tar.gz` 를 유지하며 UTC 스테이징 시작 시간을 한 번만 붙입니다. 동일 초 충돌은 `-2`, `-3` 등으로 처리합니다. 예외 디렉터리/파일 스테이징은 같은 이름을 그대로 둡니다.
- 보고서 ID 는 의도적으로 스테이지 ID 와 다릅니다. 아카이브의 경우, `report_stem` 은 정확한 직계 자식 파일 이름(`source_name`)이며, 아카이브 및 전송 접미사를 포함합니다. 예를 들어, `sample.zip.en_dec` 은
  `sample.zip.en_dec-ipintel.md` 를 게시합니다.
- 새로운 캡처는 `watch.path` 의 직접 자식 아카이브 파일이어야 하며 예시로 `./in/2023-08-13_09-02-04.zip.en_dec`. 직접 자식 디렉터리도 예외로 허용됩니다.
- `pipelines.on_added.preprocessors` 는 분석 프로세서 전에 한 번 실행되는 프로세서를 정의합니다. 정상적인 첫 번째 전처리기는 입력 스테이저입니다.
- `pipelines.on_added.analysis.processors` 는 같은 불변 `staged_capture` 를 소비하는 분석 프로세서를 나열합니다. 구성 순서는 결정적 실행 및 보고서 게시를 제어하지만, 네 개의 분석 프로세서 간 데이터 종속성을 생성하지는 않습니다. 향후 상호 연관 프로세서는 모든 어댑터의 출력을 모두 소모할 수 있습니다.
- `processors` 는 프로세서별 설정을 포함합니다.
- 표준 프로세서 접미사는 고정된 `-ipintel.md`, `-fileintel.md`, `-ghintel.md`, `-yara.md` 이며, 모든 보고서는 `<archive_file_name>-<processor>.md` 형식입니다.
- 버전 1 은 각 파이프라인에 대해 각 보고서 생성 프로세서의 최대 한 개 활성 인스턴스를 허용합니다. 동일 표준 보고자 경로를 목표하는 구성을 거부합니다.

`in/sample.zip.en_dec` 에 대한 표준 보고 세트는 다음과 같습니다:

| 프로세서 | Markdown 보고 |
|---|---|
| IPIntel | `output/sample.zip.en_dec-ipintel.md` |
| FileIntel | `output/sample.zip.en_dec-fileintel.md` |
| GHIntel | `output/sample.zip.en_dec-ghintel.md` |
| YaraRuler | `output/sample.zip.en_dec-yara.md` |

## 4. 핵심 개념

### 4.1 Watch Event

워처는 원시 파일 시스템 이벤트를 안정적인 내부 이벤트로 변환합니다.

```text
WatchEvent
  id: 고유 이벤트 ID
  kind: added | modified | removed
  root_path: 구성된 감시 디렉터리
  path: 추가된 아카이브 파일, 파일 또는 디렉터리 경로
  relative_path: 감시 루트에 대한 상대 경로
  is_directory: 불리언
  capture_root: ./in/ 아래의 직접 자식으로 정의되는 캡처 단위
  source_name: 원본 입력 베이스네임, 모든 접미사를 포함
  observed_at: 타임스탬프
```

첫 번째 버전은 `added` 이벤트만 배포합니다. 모델은 향후 확장을 위해 `modified` 와 `removed` 를 보유합니다.

워처는 `./in/` 아래에 직접 추가된 자식들을 배포해야 합니다. 주요 흐름은 한 캡처 사례당 한 개의 직계 추가 아카이브 파일입니다. 직접 추가 디렉터리는 압축 해제되지 않은 캡처 예외를 위해 지원됩니다.

### 4.2 Processing Context

각 파이프라인 실행은 컨텍스트 객체를 받습니다.

```text
ProcessingContext
  event: WatchEvent
  config: 해결된 애플리케이션 구성
  logger: 구조화된 로거
  output_root: 해결된 middle-earth 스테이징 경로
  analysis_output_root: 해결된 보고서 출력 경로
  run_id: 고유 파이프라인 실행 ID
```

컨텍스트는 프로세서가 워처나 디스패처에 결합되지 않고 공유 서비스를 사용할 수 있도록 합니다.

### 4.3 Processor Result

프로세서는 전역 상태를 직접 변형하지 않아야 하며, 계약에 정의된 명시적 출력(예: 스테이징 파일 또는 보고서)만을 통해 결과를 반환합니다. 다음과 같은 객체를 반환합니다.

```text
ProcessorResult
  records: 프로세서가 생성하거나 증강한 레코드 목록
  metrics:
    files_seen: 정수
    records_emitted: 정수
    errors_seen: 정수
  errors: 비치명적 프로세서 오류 리스트
```

레코드는 타입 지정 딕셔너리나 데이터클래스입니다. 모든 찾기를 경로와 파이프라인 실행으로 추적할 수 있는 충분한 증거를 포함해야 합니다.

레코드는 다음을 구분합니다:

- 원본 캡처 경로.
- 추출된 아티팩트 경로.
- 추출된 아티팩트를 만든 아카이브 경로.
- 스테이지에 사용되는 고유 타임스탬프 `capture_name` 은 안정적인 `report_stem` 으로 표준 보고 파일 이름을 생성하는 데 사용됩니다.

## 5. Processor Interface

모든 프로세서는 동일한 인터페이스를 구현합니다.

```text
Processor
  name: 문자열
  accepts(input_records, context) -> 불리언
  process(input_records, context) -> ProcessorResult
```

예상 동작:

- `name` 은 안정적이며 구성에서 사용됩니다.
- `accepts` 는 프로세서가 호환되지 않는 입력을 건너뛸 수 있게 합니다.
- `process` 는 작업을 수행하고 downstream 처리를 위한 레코드를 반환합니다.
- 프로세서는 빈 입력 리스트를 받을 수 있습니다.
- 전처리 프로세서(예: input staging 및 archive extraction)는 빈 입력 리스트를 받고 `staged_capture` 와 아티팩트 레코드를 반환할 수 있습니다.
- 분석 프로세서(`IPRetriever`)는 이전 프로세서의 staged 레코드에서 소비합니다.
- 비치명적 오류는 결과에 캡처됩니다. 치명적 설정/구성 실패는 파이프라인 시작을 중단해야 합니다.

권장 구현 예시:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

@dataclass(frozen=True)
class ProcessorResult:
    records: list[Mapping[str, Any]]
    metrics: Mapping[str, int]
    errors: list[str]

class Processor(ABC):
    name: str

    def accepts(
        self,
        input_records: Sequence[Mapping[str, Any]],
        context: "ProcessingContext",
    ) -> bool:
        return True

    @abstractmethod
    def process(
        self,
        input_records: Sequence[Mapping[str, Any]],
        context: "ProcessingContext",
    ) -> ProcessorResult:
        ...
```

## 6. Dispatcher 및 파이프라인 실행

디스패처는 정규화된 워치 이벤트를 수신하고 구성된 프로세서 시퀀스를 실행합니다.

고수준 이벤트 기반 흐름:

```text
파일 시스템 워처
  -> 이벤트 정규화/디바운서
  -> 디스패처 이벤트 큐
  -> 프로세서 러너
  -> 입력 스테이징 / 아카이브 언아치버 프로세서
  -> IPRetriever
  -> FileRetriever
  -> GHIntel
  -> YaraScan
  -> 향후 선택적 상호 연관 프로세서
  -> 보고서 / 프로세서 출력
```

디스패처 책임:

- 이벤트 종류에 따라 전처리 및 분석 프로세서 목록을 선택합니다.
- `ProcessingContext` 를 생성합니다.
- 전처리기를 한 번 실행합니다.
- 설정된 순서대로 프로세서를 실행합니다.
- 새로 추가된 아카이브와 예외 디렉터리/파일을 스테이징(중간 지점) 전에 `middle-earth/` 에 배치합니다.
- 프로세서 간에 레코드를 전달합니다.
- 분석용 스테이지 캡처 레코드를 분석 프로세서에 제공하고 이후 프로세서에 보관합니다.
- 완성된 스테이징 캡처만 분석을 실행합니다. 스테이징 상태에서 보고서 소유권을 예약 및 검증하고, 쓰기를 시리얼라이즈합니다(스테이징 루트 잠금 사용).
- 디스패처 결과에 레코드를 보존합니다.
- 프로세서 메트릭과 오류를 로깅합니다.
- 분석 어댑터가 실패해도 다른 독립 어댑터 또는 이후 이벤트를 차단하지 않도록 합니다. 프리프로세서가 실패하면 분석을 중단하지만, 분석 어댑터는 실패해도 다음 독립 어댑터로 진행됩니다.

실행 정책:

- 첫 번째 구현에서는 순차 실행을 사용하여 리소스 사용 및 보고서 게시를 결정적하게 만듭니다. 네 개의 분석 어댑터는 논리적으로 독립이지만, 각자는 누적 레코드를 수집합니다.
- 향후 상호 연관 프로세서는 명시적으로 이들의 출력을 필요로 할 수 있습니다.
- 첫 번째 구현은 인-프로세스 큐를 동기식으로 드레인하며, 캡처 수준 병렬성은 스테이징 잠금, SQLite 스냅샷, 메모리 제한 및 보고서 소유권을 테스트한 후에만 추가됩니다.

위 예시:

```text
dispatch(event):
  context = create_context(event)
  records = run_preprocessors(context, config.pipelines[event.kind].preprocessors)

  if not has_completed_staged_capture(records):
    return records

  run_analysis(context, config.pipelines[event.kind].analysis.processors, records)

run_preprocessors(context, preprocessors):
  records = []

  for processor in preprocessors:
    if not processor.accepts(records, context):
      continue

    result = processor.process(records, context)
    records.extend(result.records)

  return records

run_analysis(context, processor_names, records):
  for processor in processor_names:
    if not processor.accepts(records, context):
      continue

    try:
      result = processor.process(records, context)
      records.extend(result.records)
      log metrics and errors
    except Exception as error:
      append a processor-scoped error
      continue with the next independent analysis processor
```

프로세서 순서:

- 입력 스테이저는 일반적으로 첫 번째 전처리기로 구성됩니다.
- 아카이브 추출 프로세서는 보통 스테이저에 의해 호출되거나 `preprocessors` 로 지정됩니다.
- 전처리기는 캡처 단위에 대해 한 번 실행되고 분석 프로세서가 시작합니다.
- 같은 언아치버 구현은 입력 스테이저 또는 향후 워크플로에서 다른 프로세서 이름으로 재사용될 수 있습니다.
- 분석 프로세서는 `middle-earth/` 아래의 스테이지 캡처 디렉터리를 탐색합니다. 원본 입력 경로는 증거이며 주 분석 루트가 아닙니다.
- 언아치버가 한 아카이브에서 실패하면, 존재하는 다른 아카이브에 대해 처리는 계속되고 원본 입력 경로를 증거로 보존합니다.

## 7. 워처 디자인

첫 번째 구현은 폴링 워처를 사용하며 테스트와 로컬 실행 시 OS 고유의 파일 시스템 알림 동작에 의존하지 않도록 합니다. 향후 알림 기반 구현을 위해 작은 인터페이스 뒤에 감쌉니다.

책임:

- 구성 파일을 불러오고 검증합니다.
- 감시 경로가 존재하며 디렉터리인지 확인합니다. 기본 감시 경로는 `./in/` 입니다.
- 감시 경로 아래의 새 직계 자식을 탐지합니다.
- 원시 이벤트를 `WatchEvent` 로 정규화합니다.
- 부분 복사된 아카이브 파일이나 예외 디렉터리 트리를 반복적으로 처리하지 않도록 디바운스합니다.
- 짧은 대기 후에만 배포합니다.

중요 동작:

- 아카이브 파일이 추가되면, 디스패처는 스테이지 디렉터리에 먼저 추출한 뒤 분석을 수행합니다.
- 디렉터리가 추가되면 예외 압축 해제되지 않은 캡처 단위로 취급하여 `middle-earth/` 아래에 스테이지합니다.
- 비아카이브 파일이 추가되면, 구성에서 직접 파일 허용 시에만 분석을 위해 스테이징합니다.
- `./in/` 의 직계 자식이면 하나의 캡처 사례로 간주하고 `capture_root` 로 설정합니다.
- 입력 이름 자체를 증거로 신뢰하지 않습니다; IP 주소와 포트를 포함해도 그렇습니다.
- 워처는 아카이브 추출, 복사, IP 추출, 인텔리전스 DB 읽기 등을 알지 못해야 합니다.

디바운스 전략:

- 경로별 최신 생성 이벤트 맵을 유지합니다.
- 같은 파일이 변경되거나 동일 추가 디렉터리 아래 다른 이벤트가 발생하면 타이머를 재설정합니다.
- `event_debounce_ms` 만큼 관련 생성 이벤트가 없으면 배포합니다.
- 예외 디렉터리 트리가 복사될 때는 `./in/` 의 직계 자식에 대해 바로 배포하도록 선호합니다.

## 8. 프로세서 0: 입력 스테이저 및 아카이브 언아치버

목적:

- `./in/` 아래 직접 추가된 아카이브를 `middle-earth/` 아래 고유 작업 디렉터리로 변환.
- 추가가 아카이브라면 안전하게 추출.
- 예외 디렉터리 또는 일반 비아카이브 파일이라면 안전하게 복사.
- downstream 분석 프로세서에 `staged_capture` 레코드를 내보냅니다.

스테이저는 워처나 분석 프로세서가 아니라 스테이지 이름을 할당합니다. 아카이브라면 최종 고유 스테이징 디렉터리 베이스네임(타임스탬프 및 충돌 카운터 포함)을 사용합니다. 지속적인 할당은 중복 이벤트, 동일 바이트 재전송, 재시도 및 재시작에 견고합니다. 완성된 추출 출력만 재사용할 수 있습니다; 디렉터리 자체만 있으면 충분하지 않습니다. DESIGN 02, 섹션 5.1 및 6.3 은 이 계약을 정의합니다. 예외 디렉터리/파일 베이스네임은 스테이저가 한번에 SANITIZE 하며 DESIGN 02 파일명 규칙을 사용해 스테이지 디렉터리와 보고서에 동일한 이름을 사용합니다.

스테이드 캡처 출력 레코드:

```json
{
  "type": "staged_capture",
  "capture_name": "2023-08-13_09-02-04.zip-260907-123456",
  "report_stem": "2023-08-13_09-02-04.zip.en_dec",
  "source_name": "2023-08-13_09-02-04.zip.en_dec",
  "source_path": "/watched/in/2023-08-13_09-02-04.zip.en_dec",
  "source_sha256": "<64 소문자 hex 문자>",
  "staging_started_at": "2026-09-07T12:34:56Z",
  "staged_path": "/repo/middle-earth/2023-08-13_09-02-04.zip-260907-123456",
  "staging_method": "archive_extracted",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

## 9. 프로세서 0b: 아카이브 언아치버

목적:

- 추가된 캡처에서 설정된 아카이브 파일을 검색.
- 일치하는 아카이브를 제어된 출력 위치에 추출.
- 추출된 파일과 추출 오류를 설명하는 레코드를 내보냅니다.
- content‑analysis 프로세서 전에 dispatcher 전처리기로 실행되어 IP 스캔을 위해 내용이 가용하도록 합니다.

입력:

- 빈 입력 레코드 또는 이전 언아치버 실행에서 생성한 아티팩트 레코드.
- `context.event.capture_root` 를 스캔 루트로 사용합니다. 일반적으로 직접 추가된 아카이브 파일이며, 예외 디렉터리인 경우 복사된 디렉터리입니다.

출력 레코드:

```json
{
  "type": "archive_extracted",
  "archive_path": "/watched/in/case-001.tar.gz",
  "output_dir": "/repo/middle-earth/case-001.tar.gz-260907-123456",
  "archive_format": ".tar.gz",
  "files_extracted": 42,
  "bytes_extracted": 12345,
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

선택 구성:

- `max_depth_from_event_root` 은 아카이브 검색을 이벤트 경로에서 디렉터리 깊이를 제한합니다. 예외 디렉터리 입력에 대해 중요합니다.
- `filename_regex` 는 정규 표현식과 일치하는 이름의 아카이브 파일만 추출합니다(`.*\.(en_dec|enc|zip|tar\.gz)$`). 두 조건이 모두 충족해야 합니다.
- depth 가 `null` 이면 깊이 필터를 적용하지 않습니다. 정규식이 `null` 이면 이름 필터를 적용하지 않습니다.

적대 콘텐츠 제어:

- 추출된 파일을 절대로 실행하지 않음.
- `middle-earth/` 아래 전용 스테이지 디렉터리에서 추출.
- 경로 트래버설을 방지하기 위해 추출 디렉터리를 벗어나려는 항목은 거부합니다. 절대 경로, 심링크, 하드 링크, 장치 노드, FIFO 및 특수 파일을 안전하게 처리하거나 거절합니다.
- 아카이브 크기, 추출된 파일 수, 총 추출 바이트, 중첩 깊이에 대한 설정 한계 적용.
- 원본 파일과 덮어쓰지 않음(명시적으로 허용되지 않는 경우).
- 암호화, 손상, 지원 불가 또는 과도한 아카이브를 프로세서 비치명적 오류로 기록.

구현 참고:

- `zipfile`, `tarfile` 표준 라이브러리 사용.
- `.en_dec` 및 `.enc` 은 `zipfile.is_zipfile` 으로 확인 후 ZIP 내용으로 취급. 이 접미사는 암호화 요청이 아님. 무효하거나 암호화된 ZIP은 아카이브 오류를 발생시키며, 파일 복사 fallback 에서는 절대 사용하지 않음.
- `.7z`, `.xz`, `.bz2` 또는 단일 파일 `.gz` 등 다른 형식은 운영 요구가 변경되지 않는 한 향후 확장으로 두고 둡니다.
- 아카이브 메타데이터를 신뢰하지 않습니다.
- 스테이징 할당을 결정된 후 추출을 시작하며, 중복 입력에 대해 새 타임스탬프를 생성하지 않습니다. 새로운 아카이브 ID는 타임스탬프가 붙은 출력 경로를 받습니다.
- 추출 마니페스트 레코드를 발행해 이후 프로세서와 분석가가 출처 아카이브에서 결과를 추적할 수 있도록 합니다.

## 10. 프로세서 1: IPIntel (`IPRetriever` 어댑터)

목적:

- 스테이지된 캡처 디렉터리를 재귀적으로 탐색.
- IPv4 및 IPv6 주소를 추출.
- `dbs/ipintel.sqlite3` 로부터 매칭 로컬 인텔리전스 검색.
- `output/` 아래에서 증거 연결 Markdown 보고서 작성.

입력:

- 입력 스테이저에서 발생한 `staged_capture` 레코드.
- `record.staged_path` 를 스캔, 원본 입력 경로(`in/`)는 사용하지 않음.

출력 레코드:

```json
{
  "type": "ip_observation",
  "ip": "8.8.8.8",
  "ip_version": 4,
  "source_path": "/repo/middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/file.txt",
  "display_path": "middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/file.txt",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

보고서 출력:

```text
output/<report_stem>-ipintel.md
```

`staged_capture.report_stem` 을 사용합니다; 이는 원본 아카이브 베이스네임입니다. 같은 파일 이름의 새로운 분석 결과가 기존 보고서를 원자적으로 새로 고칩니다. 보고서 본문은 `capture_name`, 소스 SHA‑256, 스테이지 경로 및 실행 ID 를 포함해 분석자가 정확한 타임스탬프 스테이징 생성을 식별할 수 있도록 합니다.

구현 참고:

- 스테이지 디렉터리를 재귀적으로 탐색.
- 한계 파일 크기, 심링크, 숨김 파일/디렉터리, 청크 크기 및 오버랩 구성을 준수합니다.
- 비 regex 기반이 아니라 강력한 IP 파서 사용(예: `ipaddress` 모듈).
- 후보 정규식은 넓게 잡되며, 파서로 검증하고 표준 표현으로 정규화.
- 라인 번호는 텍스트 파일에 한정해 제공.
- `dbs/ipintel.sqlite3` 를 읽기 전용으로 사용; 별도 `erecb-ipintel` 애플리케이션이 수집 및 DB 변조를 담당합니다.
- DB가 없거나 읽을 수 없으면 보고서를 작성하고, 없는 행이라면 비치명적 오류로 간주.

## 11. 프로세서 2: FileIntel (`FileRetriever` 어댑터)

목적:

- 스테이지된 캡처 디렉터리를 재귀적으로 탐색.
- 실행 파일 또는 스크립트와 같은 실행 가능한 파일을 식별(실제 실행은 하지 않음).
- 각 실행 파일에 대해 SHA‑256 및 MD5를 스트리밍 한 번으로 계산.
- `dbs/fileintel.sqlite3` 로부터 매칭 로컬 인텔리전스 검색.
- `output/` 아래에서 증거 연결 Markdown 보고서 작성.

입력:

- 입력 스테이저에서 발생한 `staged_capture` 레코드.
- `ip_observation`, `ip_intel_hit` 기록은 받을 수 있으나 필수는 아님; 하위 컨텍스트로 보존됩니다.

출력 레코드:

```json
{
  "type": "file_observation",
  "sha256_hash": "<64 소문자 hex>",
  "md5_hash": "<32 소문자 hex>",
  "magic": "PE32 executable ...",
  "classification_reason": "magic: PE32 executable",
  "source_path": "/repo/middle-earth/2023-08-13_09-02-04.zip-260907-123456/tool.exe",
  "display_path": "middle-earth/2023-08-13_09-02-04.zip-260907-123456/tool.exe",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

보고서 출력:

```text
output/<report_stem>-fileintel.md
```

다른 분석 어댑터와 동일하게 `report_stem` 사용. 별도 `erecb-fileintel` 애플리케이션이 엔richment 및 DB 변조를 담당합니다; `FileRetriever` 는 읽기 전용으로 `dbs/fileintel.sqlite3` 를 열고, 누락 행은 오류가 아니라 커버리지 갭으로 처리합니다. 참고: `DESIGN_04_PROCESSOR_FILEINTEL.md`.

## 12. 프로세서 3: GHIntel

목적:

- 스테이지된 일반 파일 바이트에서 지원되는 GitHub 저장소 루트 주소를 추출.
- 제공자와 호환되도록 정규화(사례 접두어 `github.com/owner/repository` 로 대문자 통합).
- Git, GitHub API, LLM 호출 없이 `dbs/ghintel.sqlite3` 에서 효과적인 프로젝트 카드를 읽음.
- `output/<report_stem>-ghintel.md` 를 작성하며 현재 캡처 증거를 생산자가 보유한 이력과 분리.

GHIntel 은 콘텐츠 스캐너이며, 캡처된 `.git` 디렉터리를 신뢰하거나 Git 설정을 평가하거나 포함 파일을 따르지 않으며 자격 증명 헬퍼를 실행하지 않습니다. 데이터베이스 히트/미스/가용성 오류는 서로 구분됩니다. `DESIGN_05_PROCESSOR_GHINTEL.md` 참조.

## 13. 프로세서 4: YaraRuler (`YaraScan` 어댑터)

목적:

- 완료된 스테이지 캡처에서 실행 파일 및 스크립트와 같은 후보를 선택.
- 독립 YaraRuler 애플리케이션이 준비한 불변 YARA 캐시 세대를 고정하고 검증.
- 파일 내용을 매칭하며, 타임아웃과 비실행 조건을 준수.
- 규칙/소스/캐시 증거와 일치 바이트 해시를 발행 후 `output/<report_stem>-yara.md` 를 작성.

캡처 처리는 룰 저장소 클론 또는 소스 규칙 컴파일을 수행하지 않습니다. 캐시가 없거나 유효하지 않으면 성공 스캔과 0 매치를 구분할 수 있습니다. `DESIGN_06_PROCESSOR_YARARULER.md` 참조.

## 14. 오류 처리

세 단계 실패를 사용합니다:

- **구성 오류**:
  - 잘못된 감시 경로.
  - 파이프라인에 존재하지 않는 프로세서 이름.
  - DB 경로나 출력 루트와 같은 필수 설정 누락.
  - 이는 시작 시에 실패해야 합니다.

- **프로세서 레코드 오류**:
  - 읽을 수 없는 파일.
  - 처리 전 삭제된 파일.
  - 암호화, 손상, 지원 불가, 과도한 아카이브 또는 경로 트래버설.
  - 이는 `ProcessorResult.errors` 에 캡처되고 로깅됩니다.

- **실행 오류**:
  - 프로세서에서 예상치 못한 예외.
  - 프리프로세서 예외는 분석을 중단하지만, 분석 어댑터 예외는 독립 어댑터에만 제한됩니다. 나머지 이벤트는 계속 진행합니다.

IP 가 비활성 DB 행이 없는 경우 오류가 아닙니다. FileRetriever 에서 실행 파일 해시가 없으면 오류가 아니며, GHIntel 도 마찬가지입니다. YARA 스캔이 0 매치를 하면 깨끗한 결과라고 말하지 않으며, 누락/비호환 데이터베이스나 규칙 캐시는 완전 분석 오류이며, 로컬 관찰을 보존하고 가능한 한 명시적인 불완전 보고를 게시하며 독립 어댑터와 이후 캡처에 영향을 주지 않습니다.

## 15. 제안 프로젝트 레이아웃

```text
config/
  watcher_ipintel.yaml
  watcher_localintel.yaml
src/
  erecb_triage/
    __init__.py
    config.py
    events.py
    watcher.py
    dispatcher.py
    processors/
      __init__.py
      archive_unarchiver.py
      base.py
      input_stager.py
      ip_retriever.py
      file_retriever.py
      ghintel.py
      yara_scan.py
    ipintel/
      __init__.py
      extractor.py
      repository.py
      report.py
    fileintel/
      __init__.py
      classifier.py
      hashing.py
      repository.py
      report.py
    ghintel/
      __init__.py
      extractor.py
      normalization.py
      repository.py
      report.py
    yarascan/
      __init__.py
      cache.py
      discovery.py
      matcher.py
      report.py
tests/
  test_archive_unarchiver.py
  test_ip_retriever.py
  test_file_retriever.py
  test_dispatcher.py
```

## 16. 인도 계획

권위 있는 단계별 인도 계획은 [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) 에 있습니다. DESIGN 03‑06 의 컴포넌트 로컬 단계는 exit 기준을 제공하지만, 구현 상태를 독립적으로 주장하지는 않습니다.

아래 개요는 기능 분해만 남겨 두었습니다:

### Phase 1: Core Contracts

- config loader 및 validator 추가.
- `WatchEvent`, `ProcessingContext`, `Processor`, `ProcessorResult` 추가.
- 프로세서 레지스트리 추가.

### Phase 2: Dispatcher

- 구성에서 프로세서 로딩 구현.
- 분석 전 공유 프리프로세서 실행 구현.
- 순차적 프로세서 실행 구현.
- 프로세서 순서, 건너뛰기 동작, 실패 격리 단위 테스트 추가.

### Phase 3: Watcher

- 폴링 파일 시스템 워처 추가.
- 원시 이벤트 정규화.
- 대량 복사 아카이브 및 예외 디렉터리 캡처에 대해 디바운스 구현.
- `./in/` 아래 직계 아카이브 파일을 dispatch; `./in/` 내부의 직접 디렉터리를 예외 압축 해제 캡처 단위로 처리.

### Phase 4: Archive Preprocessing

- 입력 스테이저를 먼저 사용해 아카이브 파일과 예외 디렉터리/정규 파일을 스테이지.
- archive unarchiver 프로세서 구현.
- 깊이에 기반한 아카이브 탐색 추가.
- 정규식 이름 필터링 추가.
- 적대적 아카이브 안전 검사 추가.
- `.en_dec` ZIP 추출, 유지된 `.zip`, `IP:PORT` 멤버 보존, 동일 초 충돌 및 지속 중복/재시도 처리 등 테스트와 단위 테스트 포함.

### Phase 5: Local Analysis Processors

- IPRetriever 구현, 로컬 SQLite 조회, Markdown 보고서 작성.
- FileRetriever 구현, 실행 파일 분류, 스트리밍 해시 계산, 로컬 SQLite 조회, Markdown 보고서 작성.
- FileRetriever 가 IP 프로세서가 없거나 DB 히트가 없어도 보고서를 생성하는지 테스트.

### Phase 6: GitHub Intelligence

- 제한된 저장소 주소 추출 및 정규화 구현.
- 읽기 전용 GHIntel 스키마 어댑터와 효과적인 프로젝트 카드 조회 구현.
- Git, 네트워크, 자격 증명 헬퍼, LLM 동작이 없음을 입증.

### Phase 7: YARA Analysis

- 검증된 YaraRuler 캐시 소비자 구현 및 실행 파일 선택기.
- 타임아웃 매칭, 일치 전 해시, 출처/캐시 증거 기록, 제한된 보고서 구현.
- 캐시 실패가 성공 스캔과 0 매치를 구분한다는 것을 입증.

## 17. 남은 설계 결정

- 입력 아카이브, 스테이지 캡처, 스테이징‑인덱스 행, 보고서 및 오래된 YARA 세대의 보존 기간 및 삭제 권한.
- 누적 in‑memory 레코드 리스트가 매우 큰 캡처에 대해 버전ed on‑disk/streaming 저장소로 전환해야 할지 여부.
- 캡처 수준 병렬성이 언제 안전한지; 버전 1 은 인-프로세스 큐와 결정적인 순차 드레인을 사용합니다.
- 디스크 이미지, 펌웨어 이미지 및 패킷 캡처 같은 깊은 포맷을 별도 프로세서로 처리할 것인지, 아니면 아카이브 언아치버에 통합할 것인지 여부.
- FileIntel, GHIntel, YaraRuler 간의 격리된 증거 규칙과 효율적인 아티팩트 인벤토리를 공유함으로써 중복 워크를 줄일 수 있을지 여부.

해결된 결정: 파이썬은 구현 언어이며 버전 1 은 누적 레코드 리스트를 사용하고, 향후 모드 `--once` 는 기존 직계 자식을 스캔하며, `python‑magic` 은 선택적으로 사용하되 문서화된 일관성 fallback 를 제공합니다.
