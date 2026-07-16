# GhostHeader

HTTP 요청의 "지문(fingerprint)"을 통해 비정상 클라이언트를 가려내는 Spring Boot 3.3 게이트웨이. IP 차단도 CAPTCHA도 사용하지 않고, 헤더 구성·순서·콘텐츠 길이·요청 리듬을 누적 학습한다.

## 탐지 신호

| 신호 | 의도 | 점수 |
|---|---|---|
| Content-Length 헤더와 실제 본문 바이트 불일치 (same-request) | 위조/스머글링 시도 | +10 |
| User-Agent 누락 | 정상 브라우저는 항상 전송 | +3 |
| 브라우저 UA + Accept-Language 누락 | 자동화 도구가 흔히 누락 | +4 |
| 브라우저 UA + 헤더 6개 미만 + 쿠키 없음 | 최소 헤더 자동화 | +2.5 |
| 첫 헤더가 Host가 아님 (브라우저 UA) | 정상 브라우저 송신 패턴 위반 | +2 |
| 같은 클라이언트 50ms 미만 연속 호출 (warmup 후) | 봇 리듬 | +6 |
| 클라이언트 간격 z-score > 4 | 변동 패턴 이탈 | +α |
| 브라우저 UA + Accept-Encoding 누락 | 정상 브라우저는 항상 압축 광고 | +1.5 |
| 브라우저 UA + Sec-Fetch-Site 누락 | Chromium/Safari/Firefox 모두 송신 | +2 |

threshold는 deny 비율(EMA)에 따라 `[ghost.threshold.min, ghost.threshold.max]` 사이에서 동적으로 조정되며, `/admin/threshold/override?value=…` 로 수동 잠금 가능.

### 대응 정책 (spec §5)

이진 allow/deny가 아니라 `ratio = score / threshold` 로 강도를 나눈 4단계 `Verdict.Action`. 경계는 동적 threshold의 배수라 threshold가 움직여도 같이 스케일한다 (`ResponsePolicy`).

| ratio | Action | 동작 |
|---|---|---|
| `< 1.0` | ALLOW | 실제 응답 정상 서빙 |
| `[1.0, 1.4)` | DELAY | `ghost.response.delay-ms`(기본 1000ms) 지연 후 실제 응답 서빙 (tarpit) |
| `[1.4, 1.8)` | DECOY | 실제 핸들러를 타지 않고 가짜 정상 응답(`{"ok":true}`) 200 반환 - 봇이 탐지 사실을 알 수 없게 |
| `>= 1.8` | BLOCK | 403 |

경계는 `ghost.response.{delay,decoy,block}-ratio` 로 설정. DELAY/DECOY 응답에는 탐지 노출을 막기 위해 `X-Ghost-Reasons` 를 붙이지 않는다 (BLOCK에만 부착). 카운터: `ghost.verdict.{allowed,delayed,decoyed,denied}`.

## 구성요소

- `Fingerprint` — 헤더 이름 순열 + UA 쉐입 + Accept-Language·Cookie 유무를 SHA-1로 압축
- `Profile` — 클라이언트별/지문별 요청 간격의 Welford 평균·분산 누적
- `AnomalyDetector` — 요청 1건의 점수와 사유를 산출, `ResponsePolicy`로 Action 결정
- `ResponsePolicy` — score/threshold 배수로 ALLOW/DELAY/DECOY/BLOCK 매핑
- `DetectionFilter` — `OncePerRequestFilter`로 `/api/**` 경로 검사, Action별 응답 적용

## 빌드 및 실행

```bash
mvn test                  # 35건 테스트
mvn spring-boot:run       # 8110 포트
```

## 호출 예시

```bash
# 브라우저처럼 헤더를 갖추면 통과
curl -i 'http://localhost:8110/api/protected' \
  -H 'Host: localhost:8110' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36' \
  -H 'Accept-Language: ko-KR,en;q=0.8' \
  -H 'Cookie: s=abc' \
  -H 'X-Client-Token: alice'
```

응답에는 항상 `X-Ghost-Score`, `X-Ghost-Fingerprint`가 붙고, 차단 시 `X-Ghost-Reasons`도 함께 전송된다.

## 테스트 (26건)

`AnomalyDetectorTests` (11건) — 단위:
- 정상 브라우저 통과, curl 룰 비대상, AL 결손 차단, Content-Length 불일치 룰 자체(합성 `RequestSnapshot` 기준) 차단, burst 리듬 차단, Host 헤더 위치 페널티, 동일 형상 지문 동일성, UA 카테고리 분리, SHA-256 길이, 동시성(detector / profile snapshot)

`HttpFlowTests` (5건) — 필터 통합:
- 보호 엔드포인트 정상 통과, AL 결손 차단, allow/deny verdict Micrometer 카운터 증가, **선언 Content-Length ≠ 실제 스트리밍 바이트 → 실측 후 차단(same-request)**, 정직한 Content-Length는 오탐 없이 통과

`BrowserCapabilityRulesTest` (4건) — Accept-Encoding/Sec-Fetch 룰 단위.

`DynamicThresholdTests` (6건) — base/min/max 가드, deny EMA 반응, manual override 우선순위.

`mvn test` → 26/26 pass.

## 의도적으로 보류한 항목

- TLS JA3/JA4 등 핸드셰이크 지문
- HTTP/2 프레임 시퀀스 분석
- 모델 영속화/관리 콘솔
- 다중 노드 공유 프로파일 스토어

## Content-Length 불일치 탐지 (동작 방식)

- **실측 기반이며 same-request 의미론이다.** `DetectionFilter`는 요청을 `BufferedBodyRequestWrapper`로 감싸 채점 *이전에* 본문을 선(先)소비한다. 클라이언트가 실제로 스트리밍한 바이트 수를 세고, 이를 `Content-Length` 헤더의 선언값과 비교한다. 불일치하면 바로 그 요청이 `ContentLengthMismatchRule`(+10)로 채점되어 그 자리에서 403된다 - 다음 요청으로 미루지 않는다.
- 근본 긴장: 필터는 핸들러가 본문을 읽기 *전에* 채점하지만, 실제 바이트 수는 소비 *후에야* 알 수 있다. 이를 필터가 본문을 미리 버퍼링해 소비 시점을 채점 앞으로 당겨 해소했다.
- **경계(제한):** 본문을 버퍼링하므로 `ghost.body-measure-cap-bytes`(기본 64 KiB)로 상한을 둔다. 이 상한을 초과하는 본문은 (핸들러로는 온전히 스트리밍되지만) 인라인 길이 검증을 건너뛴다 - 즉 상한 이하의 본문에 대해서만 불일치를 판정한다. 상한은 설정으로 조정 가능하다.
- 선언값은 `Content-Length` 요청 헤더에서 파싱하며, 헤더가 없거나(청크 전송 등) 음수/파싱 불가면 판정하지 않는다. 클라이언트 자기신고 헤더(`X-Declared-Body-Bytes`)와 `ghost.trust-declared-body-header` 설정은 제거했다.

## 최근 추가

- `DynamicThreshold` — deny 비율 EMA 기반 자동 튜닝 + manual override (`/admin/threshold`).
- 브라우저 능력 신호 — Accept-Encoding/Sec-Fetch-Site 결손 룰. Chromium 계열의 발신 패턴을 추가로 활용한다.
- `Fingerprint`에 AE/SF 차원 추가 — 동일 UA로도 헤더 능력 차이로 분리되는 지문 생성.
