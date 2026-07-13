# GhostHeader

HTTP 요청의 "지문(fingerprint)"을 통해 비정상 클라이언트를 가려내는 Spring Boot 3.3 게이트웨이. IP 차단도 CAPTCHA도 사용하지 않고, 헤더 구성·순서·콘텐츠 길이·요청 리듬을 누적 학습한다.

## 탐지 신호

| 신호 | 의도 | 점수 |
|---|---|---|
| Content-Length 헤더와 실제 본문 바이트 불일치 (미구현·스텁) | 위조/스머글링 시도 | +10 |
| User-Agent 누락 | 정상 브라우저는 항상 전송 | +3 |
| 브라우저 UA + Accept-Language 누락 | 자동화 도구가 흔히 누락 | +4 |
| 브라우저 UA + 헤더 6개 미만 + 쿠키 없음 | 최소 헤더 자동화 | +2.5 |
| 첫 헤더가 Host가 아님 (브라우저 UA) | 정상 브라우저 송신 패턴 위반 | +2 |
| 같은 클라이언트 50ms 미만 연속 호출 (warmup 후) | 봇 리듬 | +6 |
| 클라이언트 간격 z-score > 4 | 변동 패턴 이탈 | +α |
| 브라우저 UA + Accept-Encoding 누락 | 정상 브라우저는 항상 압축 광고 | +1.5 |
| 브라우저 UA + Sec-Fetch-Site 누락 | Chromium/Safari/Firefox 모두 송신 | +2 |

`score >= threshold`면 403. threshold는 deny 비율(EMA)에 따라 `[ghost.threshold.min, ghost.threshold.max]` 사이에서 동적으로 조정되며, `/admin/threshold/override?value=…` 로 수동 잠금 가능.

## 구성요소

- `Fingerprint` — 헤더 이름 순열 + UA 쉐입 + Accept-Language·Cookie 유무를 SHA-1로 압축
- `Profile` — 클라이언트별/지문별 요청 간격의 Welford 평균·분산 누적
- `AnomalyDetector` — 요청 1건의 점수와 사유를 산출
- `DetectionFilter` — `OncePerRequestFilter`로 `/api/**` 경로 검사

## 빌드 및 실행

```bash
mvn test                  # 14건 테스트
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

## 테스트 (24건)

`AnomalyDetectorTests` (11건) — 단위:
- 정상 브라우저 통과, curl 룰 비대상, AL 결손 차단, Content-Length 불일치 룰 자체(합성 `RequestSnapshot` 기준) 차단, burst 리듬 차단, Host 헤더 위치 페널티, 동일 형상 지문 동일성, UA 카테고리 분리, SHA-256 길이, 동시성(detector / profile snapshot)

`HttpFlowTests` (3건) — 필터 통합:
- 보호 엔드포인트 정상 통과, AL 결손 차단, allow/deny verdict Micrometer 카운터 증가

`BrowserCapabilityRulesTest` (4건) — Accept-Encoding/Sec-Fetch 룰 단위.

`DynamicThresholdTests` (6건) — base/min/max 가드, deny EMA 반응, manual override 우선순위.

`mvn test` → 24/24 pass.

## 의도적으로 보류한 항목

- TLS JA3/JA4 등 핸드셰이크 지문
- HTTP/2 프레임 시퀀스 분석
- 모델 영속화/관리 콘솔
- 다중 노드 공유 프로파일 스토어

## 제한사항

- **Content-Length 불일치 탐지는 스텁이다.** `DetectionFilter`는 실제 요청 본문을 읽지 않고 `bodyBytes`를 `Content-Length` 헤더 값 그대로 채우므로(`web/DetectionFilter.java:67-68`), 기본 설정에서는 이 신호가 절대 발동하지 않는다. `ghost.trust-declared-body-header=true`로 켜도 클라이언트가 스스로 보내는 `X-Declared-Body-Bytes` 헤더와 비교할 뿐이라 위조 방지 효과가 없다. `ContentLengthMismatchRule` 자체는 단위 테스트로 검증되어 있으나, 실제 바이트 스트림과 연결되어 있지 않다.

## 최근 추가

- `DynamicThreshold` — deny 비율 EMA 기반 자동 튜닝 + manual override (`/admin/threshold`).
- 브라우저 능력 신호 — Accept-Encoding/Sec-Fetch-Site 결손 룰. Chromium 계열의 발신 패턴을 추가로 활용한다.
- `Fingerprint`에 AE/SF 차원 추가 — 동일 UA로도 헤더 능력 차이로 분리되는 지문 생성.
