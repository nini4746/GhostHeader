# GhostHeader

HTTP 요청의 "지문(fingerprint)"을 통해 비정상 클라이언트를 가려내는 Spring Boot 3.3 게이트웨이. IP 차단도 CAPTCHA도 사용하지 않고, 헤더 구성·순서·콘텐츠 길이·요청 리듬을 누적 학습한다.

## 탐지 신호

| 신호 | 의도 | 점수 |
|---|---|---|
| Content-Length 헤더와 실제 본문 바이트 불일치 | 위조/스머글링 시도 | +10 |
| User-Agent 누락 | 정상 브라우저는 항상 전송 | +3 |
| 브라우저 UA + Accept-Language 누락 | 자동화 도구가 흔히 누락 | +4 |
| 브라우저 UA + 헤더 6개 미만 + 쿠키 없음 | 최소 헤더 자동화 | +2.5 |
| 첫 헤더가 Host가 아님 (브라우저 UA) | 정상 브라우저 송신 패턴 위반 | +2 |
| 같은 클라이언트 50ms 미만 연속 호출 (warmup 후) | 봇 리듬 | +6 |
| 클라이언트 간격 z-score > 4 | 변동 패턴 이탈 | +α |

`score >= ghost.threshold` (기본 5.0)면 403.

## 구성요소

- `Fingerprint` — 헤더 이름 순열 + UA 쉐입 + Accept-Language·Cookie 유무를 SHA-1로 압축
- `Profile` — 클라이언트별/지문별 요청 간격의 Welford 평균·분산 누적
- `AnomalyDetector` — 요청 1건의 점수와 사유를 산출
- `DetectionFilter` — `OncePerRequestFilter`로 `/api/**` 경로 검사

## 빌드 및 실행

```bash
mvn test                  # 8건 테스트
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

# Content-Length 위조 → 403
curl -i 'http://localhost:8110/api/protected' \
  -H 'Content-Length: 100' -H 'X-Declared-Body-Bytes: 1' \
  -H 'X-Client-Token: dave'
```

응답에는 항상 `X-Ghost-Score`, `X-Ghost-Fingerprint`가 붙고, 차단 시 `X-Ghost-Reasons`도 함께 전송된다.

## 테스트 (8건)

| 케이스 | 검증 |
|---|---|
| `normal_browser_sequence_passes` | 800ms 간격 10회 정상 통과 |
| `curl_like_with_minimal_headers_does_not_trigger_browser_rules` | curl는 브라우저 룰 비대상 |
| `browser_ua_without_accept_language_is_flagged` | Chrome UA + AL 결손 → 차단 |
| `content_length_mismatch_is_blocked` | 헤더/본문 바이트 불일치 → 차단 |
| `burst_rhythm_after_warmup_is_flagged` | 5회 워밍업 후 5ms 간격 호출 → 차단 |
| `header_order_with_first_not_host_is_penalized` | 첫 헤더가 Host 아님 → 페널티 발생 |
| `same_browser_shape_yields_same_fingerprint` | 같은 형상은 같은 지문 |
| `different_ua_shapes_yield_different_fingerprints` | 다른 UA 카테고리는 다른 지문 |

`mvn test` → 8/8 pass.

## 의도적으로 보류한 항목

- TLS JA3/JA4 등 핸드셰이크 지문
- HTTP/2 프레임 시퀀스 분석
- 모델 영속화/관리 콘솔
- 다중 노드 공유 프로파일 스토어
- 자동 임계값 튜닝
