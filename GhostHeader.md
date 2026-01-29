# GhostHeader
### HTTP 요청 지문 기반 비정상 접근 탐지 서버

---

## 1. 프로젝트 개요

GhostHeader는 전통적인 IP, 토큰, CAPTCHA 중심의 웹 보안 방식에서 벗어나  
**HTTP 요청 자체의 구조적 특성(Request Fingerprint)** 을 기반으로  
비정상 접근(봇, 스크립트, 리플레이 공격)을 탐지·차단하는 서버를 구현하는 프로젝트이다.

본 프로젝트의 목적은 **“누가 요청했는가”가 아니라  
“이 요청은 정상 브라우저가 생성할 수 있는가”** 를 판단하는 것이다.

---

## 2. 배경 및 문제 정의

기존 웹 보안의 한계:
- IP 기반 차단은 프록시/봇넷에 취약
- User-Agent는 위조 가능
- CAPTCHA는 UX를 심각하게 저해
- JWT/세션은 탈취 이후 무력화

GhostHeader는 다음 질문에 답해야 한다:

> “정상적인 브라우저 요청과 자동화된 요청은  
> 정말로 구분 불가능한가?”

---

## 3. 핵심 아이디어

### Request Fingerprinting

각 HTTP 요청을 다음 요소로 분석한다:

- Header 순서 및 중복 여부
- Header 간 조합 패턴
- Content-Length ↔ 실제 Body 길이 차이
- Accept / Encoding 조합
- 요청 간 시간 간격 (Request Rhythm)
- HTTP/1.1 vs HTTP/2 특성 차이

이 정보들을 기반으로 요청을 **Canonical Form**으로 변환하고  
Fingerprint Vector를 생성한다.

---

## 4. 시스템 구조

1. Raw HTTP Request 수신
2. 요청 구조 정규화
3. Fingerprint 생성
4. 정상 요청 패턴 학습
5. 이상 요청 판별
6. 대응 전략 적용

---

## 5. 필수 구현 요구사항

### 서버
- Spring Boot 기반
- Servlet Filter 레벨에서 요청 처리
- 프레임워크 추상화 이전의 요청 정보 접근

### Fingerprint
- 단순 문자열 Hash ❌
- Feature Vector 형태로 저장
- Sliding Window 기반 통계 처리

### 대응 정책
- 차단(403)
- 지연 응답
- Decoy Response (가짜 정상 응답)

---

## 6. 제한 사항

- IP 기반 차단 로직 사용 금지
- CAPTCHA 사용 금지
- 외부 WAF 연동 금지
- “봇 차단 라이브러리” 사용 금지

---

## 7. 검증 방법

- 실제 브라우저 요청
- curl / ab / siege 요청
- 동일 UA + 다른 구조 요청 비교
- Replay 공격 시도

---

## 8. 평가 기준

- 요청 지문 설계의 논리성
- 오탐/미탐에 대한 설명 가능성
- 공격 시나리오 정의의 명확성
- 코드 구조의 계층 분리

---

## 9. 보너스 과제

- HTTP/2 프레임 특성 반영
- Fingerprint 시각화 도구
- 실시간 통계 대시보드

---

## 10. 결과물

- 소스 코드
- README
- 공격 시나리오 문서
- 테스트 로그
