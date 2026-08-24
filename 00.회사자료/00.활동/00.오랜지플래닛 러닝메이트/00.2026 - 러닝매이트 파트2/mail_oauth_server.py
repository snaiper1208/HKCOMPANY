# -*- coding: utf-8 -*-
"""
==============================================================================
 다우 메일 MCP - OAuth 2.0 인증 서버 (Copilot Studio 연동용)
==============================================================================

[ 이 서버가 하는 일 ]
  Copilot Studio에서 "연결" 버튼을 누르면
    1) /authorize  -> 로그인 팝업이 뜸 (기존 /login 화면 재활용)
    2) 로그인 성공  -> 인증 코드(code)를 Copilot Studio로 돌려줌
    3) /token       -> code를 access_token + refresh_token 으로 교환
    4) 이후 도구 호출 -> Authorization: Bearer <token> 으로 본인 메일만 조회
    5) 토큰 만료 시  -> refresh_token 으로 자동 재발급 (로그인 다시 안 함)

[ 실행 방법 ]
  pip install "fastapi[all]" uvicorn itsdangerous
  python mail_oauth_server.py
  -> http://127.0.0.1:8090 에서 실행됨 (운영은 리버스 프록시로 https 연결)

[ Copilot Studio 설정값 ]
  인증        : OAuth 2.0
  구성 유형   : 수동
  권한 부여 URL : https://mcp.daedongmobility.co.kr/authorize
  토큰 URL      : https://mcp.daedongmobility.co.kr/token
  클라이언트 ID / 비밀 : 아래 REGISTERED_CLIENTS 값 사용
  범위(Scope)   : mail.read
==============================================================================
"""

import base64
import hashlib
import secrets
import sqlite3
import time
from typing import Optional

from fastapi import FastAPI, Form, Request, HTTPException, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

# ============================================================================
# 1. 기본 설정  (실제 운영 시 값만 바꾸면 됩니다)
# ============================================================================

# Copilot Studio 화면에 넣을 "클라이언트 ID / 클라이언트 비밀"
# 여러 개 등록 가능. 여기 값을 Copilot Studio 설정에 그대로 입력하세요.
REGISTERED_CLIENTS = {
    "copilot-studio": "super-secret-1234",   # {client_id: client_secret}
}

# Copilot Studio가 만들어 주는 redirect URI 를 여기에 등록해야 합니다.
# (연결 화면에서 "추가" 누르면 생성됨 -> 복사해서 아래 목록에 넣기)
ALLOWED_REDIRECT_URIS = {
    "https://global.consent.azure-apim.net/redirect",   # 예시 (실제 값으로 교체)
    "https://example.com/cb",                            # 로컬 테스트용
}

# 토큰 유효시간(초)
ACCESS_TOKEN_TTL = 3600          # access_token : 1시간
REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30   # refresh_token : 30일
AUTH_CODE_TTL = 300              # 인증 코드 : 5분

DB_PATH = "mail_oauth.db"

app = FastAPI(title="다우 메일 MCP OAuth 서버")


# ============================================================================
# 2. 데이터베이스 (SQLite) - 토큰/코드 저장
# ============================================================================

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        # 인증 코드 임시 저장 (5분 후 소멸)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_codes (
                code           TEXT PRIMARY KEY,
                username       TEXT NOT NULL,
                client_id      TEXT NOT NULL,
                redirect_uri   TEXT NOT NULL,
                code_challenge TEXT,
                expires_at     INTEGER NOT NULL
            )
        """)
        # 발급된 토큰 저장
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                access_token   TEXT PRIMARY KEY,
                refresh_token  TEXT NOT NULL,
                username       TEXT NOT NULL,
                client_id      TEXT NOT NULL,
                expires_at     INTEGER NOT NULL
            )
        """)
        conn.commit()


init_db()


# ============================================================================
# 3. 실제 메일 계정 인증 (여기만 본인 메일 시스템에 맞게 연결)
# ============================================================================

def verify_mail_login(username: str, password: str) -> bool:
    """
    사용자가 입력한 아이디/비밀번호가 맞는지 확인.
    실제로는 여기서 다우 메일 서버(IMAP/API 등)에 로그인 시도하면 됩니다.
    지금은 예시로 데모 계정만 통과시킵니다.
    """
    # --- 예시(데모) ---
    demo_accounts = {
        "hwan": "1234",
        "user@daedongmobility.co.kr": "pass",
    }
    return demo_accounts.get(username) == password

    # --- 실제 IMAP 연결 예시 (참고용) ---
    # import imaplib
    # try:
    #     m = imaplib.IMAP4_SSL("mail.daedongmobility.co.kr")
    #     m.login(username, password)
    #     m.logout()
    #     return True
    # except Exception:
    #     return False


def get_user_mails(username: str):
    """토큰으로 인증된 '본인' 메일만 조회. 실제 메일 시스템과 연결하세요."""
    # --- 예시(데모) 데이터 ---
    return [
        {"from": "notice@company.com", "subject": f"[{username}] 안녕하세요", "date": "2026-08-24"},
        {"from": "team@company.com",   "subject": "회의 일정 안내",          "date": "2026-08-23"},
    ]


# ============================================================================
# 4. 유틸 함수
# ============================================================================

def now() -> int:
    return int(time.time())


def new_token() -> str:
    return secrets.token_urlsafe(32)


def verify_pkce(code_challenge: Optional[str], code_verifier: Optional[str]) -> bool:
    """PKCE(S256) 검증. code_challenge가 없으면 검사 생략."""
    if not code_challenge:
        return True
    if not code_verifier:
        return False
    digest = hashlib.sha256(code_verifier.encode()).digest()
    calc = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return secrets.compare_digest(calc, code_challenge)


# ============================================================================
# 5. /authorize  ->  로그인 팝업 (기존 /login 화면 재활용)
# ============================================================================

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>다우 메일 로그인</title>
  <style>
    body {{ font-family: 'Pretendard', -apple-system, sans-serif; background:#111;
           display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
    .card {{ background:#1c1c1e; padding:40px; border-radius:16px; width:320px;
             box-shadow:0 10px 40px rgba(0,0,0,.5); }}
    h1 {{ color:#fff; font-size:20px; margin:0 0 4px; }}
    p  {{ color:#888; font-size:13px; margin:0 0 24px; }}
    input {{ width:100%; box-sizing:border-box; padding:12px 14px; margin-bottom:12px;
             border:1px solid #333; border-radius:10px; background:#000; color:#fff; font-size:14px; }}
    input:focus {{ outline:none; border-color:#FF4500; }}
    button {{ width:100%; padding:13px; border:none; border-radius:10px; background:#FF4500;
              color:#fff; font-size:15px; font-weight:600; cursor:pointer; }}
    button:hover {{ background:#e03e00; }}
    .err {{ color:#ff6b6b; font-size:13px; margin-bottom:12px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>다우 메일 로그인</h1>
    <p>메일 조회를 위해 로그인해 주세요.</p>
    {error}
    <form method="post" action="/authorize">
      <input type="text"     name="username" placeholder="아이디" autofocus required>
      <input type="password" name="password" placeholder="비밀번호" required>
      <!-- OAuth 파라미터를 그대로 다음 단계로 전달 -->
      <input type="hidden" name="client_id"      value="{client_id}">
      <input type="hidden" name="redirect_uri"   value="{redirect_uri}">
      <input type="hidden" name="state"          value="{state}">
      <input type="hidden" name="code_challenge" value="{code_challenge}">
      <input type="hidden" name="response_type"  value="code">
      <button type="submit">로그인</button>
    </form>
  </div>
</body>
</html>
"""


@app.get("/authorize", response_class=HTMLResponse)
def authorize_page(
    response_type: str = "code",
    client_id: str = "",
    redirect_uri: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "",
    scope: str = "",
):
    """
    [1단계] Copilot Studio가 이 주소로 사용자를 보냄 -> 로그인 팝업(HTML) 표시
    """
    # 클라이언트/리다이렉트 검증
    if client_id not in REGISTERED_CLIENTS:
        raise HTTPException(400, "알 수 없는 client_id 입니다.")
    if not _redirect_allowed(redirect_uri):
        raise HTTPException(400, "허용되지 않은 redirect_uri 입니다.")

    return LOGIN_PAGE.format(
        error="",
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
    )


@app.post("/authorize")
def authorize_submit(
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
    code_challenge: str = Form(""),
    response_type: str = Form("code"),
):
    """
    [2단계] 로그인 폼 제출 -> 계정 검증 -> 인증 코드 발급 -> Copilot Studio로 되돌려보냄
    """
    # 로그인 실패하면 에러 메시지와 함께 다시 폼 표시
    if not verify_mail_login(username, password):
        html = LOGIN_PAGE.format(
            error='<div class="err">아이디 또는 비밀번호가 올바르지 않습니다.</div>',
            client_id=client_id, redirect_uri=redirect_uri,
            state=state, code_challenge=code_challenge,
        )
        return HTMLResponse(html, status_code=401)

    # 로그인 성공 -> 인증 코드 생성 & 저장(5분 유효)
    code = new_token()
    with db() as conn:
        conn.execute(
            "INSERT INTO auth_codes VALUES (?,?,?,?,?,?)",
            (code, username, client_id, redirect_uri, code_challenge, now() + AUTH_CODE_TTL),
        )
        conn.commit()

    # redirect_uri?code=...&state=... 형태로 되돌려보냄 -> 팝업이 닫히고 자동 진행
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}"
    if state:
        location += f"&state={state}"
    return RedirectResponse(location, status_code=302)


# ============================================================================
# 6. /token  ->  code 를 access_token + refresh_token 으로 교환
# ============================================================================

@app.post("/token")
def token(
    grant_type: str = Form(...),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    code_verifier: str = Form(None),
    refresh_token: str = Form(None),
    authorization: Optional[str] = Header(None),
):
    """
    [3단계] Copilot Studio가 code를 토큰으로 바꾸는 곳.
      - grant_type=authorization_code : code -> 새 토큰 발급
      - grant_type=refresh_token      : 만료된 토큰 자동 갱신 (재로그인 X)
    """
    # 헤더(Basic)로 client 인증이 오는 경우도 지원
    client_id, client_secret = _resolve_client(authorization, client_id, client_secret)

    # 클라이언트 검증
    if REGISTERED_CLIENTS.get(client_id) != client_secret:
        return _oauth_error("invalid_client", "클라이언트 인증 실패", 401)

    # ---- (A) 최초 토큰 발급 ----
    if grant_type == "authorization_code":
        if not code:
            return _oauth_error("invalid_request", "code 가 없습니다.")

        with db() as conn:
            row = conn.execute("SELECT * FROM auth_codes WHERE code=?", (code,)).fetchone()
            if not row:
                return _oauth_error("invalid_grant", "유효하지 않은 code")
            if row["expires_at"] < now():
                conn.execute("DELETE FROM auth_codes WHERE code=?", (code,))
                conn.commit()
                return _oauth_error("invalid_grant", "만료된 code")
            # PKCE 검증
            if not verify_pkce(row["code_challenge"], code_verifier):
                return _oauth_error("invalid_grant", "PKCE 검증 실패")

            username = row["username"]
            # code는 1회용 -> 즉시 삭제
            conn.execute("DELETE FROM auth_codes WHERE code=?", (code,))
            conn.commit()

        return _issue_tokens(username, client_id)

    # ---- (B) 토큰 갱신 (자동, 재로그인 없음) ----
    elif grant_type == "refresh_token":
        if not refresh_token:
            return _oauth_error("invalid_request", "refresh_token 이 없습니다.")
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM tokens WHERE refresh_token=?", (refresh_token,)
            ).fetchone()
            if not row:
                return _oauth_error("invalid_grant", "유효하지 않은 refresh_token")
            username = row["username"]
            # 기존 access_token 삭제 후 새로 발급
            conn.execute("DELETE FROM tokens WHERE refresh_token=?", (refresh_token,))
            conn.commit()
        return _issue_tokens(username, client_id)

    return _oauth_error("unsupported_grant_type", f"지원하지 않는 grant_type: {grant_type}")


def _issue_tokens(username: str, client_id: str) -> JSONResponse:
    """새 access_token + refresh_token 을 만들어 DB에 저장하고 표준 형식으로 반환."""
    access = new_token()
    refresh = new_token()
    with db() as conn:
        conn.execute(
            "INSERT INTO tokens VALUES (?,?,?,?,?)",
            (access, refresh, username, client_id, now() + ACCESS_TOKEN_TTL),
        )
        conn.commit()
    return JSONResponse({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL,
        "refresh_token": refresh,
        "scope": "mail.read",
    })


# ============================================================================
# 7. 보호된 리소스 : 토큰으로 "본인" 메일만 조회
# ============================================================================

def get_current_user(authorization: Optional[str]) -> str:
    """Authorization: Bearer <token> 를 검증하고 사용자명을 돌려줌."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "토큰이 필요합니다.")
    token_value = authorization.split(" ", 1)[1].strip()
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM tokens WHERE access_token=?", (token_value,)
        ).fetchone()
    if not row:
        raise HTTPException(401, "유효하지 않은 토큰")
    if row["expires_at"] < now():
        raise HTTPException(401, "만료된 토큰 (refresh 필요)")
    return row["username"]


@app.get("/mails/search")
def search_mails(authorization: Optional[str] = Header(None), q: str = ""):
    """
    MCP 도구가 호출하는 메일 검색 API.
    토큰에 담긴 '본인' 메일만 조회됩니다.
    """
    username = get_current_user(authorization)
    mails = get_user_mails(username)
    if q:
        mails = [m for m in mails if q in m["subject"]]
    return {"user": username, "count": len(mails), "mails": mails}


@app.get("/whoami")
def whoami(authorization: Optional[str] = Header(None)):
    """토큰이 누구 것인지 확인용."""
    return {"user": get_current_user(authorization)}


# ============================================================================
# 8. (선택) 디스커버리 - '동적' 구성을 쓰고 싶을 때 자동 인식용
# ============================================================================

@app.get("/.well-known/oauth-authorization-server")
def discovery(request: Request):
    base = str(request.base_url).rstrip("/")
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "scopes_supported": ["mail.read"],
    }


# ============================================================================
# 9. 헬퍼
# ============================================================================

def _redirect_allowed(uri: str) -> bool:
    if not uri:
        return False
    # 정확히 일치하거나, 등록된 주소로 시작하면 허용 (Azure redirect는 뒤에 경로가 붙음)
    return any(uri == a or uri.startswith(a) for a in ALLOWED_REDIRECT_URIS)


def _resolve_client(authorization, client_id, client_secret):
    """client 인증이 Basic 헤더로 오면 디코딩해서 꺼냄."""
    if (not client_id) and authorization and authorization.lower().startswith("basic "):
        try:
            raw = base64.b64decode(authorization.split(" ", 1)[1]).decode()
            client_id, client_secret = raw.split(":", 1)
        except Exception:
            pass
    return client_id, client_secret


def _oauth_error(code: str, desc: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": code, "error_description": desc}, status_code=status)


# ============================================================================
# 10. 실행
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print(" 다우 메일 MCP OAuth 서버 시작")
    print(" http://127.0.0.1:8090")
    print(" 데모 계정: hwan / 1234")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8090)
