"""
GLaDOS 自动签到脚本
支持多账号、多种推送渠道、重试机制、日志脱敏
"""
import os
import re
import sys
import time
import random
import hashlib
import hmac
import base64
import urllib.parse
import logging
from typing import List, Dict, Any, Tuple, Optional, Callable
from functools import wraps
import requests

# ==================== 日志配置 ====================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("GLaDOS")

# ==================== 配置 ====================
CHECKIN_URL = "https://glados.space/api/user/checkin"
STATUS_URL = "https://glados.space/api/user/status"
# 浏览器 UA 池（定期更新为当前主流 Chrome 版本，避免过时 UA 被识别为脚本）
UA_LIST = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
]
# sec-ch-ua 池，与 UA_LIST 一一对应（Chrome Client Hints）
SEC_CH_UA_LIST = [
    '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
    '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
    '"Google Chrome";v="152", "Not_A Brand";v="8", "Chromium";v="152"',
    '"Google Chrome";v="152", "Not_A Brand";v="8", "Chromium";v="152"',
]
SEC_CH_UA_PLATFORM_LIST = ['"macOS"', '"Windows"', '"macOS"', '"Windows"']
# API 请求头模板（POST /api/user/checkin 等 XHR 请求）
HEADERS_BASE = {
    "origin": "https://glados.space",
    "referer": "https://glados.space/console/checkin",
    "accept": "application/json, text/plain, */*",
    "accept-language": "zh-CN,zh;q=0.9",
    "sec-ch-ua-mobile": "?0",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}
# 页面请求头模板（GET /console/checkin 等文档导航请求）
PAGE_HEADERS = {
    "accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7"),
    "accept-language": "zh-CN,zh;q=0.9",
    "cache-control": "max-age=0",
    "sec-ch-ua-mobile": "?0",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}

PAYLOAD = {"token": "glados.space"}
TIMEOUT = (5, 15)  # (连接超时, 读取超时)
MAX_RETRY = 3
RETRY_MIN_WAIT = 2.0
RETRY_MAX_WAIT = 10.0
MIN_DELAY = 3.0
MAX_DELAY = 8.0
TELEGRAM_MAX_LENGTH = 4000
TELEGRAM_TRUNCATE_LENGTH = 3990
CONTENT_MAX_LENGTH = 3000
COOKIE_MASK_LENGTH = 10
COOKIE_MIN_LENGTH = 24
REPEAT_KEYWORDS = ("repeat", "already", "重复", "已签到", "签到过", "请勿")


# ==================== 工具函数 ====================
def _pick_ua() -> Tuple[str, str, str]:
    """随机选取一组匹配的 UA / sec-ch-ua / sec-ch-ua-platform。"""
    idx = random.randint(0, len(UA_LIST) - 1)
    return UA_LIST[idx], SEC_CH_UA_LIST[idx], SEC_CH_UA_PLATFORM_LIST[idx]


def build_api_headers(cookie: str) -> Dict[str, str]:
    """构建 API 请求头（签到等 XHR），随机 UA + 完整 Client Hints。"""
    ua, sec_ch_ua, sec_ch_ua_platform = _pick_ua()
    return {
        **HEADERS_BASE,
        "user-agent": ua,
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-platform": sec_ch_ua_platform,
        "cookie": cookie,
    }


def build_page_headers(cookie: str) -> Dict[str, str]:
    """构建页面请求头（文档导航），随机 UA + 完整 Client Hints。"""
    ua, sec_ch_ua, sec_ch_ua_platform = _pick_ua()
    return {
        **PAGE_HEADERS,
        "user-agent": ua,
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-platform": sec_ch_ua_platform,
        "cookie": cookie,
    }


def simulate_browse(session: requests.Session, cookie: str) -> None:
    """
    签到前先访问页面，模拟真实浏览器行为链路。
    真实用户会先 GET /console/checkin 加载页面，再点击签到按钮触发 POST。
    此步骤非关键路径，失败不影响签到流程。
    """
    headers = build_page_headers(cookie)
    try:
        session.get("https://glados.space/console/checkin",
                     headers=headers, timeout=TIMEOUT)
        time.sleep(random.uniform(2, 5))  # 模拟阅读页面后点击签到
    except Exception as e:
        logger.debug("模拟页面访问失败（非关键步骤）: %s", e)


def safe_json(resp: requests.Response) -> Dict[str, Any]:
    """安全解析 JSON 响应（用于推送等非关键路径，失败返回空字典）。"""
    try:
        return resp.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        return {}


def require_json(resp: requests.Response) -> Dict[str, Any]:
    """
    严格解析 JSON 响应（用于签到等核心请求路径）。
    非 JSON 响应抛异常进入重试。
    """
    try:
        return resp.json()
    except ValueError:
        snippet = (resp.text or "<空响应>")[:200]
        logger.debug(
            "非 JSON 响应 (status=%s, content-type=%s): %s",
            resp.status_code, resp.headers.get("Content-Type"), snippet,
        )
        raise


def mask_cookie(cookie: str) -> str:
    """Cookie 脱敏（只显示前后各10个字符）。长度不足时整体脱敏。"""
    if not cookie or len(cookie) <= COOKIE_MIN_LENGTH:
        return "***"
    return f"{cookie[:COOKIE_MASK_LENGTH]}...{cookie[-COOKIE_MASK_LENGTH:]}"


def mask_email(email: str) -> str:
    """邮箱脱敏：保留前两个字符和最后一个字符，中间用 *** 替代"""
    if not email or email == "unknown" or "@" not in email:
        return email
    try:
        name, domain = email.rsplit("@", 1)
        if not name:
            return email
        if len(name) <= 3:
            masked_name = "***"
        else:
            masked_name = f"{name[:2]}***{name[-1]}"
        return f"{masked_name}@{domain}"
    except Exception:
        return email


def safe_int_str(val: Any, default: str = "-") -> str:
    """安全将值转为整数字符串，失败时返回默认值"""
    try:
        return str(int(val))
    except (TypeError, ValueError):
        try:
            return str(int(float(val)))
        except (TypeError, ValueError):
            return default


def _escape_markdown(text: str) -> str:
    """转义 Markdown 特殊字符，防止外部文本破坏推送格式。"""
    if not text:
        return text
    for ch in ("\\", "`", "*", "_", "#", "[", "]"):
        text = text.replace(ch, f"\\{ch}")
    return text


def parse_earned_points(message: str) -> int:
    """
    从签到成功响应文本中解析本次获得的积分数。
    兼容中英文两种文案：
      - 英文： "Checkin success, got 1 points"
      - 中文： "已经签到成功，获得 1 点，请明天继续签到哦！"
    """
    if not message:
        return 0
    m = re.search(r"got\s+(\d+)\s+points?", message, re.IGNORECASE)
    if m:
        return int(m.group(1))
    m = re.search(r"获得\s*(\d+)\s*点", message)
    return int(m.group(1)) if m else 0


def validate_cookie(cookie: str) -> Tuple[bool, str]:
    """验证 Cookie 是否包含必要字段"""
    if not cookie or not cookie.strip():
        return False, "Cookie 为空"
    cookie = cookie.strip()
    keys = {part.split("=", 1)[0].strip() for part in cookie.split(";") if part.strip()}
    required = ["koa:sess", "koa:sess.sig", "gld:sess", "gld:sess.sig"]
    missing = [k for k in required if k not in keys]
    if missing:
        return False, f"Cookie 缺少必要字段: {', '.join(missing)}"
    return True, ""


def is_retryable(exc: Exception) -> bool:
    """
    判断异常是否可重试。
    - 网络层异常（超时/连接错误等 RequestException，非 HTTPError）：可重试；
    - HTTPError：仅 5xx 和 429 可重试，4xx 客户端错误不可重试；
    - 其它异常：不可重试。
    """
    if isinstance(exc, requests.exceptions.HTTPError):
        resp = getattr(exc, "response", None)
        status = getattr(resp, "status_code", 0) if resp is not None else 0
        if status == 429:
            return True
        return 500 <= status < 600
    if isinstance(exc, requests.exceptions.RequestException):
        return True
    return False


def retry_on_failure(max_retries: int = MAX_RETRY, min_wait: float = RETRY_MIN_WAIT,
                     max_wait: float = RETRY_MAX_WAIT):
    """重试装饰器（指数退避，仅对可重试异常重试）"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.RequestException as e:
                    last_exception = e
                    if attempt < max_retries and is_retryable(e):
                        wait_time = min(min_wait * (2 ** attempt), max_wait)
                        logger.warning("第 %d 次尝试失败: %s，%.1f秒后重试...",
                                       attempt + 1, e, wait_time)
                        time.sleep(wait_time)
                        continue
                    break
            raise last_exception  # type: ignore
        return wrapper
    return decorator


# ==================== 推送函数 ====================
def _push_request(
    name: str,
    url: str,
    *,
    json_payload: Optional[Dict[str, Any]] = None,
    data_payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    success_check: Callable[[Dict[str, Any], requests.Response], bool],
    fail_msg_keys: Tuple[str, ...] = ("message",),
) -> bool:
    """通用推送请求函数，返回是否推送成功。"""
    try:
        if json_payload is not None:
            r = requests.post(url, json=json_payload, headers=headers, timeout=TIMEOUT)
        else:
            r = requests.post(url, data=data_payload, headers=headers, timeout=TIMEOUT)
        if not r.ok:
            logger.warning("%s 推送失败: HTTP %d", name, r.status_code)
            return False
        resp = safe_json(r)
        if success_check(resp, r):
            logger.info("%s 推送成功", name)
            return True
        fail_msg = r.text
        for key in fail_msg_keys:
            if resp.get(key):
                fail_msg = resp[key]
                break
        if fail_msg and len(fail_msg) > 200:
            fail_msg = fail_msg[:200] + "...(已截断)"
        logger.warning("%s 推送失败: %s", name, fail_msg)
        return False
    except Exception as e:  # noqa: BLE001
        logger.warning("%s 推送异常: %s", name, e)
        return False


def push_deer(key: str, title: str, content: str) -> bool:
    """PushDeer 推送"""
    if not key:
        return False
    return _push_request(
        "PushDeer",
        "https://api2.pushdeer.com/message/push",
        json_payload={"pushkey": key, "text": f"{title}\n\n{content}", "type": "text"},
        success_check=lambda resp, r: r.ok and resp.get("code") == 0,
    )


def push_serverchan(key: str, title: str, content: str) -> bool:
    """Server酱推送"""
    if not key:
        return False
    return _push_request(
        "Server酱",
        f"https://sctapi.ftqq.com/{key}.send",
        data_payload={"title": title, "desp": content},
        success_check=lambda resp, r: r.ok and resp.get("code") == 0,
    )


def push_telegram(bot_token: str, chat_id: str, title: str, content: str) -> bool:
    """Telegram Bot 推送"""
    if not bot_token or not chat_id:
        return False
    text = f"{title}\n\n{content}"
    if len(text) > TELEGRAM_MAX_LENGTH:
        text = text[:TELEGRAM_TRUNCATE_LENGTH] + "\n..."
    return _push_request(
        "Telegram",
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        json_payload={"chat_id": chat_id, "text": text},
        success_check=lambda resp, r: r.ok and resp.get("ok"),
        fail_msg_keys=("description",),
    )


def push_pushplus(token: str, title: str, content: str) -> bool:
    """PushPlus 推送"""
    if not token:
        return False
    return _push_request(
        "PushPlus",
        "https://www.pushplus.plus/send",
        json_payload={"token": token, "title": title, "content": content, "template": "html"},
        success_check=lambda resp, r: r.ok and resp.get("code") == 200,
        fail_msg_keys=("msg",),
    )


def push_dingtalk(webhook_url: str, title: str, content: str) -> bool:
    """钉钉机器人推送（支持加签）"""
    if not webhook_url:
        return False
    secret = os.getenv("DINGTALK_SECRET", "")
    if secret:
        timestamp = str(round(time.time() * 1000))
        string_to_sign = f"{timestamp}\n{secret}"
        hmac_code = hmac.new(
            secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        separator = "&" if "?" in webhook_url else "?"
        webhook_url = f"{webhook_url}{separator}timestamp={timestamp}&sign={sign}"
    else:
        logger.warning(
            "DINGTALK_WEBHOOK 已配置，但 DINGTALK_SECRET 缺失："
            "将发送无签名请求（若机器人启用了加签校验会失败）"
        )
    return _push_request(
        "钉钉机器人",
        webhook_url,
        json_payload={
            "msgtype": "markdown",
            "markdown": {"title": _escape_markdown(title),
                         "text": f"### {_escape_markdown(title)}\n\n{_escape_markdown(content)}"},
        },
        headers={"Content-Type": "application/json"},
        success_check=lambda resp, r: r.ok and resp.get("errcode") == 0,
        fail_msg_keys=("errmsg",),
    )


def push_feishu(webhook_url: str, title: str, content: str) -> bool:
    """飞书机器人推送（支持加签）"""
    if not webhook_url:
        return False
    data: Dict[str, Any] = {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": _escape_markdown(title)},
                "template": "blue",
            },
            "elements": [{"tag": "markdown", "content": _escape_markdown(content)}],
        },
    }
    secret = os.getenv("FEISHU_SECRET", "")
    if secret:
        timestamp = str(round(time.time()))
        string_to_sign = f"{timestamp}\n{secret}"
        hmac_code = hmac.new(
            string_to_sign.encode("utf-8"), b"",
            digestmod=hashlib.sha256,
        ).digest()
        sign = base64.b64encode(hmac_code).decode("utf-8")
        data["timestamp"] = timestamp
        data["sign"] = sign
    else:
        logger.warning(
            "FEISHU_WEBHOOK 已配置，但 FEISHU_SECRET 缺失："
            "将发送无签名请求（若机器人启用了加签校验会失败）"
        )
    return _push_request(
        "飞书机器人",
        webhook_url,
        json_payload=data,
        headers={"Content-Type": "application/json"},
        success_check=lambda resp, r: r.ok and resp.get("code") == 0,
        fail_msg_keys=("msg",),
    )


def push_wecom_bot(webhook_url: str, title: str, content: str) -> bool:
    """企业微信机器人推送"""
    if not webhook_url:
        return False
    return _push_request(
        "企业微信机器人",
        webhook_url,
        json_payload={
            "msgtype": "markdown",
            "markdown": {"content": f"### {_escape_markdown(title)}\n\n{_escape_markdown(content)}"},
        },
        headers={"Content-Type": "application/json"},
        success_check=lambda resp, r: r.ok and resp.get("errcode") == 0,
        fail_msg_keys=("errmsg",),
    )


def push_yunhu(token: str, recv_id: str, title: str, content: str) -> bool:
    """云湖机器人推送"""
    if not token or not recv_id:
        return False
    recv_type = os.getenv("YUNHU_RECV_TYPE", "group")
    if recv_type not in ("group", "private"):
        logger.warning("YUNHU_RECV_TYPE 值 '%s' 非法，应为 'group' 或 'private'，使用默认值 'group'", recv_type)
        recv_type = "group"
    return _push_request(
        "云湖机器人",
        "https://chat-go.jwzhd.com/open-apis/v1/bot/send-message",
        json_payload={
            "token": token, "recvId": recv_id, "recvType": recv_type,
            "contentType": 1, "content": f"**{title}**\n\n{content}",
        },
        headers={"Content-Type": "application/json"},
        success_check=lambda resp, r: r.ok and resp.get("code") == 1,
        fail_msg_keys=("msg", "message"),
    )


# ==================== 推送渠道配置 ====================
PUSH_CHANNELS: List[Tuple[str, List[str], Callable[[str, str], bool]]] = [
    ("PushDeer", ["SENDKEY"],
     lambda t, c: push_deer(os.getenv("SENDKEY", ""), t, c)),
    ("Server酱", ["SERVERCHAN_KEY"],
     lambda t, c: push_serverchan(os.getenv("SERVERCHAN_KEY", ""), t, c)),
    ("Telegram", ["TG_BOT_TOKEN", "TG_CHAT_ID"],
     lambda t, c: push_telegram(os.getenv("TG_BOT_TOKEN", ""), os.getenv("TG_CHAT_ID", ""), t, c)),
    ("PushPlus", ["PUSHPLUS_TOKEN"],
     lambda t, c: push_pushplus(os.getenv("PUSHPLUS_TOKEN", ""), t, c)),
    ("钉钉机器人", ["DINGTALK_WEBHOOK"],
     lambda t, c: push_dingtalk(os.getenv("DINGTALK_WEBHOOK", ""), t, c)),
    ("飞书机器人", ["FEISHU_WEBHOOK"],
     lambda t, c: push_feishu(os.getenv("FEISHU_WEBHOOK", ""), t, c)),
    ("企业微信机器人", ["WECOM_BOT_WEBHOOK"],
     lambda t, c: push_wecom_bot(os.getenv("WECOM_BOT_WEBHOOK", ""), t, c)),
    ("云湖机器人", ["YUNHU_TOKEN", "YUNHU_RECV_ID"],
     lambda t, c: push_yunhu(os.getenv("YUNHU_TOKEN", ""), os.getenv("YUNHU_RECV_ID", ""), t, c)),
]


def push_all(title: str, content: str) -> Tuple[int, int]:
    """
    推送到所有已配置的通知渠道。
    返回 (成功数, 已配置数)。
    """
    results: List[Tuple[str, bool]] = []
    for name, env_vars, fn in PUSH_CHANNELS:
        if all(os.getenv(v, "").strip() for v in env_vars):
            try:
                ok_push = fn(title, content)
            except Exception as e:  # noqa: BLE001
                logger.warning("%s 推送异常: %s", name, e)
                ok_push = False
            results.append((name, bool(ok_push)))

    configured = [n for n, _ in results]
    success = sum(1 for _, ok_push in results if ok_push)
    if not configured:
        logger.warning("未配置任何推送服务，请在 Secrets 中设置至少一种推送渠道")
    else:
        logger.info("已推送至: %s（成功 %d/%d）", ", ".join(configured), success, len(configured))
    return success, len(configured)


# ==================== 签到逻辑 ====================
def classify_checkin(code: Any, message: str) -> str:
    """
    判断签到结果: ok / repeat / fail
    GLaDOS API: code=0 成功, code=1 已签到, 其他失败
    """
    try:
        code = int(code)
    except (TypeError, ValueError):
        code = -2
    if code == 0:
        return "ok"
    if code == 1:
        return "repeat"
    msg = (message or "").lower()
    if re.search(r"got\s+\d+\s+points?", msg):
        return "ok"
    if any(kw in msg for kw in REPEAT_KEYWORDS):
        return "repeat"
    return "fail"


@retry_on_failure()
def api_get(session: requests.Session, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """查询账号状态（带重试）"""
    r = session.get(url, headers=headers, timeout=TIMEOUT)
    r.raise_for_status()
    return require_json(r)


@retry_on_failure()
def checkin_request(session: requests.Session, headers: Dict[str, str]) -> Dict[str, Any]:
    """执行签到请求（带重试）"""
    r = session.post(CHECKIN_URL, headers=headers, json=PAYLOAD, timeout=TIMEOUT)
    r.raise_for_status()
    return require_json(r)


def checkin_account(
    session: requests.Session,
    cookie: str,
    index: int,
) -> Dict[str, Any]:
    """执行单个账号的签到，返回账号信息字典"""
    session.cookies.clear()  # 清除上一个账号的残留 Cookie，避免串扰

    # 签到前先模拟页面访问，建立完整的浏览器行为链路
    simulate_browse(session, cookie)

    # 构建 API 请求头（随机 UA + 完整 Client Hints + Fetch Metadata）
    headers = build_api_headers(cookie)

    email = "unknown"
    days = "-"
    status = ""
    result = "fail"

    try:
        # 1. 签到
        j = checkin_request(session, headers)
        code = j.get("code", -2)
        message = j.get("message", "")
        earned = parse_earned_points(message)
        result = classify_checkin(code, message)

        if result == "ok":
            status = f"✅ 成功 (+{earned}积分)"
        elif result == "repeat":
            status = "🔄 已签到"
        else:
            status = f"❌ 失败({message})"

        # 2. 查询账号状态（剩余天数、邮箱）
        try:
            s = api_get(session, STATUS_URL, headers)
            data = s.get("data") or {}
            email = data.get("email", email)
            if data.get("leftDays") is not None:
                days = f"{safe_int_str(data['leftDays'])} 天"
        except Exception as e:  # noqa: BLE001
            logger.warning("账号 %d 状态查询失败: %s", index, e)

    except Exception as e:  # noqa: BLE001
        logger.error("账号 %d 签到异常: %s", index, e)
        status = f"❌ 异常({type(e).__name__})"
        result = "fail"

    return {
        "index": index,
        "email": mask_email(email),
        "status": status,
        "result": result,
        "remaining_days": days,
    }


# ==================== 主流程 ====================
def main() -> int:
    # 随机启动延迟（0-30 分钟），避免 cron 精确定时被识别为自动化
    delay = random.uniform(0, 1800)
    logger.info("随机延迟 %.0f 秒后开始签到...", delay)
    time.sleep(delay)

    # 支持 ||| 或换行(\n)或 & 分隔多账号 Cookie；推荐使用 ||| 避免与 Cookie 值冲突
    raw = os.getenv("COOKIES", "")
    cookies = [c.strip() for c in re.split(r"\|\|\||[&\n]", raw) if c.strip()]

    if not cookies:
        push_all("GLaDOS 签到", "❌ 未检测到 COOKIES，请配置 GitHub Secrets")
        return 1

    logger.info("检测到 %d 个账号", len(cookies))

    ok = fail = repeat = 0
    lines = []

    with requests.Session() as session:
        for idx, cookie in enumerate(cookies, 1):
            # 验证 Cookie 格式，无效则跳过
            is_valid, error_msg = validate_cookie(cookie)
            if not is_valid:
                logger.warning("账号 %d Cookie 格式异常: %s", idx, error_msg)
                logger.warning("Cookie 片段: %s", mask_cookie(cookie))
                fail += 1
                lines.append(f"{idx}. [无效Cookie] | ❌ 失败({error_msg}) | 剩余:-")
                if idx < len(cookies):
                    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
                continue

            logger.info("正在处理账号 %d/%d...", idx, len(cookies))
            acc = checkin_account(session, cookie, idx)

            if acc["result"] == "ok":
                ok += 1
            elif acc["result"] == "repeat":
                repeat += 1
            else:
                fail += 1

            lines.append(f"{acc['index']}. {acc['email']} | {acc['status']} | 剩余:{acc['remaining_days']}")

            # 非最后一个账号时随机延迟
            if idx < len(cookies):
                time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

    title = f"GLaDOS 签到完成 ✅{ok} ❌{fail} 🔄{repeat}"
    content = "\n".join(lines)

    # 汇总内容过长时统一截断，避免部分推送渠道因超限静默失败
    if len(content) > CONTENT_MAX_LENGTH:
        content = content[:CONTENT_MAX_LENGTH] + "\n…(内容过长已截断)"

    logger.info("%s", "=" * 50)
    logger.info("%s", content)
    logger.info("%s", "=" * 50)

    pushed_success, pushed_configured = push_all(title, content)

    # 区分"业务失败"与"通知发送失败"
    if ok == 0 and repeat == 0 and len(cookies) > 0:
        logger.error("⚠️ 全部 %d 个账号签到失败", len(cookies))
        if pushed_configured > 0 and pushed_success == 0:
            logger.error("⚠️ 且已配置推送渠道但全部发送失败，无人收到通知")
        return 1
    if pushed_configured > 0 and pushed_success == 0:
        logger.warning("⚠️ 已配置推送渠道但全部发送失败，无人收到通知（不影响运行结果）")
    return 0


if __name__ == "__main__":
    sys.exit(main())