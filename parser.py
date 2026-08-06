#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Парсер Telegram-каналов и прокси-профилей.

Что делает этот скрипт:
1. Читает подписки из input.txt.
2. Достаёт из них профили и Telegram-каналы.
3. По Telegram берёт только сообщения за последние 7 дней.
4. Проводит жёсткую канонизацию и дедупликацию профилей.
5. Разрешает только endpoint'ы с IPv4.
6. Ведёт 7-дневный реестр profiles/protocols без дублей.
7. После истечения 7 дней полностью сбрасывает реестр.
8. Выполняет быструю speed-оценку для каждого профиля.
9. Сохраняет protocols.txt, best_channels.txt, bad_channels.txt, stats.json.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import math
import os
import random
import re
import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import aiohttp

try:
    import config
except ImportError:  # pragma: no cover
    config = None


# =============================================================================
# НАСТРОЙКИ
# =============================================================================

def cfg(name: str, default: Any) -> Any:
    return getattr(config, name, default) if config else default


OUTPUT_DIR = cfg('OUTPUT_DIR', 'output')
WRITE_MIRROR_FILES_TO_ROOT = cfg('WRITE_MIRROR_FILES_TO_ROOT', True)
OUTPUT_ENCODING = cfg('OUTPUT_ENCODING', 'utf-8')

LOG_LEVEL = cfg('LOG_LEVEL', 'INFO')
LOG_FILE = cfg('LOG_FILE', 'parser.log')

PROFILE_WINDOW_DAYS = int(cfg('PROFILE_WINDOW_DAYS', 7))
REGISTRY_RESET_DAYS = int(cfg('REGISTRY_RESET_DAYS', 7))
MERGE_WITH_PREVIOUS_REGISTRY = bool(cfg('MERGE_WITH_PREVIOUS_REGISTRY', True))

PROTOCOLS_FILE_NAME = cfg('PROTOCOLS_FILE', 'protocols.txt')
BEST_CHANNELS_FILE_NAME = cfg('BEST_CHANNELS_FILE', 'best_channels.txt')
BAD_CHANNELS_FILE_NAME = cfg('BAD_CHANNELS_FILE', 'bad_channels.txt')
STATS_FILE_NAME = cfg('STATS_FILE', 'stats.json')
PROTOCOLS_STATE_FILE_NAME = cfg('PROTOCOLS_STATE_FILE', 'protocols_state.json')

USER_AGENT = cfg('USER_AGENT', 'Mozilla/5.0')
SUBSCRIPTION_FETCH_TIMEOUT = float(cfg('SUBSCRIPTION_FETCH_TIMEOUT', 25))
TELEGRAM_FETCH_TIMEOUT = float(cfg('TELEGRAM_FETCH_TIMEOUT', 12))
SPEED_TEST_TIMEOUT = float(cfg('SPEED_TEST_TIMEOUT', 2.5))
MAX_CONCURRENT_SUBSCRIPTION_FETCHES = int(cfg('MAX_CONCURRENT_SUBSCRIPTION_FETCHES', 20))
MAX_CONCURRENT_TELEGRAM_FETCHES = int(cfg('MAX_CONCURRENT_TELEGRAM_FETCHES', 40))
MAX_CONCURRENT_SPEED_TESTS = int(cfg('MAX_CONCURRENT_SPEED_TESTS', 150))
TELEGRAM_MESSAGES_LIMIT = int(cfg('TELEGRAM_MESSAGES_LIMIT', 100))

SPEED_TEST_URL = cfg('SPEED_TEST_URL', 'http://speedtest.tele2.net/100KB.zip')
SPEED_TEST_FILE_SIZE_BYTES = int(cfg('SPEED_TEST_FILE_SIZE_BYTES', 102400))
SPEED_THRESHOLD_KBPS = float(cfg('SPEED_THRESHOLD_KBPS', 300.0))
MAX_REPORTED_SPEED_KBPS = float(cfg('MAX_REPORTED_SPEED_KBPS', 5000.0))
SPEED_TEST_STRATEGY = str(cfg('SPEED_TEST_STRATEGY', 'tcp_probe')).strip().lower()
MIN_BASE_SCORE_FOR_SPEED_PRIORITY = float(cfg('MIN_BASE_SCORE_FOR_SPEED_PRIORITY', 45.0))

SUPPORTED_PROTOCOLS = {p.lower() for p in cfg('SUPPORTED_PROTOCOLS', ['vless', 'vmess', 'trojan', 'ss', 'ssr', 'tuic', 'hy2', 'hysteria', 'hysteria2'])}
ALLOW_ONLY_IPV4 = bool(cfg('ALLOW_ONLY_IPV4', True))
REJECT_NON_PUBLIC_IPV4 = bool(cfg('REJECT_NON_PUBLIC_IPV4', True))
STRICT_QUERY_IP_CHECK = bool(cfg('STRICT_QUERY_IP_CHECK', True))
IP_LIKE_QUERY_KEYS = {str(x).lower() for x in cfg('IP_LIKE_QUERY_KEYS', ['ip', 'add', 'server', 'server_address', 'remote_addr'])}
IGNORED_QUERY_KEYS = {str(x).lower() for x in cfg('IGNORED_QUERY_KEYS', [])}
IGNORED_VMESS_KEYS = {str(x).lower() for x in cfg('IGNORED_VMESS_KEYS', [])}
ENABLE_STRICT_DEDUPLICATION = bool(cfg('ENABLE_STRICT_DEDUPLICATION', True))

BAD_CHANNELS_THRESHOLD = float(cfg('BAD_CHANNELS_THRESHOLD', 20.0))
STANDARD_PORTS = {str(x) for x in cfg('STANDARD_PORTS', ['443', '80', '8443', '2053', '2083', '2087', '2096', '8080'])}
SUSPICIOUS_HOST_PARTS = tuple(str(x).lower() for x in cfg('SUSPICIOUS_HOST_PARTS', []))
PROFILE_WEIGHTS = dict(cfg('PROFILE_WEIGHTS', {}))
CHANNEL_WEIGHTS = dict(cfg('CHANNEL_WEIGHTS', {}))
PROTOCOL_PATTERNS = dict(cfg('PROTOCOL_PATTERNS', {}))
TG_PATTERNS = list(cfg('TG_PATTERNS', []))
EXTRACT_DIRECT_PROFILES_FROM_SUBSCRIPTIONS = bool(cfg('EXTRACT_DIRECT_PROFILES_FROM_SUBSCRIPTIONS', True))
DEDUPLICATE_BY_ENDPOINT = bool(cfg('DEDUPLICATE_BY_ENDPOINT', True))
PROFILE_TAG_LENGTH = int(cfg('PROFILE_TAG_LENGTH', 7))
PROFILE_TAG_ALPHABET = str(cfg('PROFILE_TAG_ALPHABET', 'abcdefghijklmnopqrstuvwxyz0123456789'))

PROTOCOLS_FILE = os.path.join(OUTPUT_DIR, PROTOCOLS_FILE_NAME)
BEST_CHANNELS_FILE = os.path.join(OUTPUT_DIR, BEST_CHANNELS_FILE_NAME)
BAD_CHANNELS_FILE = os.path.join(OUTPUT_DIR, BAD_CHANNELS_FILE_NAME)
STATS_FILE = os.path.join(OUTPUT_DIR, STATS_FILE_NAME)
PROTOCOLS_STATE_FILE = os.path.join(OUTPUT_DIR, PROTOCOLS_STATE_FILE_NAME)

REGISTRY_VERSION = 2
DECORATIVE_KEYS = {'title', 'name', 'ps', 'remark', 'remarks', 'description', 'tag'}
HYSTERIA_SCHEMES = {'hy2', 'hysteria', 'hysteria2'}


# =============================================================================
# ЛОГИРОВАНИЕ
# =============================================================================

os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding=OUTPUT_ENCODING),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger('parser')


# =============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =============================================================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def dt_to_iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat() + 'Z'


def iso_to_dt(value: str) -> datetime:
    if value.endswith('Z'):
        value = value[:-1]
    return datetime.fromisoformat(value)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def b64decode_padded(data: str) -> bytes:
    compact = ''.join(data.strip().split())
    compact += '=' * (-len(compact) % 4)
    return base64.urlsafe_b64decode(compact.encode())


def b64encode_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def normalize_port(value: Any) -> Optional[str]:
    try:
        port = int(str(value).strip())
    except Exception:
        return None
    if 1 <= port <= 65535:
        return str(port)
    return None


def normalize_ipv4(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().strip('[]')
    if not text:
        return None
    if any(ch.isalpha() for ch in text):
        return None
    if ':' in text:
        return None
    try:
        ip = ipaddress.IPv4Address(text)
    except Exception:
        return None
    if REJECT_NON_PUBLIC_IPV4:
        if any([ip.is_private, ip.is_loopback, ip.is_multicast, ip.is_reserved, ip.is_link_local, ip.is_unspecified]):
            return None
    return str(ip)


def is_public_ipv4(value: Optional[str]) -> bool:
    return normalize_ipv4(value) is not None


def normalize_path(value: str) -> str:
    if not value:
        return ''
    return quote(unquote(value), safe='/%:@-._~!$&\'()*+,;=')


def strip_fragment(raw: str) -> str:
    return raw.split('#', 1)[0].strip().strip('"\'<>')


def clean_candidate(raw: str) -> str:
    cleaned = strip_fragment(raw)
    while cleaned and cleaned[-1] in '.,;)]}>':
        cleaned = cleaned[:-1]
    return cleaned


def safe_json_dumps(data: Dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(',', ':'), sort_keys=True)


def canonical_query_pairs(query: str) -> List[Tuple[str, str]]:
    items = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        k = key.strip()
        v = value.strip()
        if not k:
            continue
        if k.lower() in IGNORED_QUERY_KEYS:
            continue
        items.append((k, v))
    items.sort(key=lambda item: (item[0].lower(), item[1]))
    return items


def query_pairs_to_dict(pairs: Sequence[Tuple[str, str]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for k, v in pairs:
        result[k] = v
    return result


def validate_ip_like_query_values(pairs: Sequence[Tuple[str, str]]) -> bool:
    if not STRICT_QUERY_IP_CHECK:
        return True
    for key, value in pairs:
        if key.lower() in IP_LIKE_QUERY_KEYS and value:
            if not is_public_ipv4(value):
                return False
    return True


def cleaned_netloc(userinfo: str, host: str, port: str) -> str:
    if userinfo:
        return f"{quote(userinfo, safe=':@-._~!$&\'()*+,;=')}@{host}:{port}"
    return f'{host}:{port}'


def maybe_decode_subscription_content(content: str) -> str:
    text = content.strip()
    if not text:
        return content
    if any(proto in text.lower() for proto in ('vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'tuic://', 'hy2://', 'hysteria://', 'hysteria2://')):
        return content
    compact = ''.join(text.split())
    if len(compact) < 40 or not re.fullmatch(r'[A-Za-z0-9+/=_-]+', compact):
        return content
    try:
        decoded = b64decode_padded(compact).decode('utf-8', errors='ignore')
    except Exception:
        return content
    lowered = decoded.lower()
    if any(proto in lowered for proto in ('vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'tuic://', 'hy2://', 'hysteria://', 'hysteria2://', 't.me/', 'telegram.me/', 'tg://resolve')):
        return decoded
    return content


def make_output_tag(protocol: str) -> str:
    suffix = ''.join(random.choice(PROFILE_TAG_ALPHABET) for _ in range(PROFILE_TAG_LENGTH))
    return f'{protocol.upper()}-{suffix}'


def mirror_file_to_root(output_path: str, root_name: str) -> None:
    if not WRITE_MIRROR_FILES_TO_ROOT:
        return
    shutil.copyfile(output_path, root_name)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


# =============================================================================
# МОДЕЛИ
# =============================================================================

@dataclass
class ProtocolProfile:
    protocol: str
    scheme: str
    host: str
    port: str
    credential: str
    canonical_config: str
    identity_key: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_channel: str = ''
    first_seen_at: datetime = field(default_factory=utcnow)
    last_seen_at: datetime = field(default_factory=utcnow)
    quality_score: float = 0.0
    base_score: float = 0.0
    speed_kbps: float = 0.0
    speed_probe_ms: float = 0.0
    speed_method: str = SPEED_TEST_STRATEGY

    @property
    def canonical_key(self) -> str:
        return sha256_text(self.canonical_config)

    def metadata_richness(self) -> int:
        def _count(obj: Any) -> int:
            if isinstance(obj, dict):
                total = 0
                for key, value in obj.items():
                    if key in DECORATIVE_KEYS:
                        continue
                    total += _count(value)
                return total
            if isinstance(obj, list):
                return sum(_count(item) for item in obj)
            return 1 if str(obj).strip() else 0
        return _count(self.metadata)

    @property
    def endpoint_key(self) -> str:
        return f'{self.protocol}|{self.host}|{self.port}'

    def replacement_priority(self) -> Tuple[float, float, int, int, int]:
        return (
            self.base_score,
            self.speed_kbps,
            self.metadata_richness(),
            len(self.credential),
            1 if self.source_channel else 0,
        )

    def render_for_output(self) -> str:
        return f'{self.canonical_config}#{make_output_tag(self.protocol)}'

    def to_state_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['first_seen_at'] = dt_to_iso(self.first_seen_at)
        data['last_seen_at'] = dt_to_iso(self.last_seen_at)
        return data

    @classmethod
    def from_state_dict(cls, data: Dict[str, Any]) -> 'ProtocolProfile':
        payload = dict(data)
        payload['first_seen_at'] = iso_to_dt(payload['first_seen_at'])
        payload['last_seen_at'] = iso_to_dt(payload['last_seen_at'])
        return cls(**payload)


@dataclass
class TelegramChannel:
    username: str
    url: str
    profiles_count: int = 0
    quality_score: float = 0.0
    protocols_found: Dict[str, int] = field(default_factory=dict)
    last_updated: Optional[datetime] = None


# =============================================================================
# КАЧЕСТВО
# =============================================================================

class QualityEvaluator:
    @staticmethod
    def evaluate_profile_base(profile: ProtocolProfile, channel_protocols: Optional[Dict[str, int]] = None) -> float:
        score = float(PROFILE_WEIGHTS.get('base', 20.0))

        if is_public_ipv4(profile.host):
            score += float(PROFILE_WEIGHTS.get('ipv4_public', 15.0))

        if profile.port in STANDARD_PORTS:
            score += float(PROFILE_WEIGHTS.get('standard_port', 8.0))

        richness_bonus = min(profile.metadata_richness(), 12)
        score += min(richness_bonus, float(PROFILE_WEIGHTS.get('metadata_richness', 12.0)))

        clean_query_bonus = float(PROFILE_WEIGHTS.get('query_cleanliness', 10.0))
        if '?' not in profile.canonical_config:
            score += clean_query_bonus * 0.4
        else:
            score += clean_query_bonus

        if channel_protocols:
            diversity = min(len(channel_protocols), 5)
            score += min(diversity * 2.0, float(PROFILE_WEIGHTS.get('channel_protocol_diversity', 10.0)))

        return round(min(score, 75.0), 2)

    @staticmethod
    def apply_speed_bonus(base_score: float, speed_kbps: float) -> float:
        speed_weight = float(PROFILE_WEIGHTS.get('speed_bonus', 25.0))
        if speed_kbps <= 0:
            return 0.0
        if base_score < MIN_BASE_SCORE_FOR_SPEED_PRIORITY:
            return round(min(speed_weight * 0.20, speed_kbps / max(SPEED_THRESHOLD_KBPS, 1.0) * speed_weight * 0.20), 2)
        if speed_kbps >= SPEED_THRESHOLD_KBPS:
            return round(speed_weight, 2)
        return round((speed_kbps / SPEED_THRESHOLD_KBPS) * speed_weight, 2)

    @classmethod
    def finalize_profile(cls, profile: ProtocolProfile, channel_protocols: Optional[Dict[str, int]] = None) -> float:
        base_score = cls.evaluate_profile_base(profile, channel_protocols)
        profile.base_score = base_score
        bonus = cls.apply_speed_bonus(base_score, profile.speed_kbps)
        profile.quality_score = round(min(base_score + bonus, 100.0), 2)
        return profile.quality_score

    @staticmethod
    def evaluate_channel(channel: TelegramChannel, all_channels: List[TelegramChannel]) -> float:
        if not all_channels:
            return 0.0

        max_profiles = max((item.profiles_count for item in all_channels), default=1)
        score_profile_count = 0.0
        if channel.profiles_count > 0 and max_profiles > 0:
            score_profile_count = math.log1p(channel.profiles_count) / math.log1p(max_profiles)

        diversity = min(len(channel.protocols_found), 6) / 6.0

        freshness = 0.0
        if channel.last_updated:
            delta_days = max((utcnow() - channel.last_updated).days, 0)
            freshness = max(0.0, 1.0 - (delta_days / max(PROFILE_WINDOW_DAYS, 1)))

        validity = min(sum(channel.protocols_found.values()) / 20.0, 1.0)

        total = (
            score_profile_count * float(CHANNEL_WEIGHTS.get('profile_count', 0.35))
            + diversity * float(CHANNEL_WEIGHTS.get('protocol_diversity', 0.25))
            + freshness * float(CHANNEL_WEIGHTS.get('freshness', 0.20))
            + validity * float(CHANNEL_WEIGHTS.get('validity', 0.20))
        )
        return round(total * 100.0, 2)


# =============================================================================
# ПАРСИНГ ПРОФИЛЕЙ
# =============================================================================

class ProtocolParser:
    @classmethod
    def extract_protocols(cls, text: str, source_channel: str = '') -> List[ProtocolProfile]:
        decoded_text = maybe_decode_subscription_content(text)
        candidates = {decoded_text}
        if decoded_text != text:
            candidates.add(text)

        raw_links: set[str] = set()
        for chunk in candidates:
            for protocol, pattern in PROTOCOL_PATTERNS.items():
                if protocol not in SUPPORTED_PROTOCOLS:
                    continue
                for match in re.findall(pattern, chunk, flags=re.IGNORECASE):
                    raw_links.add(clean_candidate(match))

        profiles: List[ProtocolProfile] = []
        for raw in raw_links:
            profile = cls.parse(raw)
            if profile:
                profile.source_channel = source_channel
                profiles.append(profile)
        return profiles

    @classmethod
    def extract_telegram_channels(cls, text: str) -> Dict[str, str]:
        channels: Dict[str, str] = {}
        decoded_text = maybe_decode_subscription_content(text)
        chunks = {text, decoded_text}
        for chunk in chunks:
            for pattern in TG_PATTERNS:
                for match in re.findall(pattern, chunk, flags=re.IGNORECASE):
                    username = match.strip().lstrip('@')
                    if len(username) < 5:
                        continue
                    lower = username.lower()
                    channels.setdefault(lower, username)
        return channels

    @classmethod
    def parse(cls, raw: str) -> Optional[ProtocolProfile]:
        lowered = raw.lower()
        try:
            if lowered.startswith('vmess://'):
                return cls.parse_vmess(raw)
            if lowered.startswith('vless://'):
                return cls.parse_url_based(raw, 'vless')
            if lowered.startswith('trojan://'):
                return cls.parse_url_based(raw, 'trojan')
            if lowered.startswith('tuic://'):
                return cls.parse_url_based(raw, 'tuic')
            if lowered.startswith('hy2://') or lowered.startswith('hysteria://') or lowered.startswith('hysteria2://'):
                return cls.parse_url_based(raw, 'hy2')
            if lowered.startswith('ss://'):
                return cls.parse_ss(raw)
            if lowered.startswith('ssr://'):
                return cls.parse_ssr(raw)
        except Exception as exc:
            logger.debug('Ошибка парсинга профиля %s: %s', raw[:120], exc)
        return None

    @classmethod
    def parse_vmess(cls, raw: str) -> Optional[ProtocolProfile]:
        payload = strip_fragment(raw)[len('vmess://'):]
        decoded = b64decode_padded(payload).decode('utf-8', errors='ignore').strip()
        if not decoded:
            return None
        data = json.loads(decoded)
        host = normalize_ipv4(data.get('add') or data.get('server') or data.get('hostip'))
        port = normalize_port(data.get('port'))
        if not host or not port:
            return None

        normalized: Dict[str, Any] = {}
        for key, value in data.items():
            key_str = str(key)
            if key_str.lower() in IGNORED_VMESS_KEYS:
                continue
            if value is None:
                continue
            text = str(value).strip()
            if not text:
                continue
            normalized[key_str] = text

        normalized['add'] = host
        normalized['port'] = port

        for ip_key in ('add', 'server', 'hostip'):
            if ip_key in normalized and not is_public_ipv4(normalized[ip_key]):
                return None

        credential = str(normalized.get('id', '')).strip()
        if not credential:
            return None

        canonical_json = safe_json_dumps(normalized)
        canonical_config = 'vmess://' + b64encode_nopad(canonical_json.encode('utf-8'))
        identity_key = f"vmess|{host}|{port}|{credential}"
        return ProtocolProfile(
            protocol='vmess',
            scheme='vmess',
            host=host,
            port=port,
            credential=credential,
            canonical_config=canonical_config,
            identity_key=identity_key,
            metadata=normalized,
        )

    @classmethod
    def parse_url_based(cls, raw: str, protocol_group: str) -> Optional[ProtocolProfile]:
        base = strip_fragment(raw)
        parsed = urlsplit(base)
        host = normalize_ipv4(parsed.hostname)
        port = normalize_port(parsed.port)
        if not host or not port:
            return None

        if any(part in host.lower() for part in SUSPICIOUS_HOST_PARTS):
            return None

        pairs = canonical_query_pairs(parsed.query)
        if not validate_ip_like_query_values(pairs):
            return None

        raw_userinfo = parsed.netloc.rsplit('@', 1)[0] if '@' in parsed.netloc else ''
        userinfo = unquote(raw_userinfo)
        if not userinfo:
            return None

        scheme = 'hy2' if protocol_group == 'hy2' else protocol_group
        path = normalize_path(parsed.path)
        query = urlencode(pairs, doseq=True)
        netloc = cleaned_netloc(userinfo, host, port)
        canonical_config = urlunsplit((scheme, netloc, path, query, ''))
        identity_key = f"{protocol_group}|{host}|{port}|{userinfo}"

        return ProtocolProfile(
            protocol=protocol_group,
            scheme=scheme,
            host=host,
            port=port,
            credential=userinfo,
            canonical_config=canonical_config,
            identity_key=identity_key,
            metadata={
                'path': unquote(path),
                'query': query_pairs_to_dict(pairs),
            },
        )

    @classmethod
    def parse_ss(cls, raw: str) -> Optional[ProtocolProfile]:
        body = strip_fragment(raw)[len('ss://'):]
        query = ''
        if '?' in body:
            body, query = body.split('?', 1)
        decoded_body = None
        if '@' not in body:
            try:
                decoded_candidate = b64decode_padded(body).decode('utf-8', errors='ignore')
                if '@' in decoded_candidate:
                    decoded_body = decoded_candidate
            except Exception:
                decoded_body = None
        if decoded_body:
            body = decoded_body
        elif '@' in body:
            auth_part, host_part = body.split('@', 1)
            try:
                decoded_auth = b64decode_padded(auth_part).decode('utf-8', errors='ignore')
                if ':' in decoded_auth:
                    body = f'{decoded_auth}@{host_part}'
            except Exception:
                pass

        pseudo_url = 'ss://' + body + ('?' + query if query else '')
        parsed = urlsplit(pseudo_url)
        host = normalize_ipv4(parsed.hostname)
        port = normalize_port(parsed.port)
        if not host or not port:
            return None

        method = unquote(parsed.username or '')
        password = unquote(parsed.password or '')
        if not method or not password:
            return None

        pairs = canonical_query_pairs(parsed.query)
        if not validate_ip_like_query_values(pairs):
            return None

        userinfo = f'{method}:{password}'
        auth_b64 = b64encode_nopad(userinfo.encode('utf-8'))
        netloc = f'{auth_b64}@{host}:{port}'
        query_part = urlencode(pairs, doseq=True)
        canonical_config = urlunsplit(('ss', netloc, '', query_part, ''))
        identity_key = f'ss|{host}|{port}|{method}|{password}'
        return ProtocolProfile(
            protocol='ss',
            scheme='ss',
            host=host,
            port=port,
            credential=userinfo,
            canonical_config=canonical_config,
            identity_key=identity_key,
            metadata={'method': method, 'query': query_pairs_to_dict(pairs)},
        )

    @classmethod
    def parse_ssr(cls, raw: str) -> Optional[ProtocolProfile]:
        payload = strip_fragment(raw)[len('ssr://'):]
        decoded = b64decode_padded(payload).decode('utf-8', errors='ignore')
        if '/?' in decoded:
            head, query = decoded.split('/?', 1)
        else:
            head, query = decoded, ''

        parts = head.split(':')
        if len(parts) < 6:
            return None

        host = normalize_ipv4(parts[0])
        port = normalize_port(parts[1])
        if not host or not port:
            return None

        protocol_name = parts[2]
        method = parts[3]
        obfs = parts[4]
        password_raw = ':'.join(parts[5:])
        try:
            password = b64decode_padded(password_raw).decode('utf-8', errors='ignore')
        except Exception:
            password = password_raw
        if not password:
            return None

        pairs = canonical_query_pairs(query)
        if not validate_ip_like_query_values(pairs):
            return None

        canonical_head = ':'.join([
            host,
            port,
            protocol_name,
            method,
            obfs,
            b64encode_nopad(password.encode('utf-8')),
        ])
        query_part = urlencode(pairs, doseq=True)
        canonical_decoded = canonical_head + ('/?' + query_part if query_part else '')
        canonical_config = 'ssr://' + b64encode_nopad(canonical_decoded.encode('utf-8'))
        identity_key = f'ssr|{host}|{port}|{protocol_name}|{method}|{obfs}|{password}'
        return ProtocolProfile(
            protocol='ssr',
            scheme='ssr',
            host=host,
            port=port,
            credential=password,
            canonical_config=canonical_config,
            identity_key=identity_key,
            metadata={'protocol': protocol_name, 'method': method, 'obfs': obfs, 'query': query_pairs_to_dict(pairs)},
        )


# =============================================================================
# HTTP/TELEGRAM
# =============================================================================

class SubscriptionFetcher:
    HEADERS = {
        'User-Agent': USER_AGENT,
        'Accept': '*/*',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
    }

    @classmethod
    async def fetch_one(cls, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, url: str) -> Optional[str]:
        request_url = cls.normalize_url(url)
        try:
            async with semaphore:
                async with session.get(request_url, headers=cls.HEADERS, timeout=aiohttp.ClientTimeout(total=SUBSCRIPTION_FETCH_TIMEOUT)) as response:
                    if response.status != 200:
                        logger.warning('Подписка вернула HTTP %s: %s', response.status, request_url)
                        return None
                    text = await response.text(errors='ignore')
                    return text
        except Exception as exc:
            logger.warning('Ошибка при загрузке подписки %s: %s', request_url, exc)
            return None

    @staticmethod
    def normalize_url(url: str) -> str:
        normalized = url.strip()
        if 'github.com' in normalized and '/raw/' in normalized:
            return normalized.replace('github.com', 'raw.githubusercontent.com').replace('/raw/', '/')
        if 'github.com' in normalized and '/blob/' in normalized:
            return normalized.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
        return normalized

    @classmethod
    async def fetch_all(cls, urls: List[str]) -> Dict[str, str]:
        connector = aiohttp.TCPConnector(ssl=False, limit=MAX_CONCURRENT_SUBSCRIPTION_FETCHES)
        timeout = aiohttp.ClientTimeout(total=SUBSCRIPTION_FETCH_TIMEOUT)
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_SUBSCRIPTION_FETCHES)
        results: Dict[str, str] = {}
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [cls.fetch_one(session, semaphore, url) for url in urls]
            responses = await asyncio.gather(*tasks)
        for url, content in zip(urls, responses):
            if content:
                results[url] = content
        return results


class TelegramChannelFetcher:
    ENDPOINTS = [
        'https://tg.i-c-a.su/r/{channel}/{limit}',
    ]

    @classmethod
    async def fetch_channel_messages(cls, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, channel: str) -> List[str]:
        cutoff = utcnow() - timedelta(days=PROFILE_WINDOW_DAYS)
        messages: List[str] = []
        async with semaphore:
            for endpoint in cls.ENDPOINTS:
                url = endpoint.format(channel=channel, limit=TELEGRAM_MESSAGES_LIMIT)
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=TELEGRAM_FETCH_TIMEOUT)) as response:
                        if response.status != 200:
                            continue
                        data = await response.json(content_type=None)
                        messages = cls.extract_messages(data, cutoff)
                        if messages:
                            return messages
                except Exception:
                    continue
        return messages

    @staticmethod
    def extract_messages(data: Any, cutoff: datetime) -> List[str]:
        result: List[str] = []
        if isinstance(data, dict):
            if 'messages' in data and isinstance(data['messages'], list):
                iterable = data['messages']
            elif 'result' in data and isinstance(data['result'], list):
                iterable = data['result']
            else:
                iterable = []
        elif isinstance(data, list):
            iterable = data
        else:
            iterable = []

        for item in iterable:
            if not isinstance(item, dict):
                continue
            item_dt: Optional[datetime] = None
            if 'date' in item:
                try:
                    if isinstance(item['date'], (int, float)):
                        item_dt = datetime.utcfromtimestamp(item['date'])
                    elif isinstance(item['date'], str):
                        item_dt = iso_to_dt(item['date'].replace(' ', 'T').replace('+00:00', ''))
                except Exception:
                    item_dt = None
            if item_dt and item_dt < cutoff:
                continue
            text = item.get('text') or item.get('message') or ''
            if isinstance(text, list):
                text = ' '.join(str(x) for x in text)
            text = str(text).strip()
            if text:
                result.append(text)
        return result


# =============================================================================
# SPEED TEST
# =============================================================================

class SpeedTester:
    def __init__(self) -> None:
        self.cache: Dict[str, Tuple[float, float]] = {}

    async def evaluate_profiles(self, profiles: Iterable[ProtocolProfile]) -> None:
        if SPEED_TEST_STRATEGY == 'disabled':
            logger.info('Speed-test отключён настройкой SPEED_TEST_STRATEGY=disabled')
            return
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_SPEED_TESTS)
        tasks = [self._test_profile(semaphore, profile) for profile in profiles]
        await asyncio.gather(*tasks)

    async def _test_profile(self, semaphore: asyncio.Semaphore, profile: ProtocolProfile) -> None:
        cache_key = f'{profile.host}:{profile.port}'
        cached = self.cache.get(cache_key)
        if cached:
            profile.speed_kbps, profile.speed_probe_ms = cached
            return

        async with semaphore:
            speed_kbps, probe_ms = await self._tcp_probe(profile.host, int(profile.port))
            self.cache[cache_key] = (speed_kbps, probe_ms)
            profile.speed_kbps = speed_kbps
            profile.speed_probe_ms = probe_ms

    async def _tcp_probe(self, host: str, port: int) -> Tuple[float, float]:
        started = time.perf_counter()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=SPEED_TEST_TIMEOUT)
            elapsed = max(time.perf_counter() - started, 0.001)
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            speed_kbps = min((SPEED_TEST_FILE_SIZE_BYTES / 1024.0) / elapsed, MAX_REPORTED_SPEED_KBPS)
            return round(speed_kbps, 2), round(elapsed * 1000.0, 2)
        except Exception:
            return 0.0, 0.0
        finally:
            if writer and not writer.is_closing():
                writer.close()


# =============================================================================
# РЕЕСТР 7-ДНЕВНОГО ОКНА
# =============================================================================

class RollingRegistry:
    def __init__(self) -> None:
        self.window_started_at = utcnow()
        self.profiles: Dict[str, ProtocolProfile] = {}
        self.identity_map: Dict[str, str] = {}
        self.endpoint_map: Dict[str, str] = {}

    def load(self) -> None:
        if not MERGE_WITH_PREVIOUS_REGISTRY or not os.path.exists(PROTOCOLS_STATE_FILE):
            return
        try:
            with open(PROTOCOLS_STATE_FILE, 'r', encoding=OUTPUT_ENCODING) as fh:
                payload = json.load(fh)
        except Exception as exc:
            logger.warning('Не удалось загрузить protocols_state.json: %s', exc)
            return

        if payload.get('version') != REGISTRY_VERSION:
            logger.info('Версия реестра изменилась — будет выполнен полный сброс окна')
            return

        try:
            window_started_at = iso_to_dt(payload['window_started_at'])
        except Exception:
            return

        if utcnow() - window_started_at >= timedelta(days=REGISTRY_RESET_DAYS):
            logger.info('Окно реестра старше %s дней — выполняется полный сброс', REGISTRY_RESET_DAYS)
            return

        self.window_started_at = window_started_at
        cutoff = utcnow() - timedelta(days=PROFILE_WINDOW_DAYS)
        kept = 0
        for item in payload.get('profiles', []):
            try:
                profile = ProtocolProfile.from_state_dict(item)
            except Exception:
                continue
            if profile.last_seen_at < cutoff:
                continue
            if not is_public_ipv4(profile.host):
                continue
            self._upsert(profile, allow_timestamp_update=False)
            kept += 1
        logger.info('Из предыдущего 7-дневного окна восстановлено %s профилей', kept)

    def merge(self, profiles: Iterable[ProtocolProfile]) -> None:
        for profile in profiles:
            self._upsert(profile, allow_timestamp_update=True)

    def _upsert(self, profile: ProtocolProfile, allow_timestamp_update: bool) -> None:
        if not ENABLE_STRICT_DEDUPLICATION:
            self.profiles[profile.canonical_key] = profile
            self.identity_map[profile.identity_key] = profile.canonical_key
            self.endpoint_map[profile.endpoint_key] = profile.canonical_key
            return

        canonical_key = profile.canonical_key
        existing = self.profiles.get(canonical_key)
        if existing:
            if allow_timestamp_update:
                existing.last_seen_at = max(existing.last_seen_at, profile.last_seen_at)
            if profile.replacement_priority() > existing.replacement_priority():
                profile.first_seen_at = min(existing.first_seen_at, profile.first_seen_at)
                profile.last_seen_at = max(existing.last_seen_at, profile.last_seen_at)
                self.profiles[canonical_key] = profile
            return

        existing_by_identity_key = self.identity_map.get(profile.identity_key)
        if existing_by_identity_key and existing_by_identity_key in self.profiles:
            incumbent = self.profiles[existing_by_identity_key]
            if profile.replacement_priority() > incumbent.replacement_priority():
                profile.first_seen_at = min(incumbent.first_seen_at, profile.first_seen_at)
                profile.last_seen_at = max(incumbent.last_seen_at, profile.last_seen_at)
                del self.profiles[existing_by_identity_key]
                self.profiles[canonical_key] = profile
                self.identity_map[profile.identity_key] = canonical_key
                self.endpoint_map[profile.endpoint_key] = canonical_key
            else:
                if allow_timestamp_update:
                    incumbent.last_seen_at = max(incumbent.last_seen_at, profile.last_seen_at)
            return

        if DEDUPLICATE_BY_ENDPOINT:
            existing_by_endpoint_key = self.endpoint_map.get(profile.endpoint_key)
            if existing_by_endpoint_key and existing_by_endpoint_key in self.profiles:
                incumbent = self.profiles[existing_by_endpoint_key]
                if profile.replacement_priority() > incumbent.replacement_priority():
                    profile.first_seen_at = min(incumbent.first_seen_at, profile.first_seen_at)
                    profile.last_seen_at = max(incumbent.last_seen_at, profile.last_seen_at)
                    del self.profiles[existing_by_endpoint_key]
                    self.profiles[canonical_key] = profile
                    self.identity_map[profile.identity_key] = canonical_key
                    self.endpoint_map[profile.endpoint_key] = canonical_key
                else:
                    if allow_timestamp_update:
                        incumbent.last_seen_at = max(incumbent.last_seen_at, profile.last_seen_at)
                return

        self.profiles[canonical_key] = profile
        self.identity_map[profile.identity_key] = canonical_key
        self.endpoint_map[profile.endpoint_key] = canonical_key

    def save(self) -> None:
        ensure_dir(OUTPUT_DIR)
        payload = {
            'version': REGISTRY_VERSION,
            'window_started_at': dt_to_iso(self.window_started_at),
            'saved_at': dt_to_iso(utcnow()),
            'profiles': [profile.to_state_dict() for profile in self.profiles.values()],
        }
        with open(PROTOCOLS_STATE_FILE, 'w', encoding=OUTPUT_ENCODING) as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)


# =============================================================================
# ОСНОВНОЙ ПАРСЕР
# =============================================================================

class Parser:
    def __init__(self, input_file: str = 'input.txt') -> None:
        self.input_file = input_file
        self.subscriptions: Dict[str, str] = {}
        self.channels: Dict[str, TelegramChannel] = {}
        self.current_profiles: Dict[str, ProtocolProfile] = {}
        self.current_identity_map: Dict[str, str] = {}
        self.current_endpoint_map: Dict[str, str] = {}
        self.registry = RollingRegistry()
        self.speed_tester = SpeedTester()
        self.stats: Dict[str, Any] = {
            'input_subscriptions': 0,
            'loaded_subscriptions': 0,
            'channels_found': 0,
            'profiles_before_registry_merge': 0,
            'profiles_after_registry_merge': 0,
            'profiles_by_protocol': {},
            'speed_test_url': SPEED_TEST_URL,
            'speed_test_strategy': SPEED_TEST_STRATEGY,
            'generated_at': dt_to_iso(utcnow()),
        }

    def load_subscriptions(self) -> List[str]:
        if not os.path.exists(self.input_file):
            logger.error('Файл %s не найден', self.input_file)
            return []
        with open(self.input_file, 'r', encoding=OUTPUT_ENCODING) as fh:
            urls = [line.strip() for line in fh if line.strip() and not line.lstrip().startswith('#')]
        self.stats['input_subscriptions'] = len(urls)
        logger.info('Загружено подписок: %s', len(urls))
        return urls

    def register_profile(self, profile: ProtocolProfile) -> None:
        profile.last_seen_at = utcnow()
        if not profile.first_seen_at:
            profile.first_seen_at = profile.last_seen_at

        if not is_public_ipv4(profile.host):
            return

        canonical_key = profile.canonical_key
        existing = self.current_profiles.get(canonical_key)
        if existing:
            if profile.replacement_priority() > existing.replacement_priority():
                profile.first_seen_at = min(existing.first_seen_at, profile.first_seen_at)
                profile.last_seen_at = max(existing.last_seen_at, profile.last_seen_at)
                self.current_profiles[canonical_key] = profile
            return

        existing_by_identity = self.current_identity_map.get(profile.identity_key)
        if existing_by_identity and existing_by_identity in self.current_profiles:
            incumbent = self.current_profiles[existing_by_identity]
            if profile.replacement_priority() > incumbent.replacement_priority():
                profile.first_seen_at = min(incumbent.first_seen_at, profile.first_seen_at)
                profile.last_seen_at = max(incumbent.last_seen_at, profile.last_seen_at)
                del self.current_profiles[existing_by_identity]
                self.current_profiles[canonical_key] = profile
                self.current_identity_map[profile.identity_key] = canonical_key
                self.current_endpoint_map[profile.endpoint_key] = canonical_key
            return

        if DEDUPLICATE_BY_ENDPOINT:
            existing_by_endpoint = self.current_endpoint_map.get(profile.endpoint_key)
            if existing_by_endpoint and existing_by_endpoint in self.current_profiles:
                incumbent = self.current_profiles[existing_by_endpoint]
                if profile.replacement_priority() > incumbent.replacement_priority():
                    profile.first_seen_at = min(incumbent.first_seen_at, profile.first_seen_at)
                    profile.last_seen_at = max(incumbent.last_seen_at, profile.last_seen_at)
                    del self.current_profiles[existing_by_endpoint]
                    self.current_profiles[canonical_key] = profile
                    self.current_identity_map[profile.identity_key] = canonical_key
                    self.current_endpoint_map[profile.endpoint_key] = canonical_key
                return

        self.current_profiles[canonical_key] = profile
        self.current_identity_map[profile.identity_key] = canonical_key
        self.current_endpoint_map[profile.endpoint_key] = canonical_key

    async def process(self) -> None:
        logger.info('Старт парсинга')
        urls = self.load_subscriptions()
        if not urls:
            logger.error('Нет входных подписок')
            return

        self.registry.load()

        logger.info('Загрузка подписок...')
        self.subscriptions = await SubscriptionFetcher.fetch_all(urls)
        self.stats['loaded_subscriptions'] = len(self.subscriptions)

        logger.info('Извлечение профилей и Telegram-каналов из подписок...')
        for content in self.subscriptions.values():
            if EXTRACT_DIRECT_PROFILES_FROM_SUBSCRIPTIONS:
                for profile in ProtocolParser.extract_protocols(content):
                    self.register_profile(profile)
            for lower, original in ProtocolParser.extract_telegram_channels(content).items():
                self.channels.setdefault(lower, TelegramChannel(username=original, url=f'https://t.me/{original}'))

        self.stats['channels_found'] = len(self.channels)
        logger.info('Найдено каналов: %s', len(self.channels))
        logger.info('Найдено уникальных профилей до Telegram/реестра: %s', len(self.current_profiles))

        if self.channels:
            await self.process_telegram_channels()

        self.stats['profiles_before_registry_merge'] = len(self.current_profiles)

        logger.info('Быстрая speed-оценка профилей...')
        await self.speed_tester.evaluate_profiles(self.current_profiles.values())

        logger.info('Финальная оценка профилей...')
        for profile in self.current_profiles.values():
            channel_protocols = None
            if profile.source_channel:
                channel_obj = self.channels.get(profile.source_channel.lower())
                if channel_obj:
                    channel_protocols = channel_obj.protocols_found
            QualityEvaluator.finalize_profile(profile, channel_protocols)

        logger.info('Объединение с 7-дневным реестром...')
        self.registry.merge(self.current_profiles.values())
        self.stats['profiles_after_registry_merge'] = len(self.registry.profiles)

        logger.info('Переоценка merged-профилей и каналов...')
        for profile in self.registry.profiles.values():
            channel_protocols = None
            if profile.source_channel:
                channel_obj = self.channels.get(profile.source_channel.lower())
                if channel_obj:
                    channel_protocols = channel_obj.protocols_found
            QualityEvaluator.finalize_profile(profile, channel_protocols)

        self.evaluate_channels()
        self.save_results()
        self.registry.save()
        logger.info('Готово')

    async def process_telegram_channels(self) -> None:
        connector = aiohttp.TCPConnector(ssl=False, limit=MAX_CONCURRENT_TELEGRAM_FETCHES)
        timeout = aiohttp.ClientTimeout(total=TELEGRAM_FETCH_TIMEOUT)
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TELEGRAM_FETCHES)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [TelegramChannelFetcher.fetch_channel_messages(session, semaphore, channel.username) for channel in self.channels.values()]
            results = await asyncio.gather(*tasks)

        for channel, messages in zip(self.channels.values(), results):
            if not messages:
                continue
            text = '\n'.join(messages)
            parsed_profiles = ProtocolParser.extract_protocols(text, source_channel=channel.username)
            if not parsed_profiles:
                continue
            unique_for_channel: set[str] = set()
            for profile in parsed_profiles:
                self.register_profile(profile)
                unique_for_channel.add(profile.canonical_key)
                channel.protocols_found[profile.protocol] = channel.protocols_found.get(profile.protocol, 0) + 1
            channel.profiles_count = len(unique_for_channel)
            channel.last_updated = utcnow()

    def evaluate_channels(self) -> None:
        channels_list = list(self.channels.values())
        for channel in channels_list:
            channel.quality_score = QualityEvaluator.evaluate_channel(channel, channels_list)

    def save_results(self) -> None:
        ensure_dir(OUTPUT_DIR)

        sorted_profiles = sorted(
            self.registry.profiles.values(),
            key=lambda p: (p.quality_score, p.speed_kbps, p.base_score, p.metadata_richness()),
            reverse=True,
        )

        with open(PROTOCOLS_FILE, 'w', encoding=OUTPUT_ENCODING) as fh:
            fh.write('# Уникальные профили за текущее 7-дневное окно\n')
            fh.write(f'# Всего профилей: {len(sorted_profiles)}\n')
            fh.write(f'# Окно начато: {dt_to_iso(self.registry.window_started_at)}\n')
            fh.write(f'# Дата генерации: {dt_to_iso(utcnow())}\n')
            fh.write(f'# Скоростной тест: {SPEED_TEST_STRATEGY}\n')
            fh.write(f'# Тестовый файл: {SPEED_TEST_URL}\n')
            fh.write(f'# Порог speed bonus: {SPEED_THRESHOLD_KBPS} KB/s\n')
            fh.write('# Формат: protocol://...#PROTOCOL-xxxxxxx\n\n')
            for profile in sorted_profiles:
                fh.write(profile.render_for_output() + '\n')
        mirror_file_to_root(PROTOCOLS_FILE, PROTOCOLS_FILE_NAME)

        sorted_channels = sorted(self.channels.values(), key=lambda c: (c.quality_score, c.profiles_count), reverse=True)
        best_channels = [channel for channel in sorted_channels if channel.quality_score >= BAD_CHANNELS_THRESHOLD]
        bad_channels = [channel for channel in sorted_channels if channel.quality_score < BAD_CHANNELS_THRESHOLD]

        with open(BEST_CHANNELS_FILE, 'w', encoding=OUTPUT_ENCODING) as fh:
            for channel in best_channels:
                fh.write(channel.url + '\n')
        mirror_file_to_root(BEST_CHANNELS_FILE, BEST_CHANNELS_FILE_NAME)

        with open(BAD_CHANNELS_FILE, 'w', encoding=OUTPUT_ENCODING) as fh:
            for channel in bad_channels:
                fh.write(channel.url + '\n')
        mirror_file_to_root(BAD_CHANNELS_FILE, BAD_CHANNELS_FILE_NAME)

        profiles_by_protocol: Dict[str, int] = {}
        for profile in sorted_profiles:
            profiles_by_protocol[profile.protocol] = profiles_by_protocol.get(profile.protocol, 0) + 1

        self.stats['profiles_by_protocol'] = profiles_by_protocol
        self.stats['best_channels_count'] = len(best_channels)
        self.stats['bad_channels_count'] = len(bad_channels)
        self.stats['window_started_at'] = dt_to_iso(self.registry.window_started_at)
        self.stats['generated_at'] = dt_to_iso(utcnow())

        with open(STATS_FILE, 'w', encoding=OUTPUT_ENCODING) as fh:
            json.dump(self.stats, fh, ensure_ascii=False, indent=2)
        mirror_file_to_root(STATS_FILE, STATS_FILE_NAME)

        logger.info('Сохранено профилей: %s', len(sorted_profiles))
        logger.info('Лучших каналов: %s | Плохих каналов: %s', len(best_channels), len(bad_channels))


async def main() -> None:
    parser = Parser('input.txt')
    await parser.process()


if __name__ == '__main__':
    asyncio.run(main())
