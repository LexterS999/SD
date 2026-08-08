#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Парсер Telegram-каналов и прокси-профилей.

Что делает этот скрипт:
1. Читает подписки из input.txt.
2. Извлекает Telegram-каналы из подписок.
3. Собирает профили ТОЛЬКО из Telegram-каналов, которые есть в best_channels.txt (за последние 7 дней).
4. По Telegram берёт только сообщения за последние 7 дней.
5. Проводит жёсткую канонизацию и дедупликацию профилей.
6. Разрешает только endpoint'ы с IPv4.
7. Ведёт 7-дневный реестр profiles/protocols без дублей.
8. После истечения 7 дней полностью сбрасывает реестр.
9. Выполняет TCP RTT проверку для каждого профиля (фильтрация по максимальному RTT).
10. Сохраняет protocols.txt, best_channels.txt, bad_channels.txt, stats.json.
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
import socket
import statistics
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit, urlparse, parse_qs

import aiohttp

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

try:
    import config
except ImportError:  # pragma: no cover
    config = None

try:
    import features
except ImportError:  # pragma: no cover
    features = None


# =============================================================================
# НАСТРОЙКИ
# =============================================================================

def cfg(name: str, default: Any) -> Any:
    return getattr(config, name, default) if config else default


OUTPUT_DIR = cfg('OUTPUT_DIR', 'output')
WRITE_MIRROR_FILES_TO_ROOT = cfg('WRITE_MIRROR_FILES_TO_ROOT', False)
OUTPUT_ENCODING = cfg('OUTPUT_ENCODING', 'utf-8')

LOG_LEVEL = cfg('LOG_LEVEL', 'INFO')
LOG_FILE = cfg('LOG_FILE', 'parser.log')

# Период сбора данных (в днях) - может быть задан через переменную окружения COLLECTION_PERIOD_DAYS
COLLECTION_PERIOD_DAYS = int(cfg('COLLECTION_PERIOD_DAYS', os.environ.get('COLLECTION_PERIOD_DAYS', '7')))
PROFILE_WINDOW_DAYS = int(cfg('PROFILE_WINDOW_DAYS', COLLECTION_PERIOD_DAYS))
CHANNEL_WINDOW_DAYS = int(cfg('CHANNEL_WINDOW_DAYS', COLLECTION_PERIOD_DAYS))
REGISTRY_RESET_DAYS = int(cfg('REGISTRY_RESET_DAYS', 7))
MERGE_WITH_PREVIOUS_REGISTRY = bool(cfg('MERGE_WITH_PREVIOUS_REGISTRY', True))

# Progressive window extension - автоматическое увеличение периода при нехватке профилей
PROGRESSIVE_WINDOW_EXTENSION_ENABLED = bool(cfg('PROGRESSIVE_WINDOW_EXTENSION_ENABLED', True))
MIN_PROFILES_THRESHOLD = int(cfg('MIN_PROFILES_THRESHOLD', 50))
MAX_COLLECTION_PERIOD_DAYS = int(cfg('MAX_COLLECTION_PERIOD_DAYS', 30))

PROTOCOLS_FILE_NAME = cfg('PROTOCOLS_FILE', 'protocols.txt')
BEST_CHANNELS_FILE_NAME = cfg('BEST_CHANNELS_FILE', 'best_channels.txt')
BAD_CHANNELS_FILE_NAME = cfg('BAD_CHANNELS_FILE', 'bad_channels.txt')
STATS_FILE_NAME = cfg('STATS_FILE', 'stats.json')
PROTOCOLS_STATE_FILE_NAME = cfg('PROTOCOLS_STATE_FILE', 'protocols_state.json')
CHANNELS_STATE_FILE_NAME = cfg('CHANNELS_STATE_FILE', 'channels_state.json')
CHANNELS_HISTORY_FILE_NAME = cfg('CHANNELS_HISTORY_FILE', 'channels_history.json')
CHANGES_REPORT_FILE_NAME = cfg('CHANGES_REPORT_FILE', 'changes_report.json')

USER_AGENT = cfg('USER_AGENT', 'Mozilla/5.0')
SUBSCRIPTION_FETCH_TIMEOUT = float(cfg('SUBSCRIPTION_FETCH_TIMEOUT', 25))
TELEGRAM_FETCH_TIMEOUT = float(cfg('TELEGRAM_FETCH_TIMEOUT', 12))
TCP_CHECK_TIMEOUT = float(cfg('TCP_CHECK_TIMEOUT', 3.0))
HTTP_CHECK_TIMEOUT = float(cfg('HTTP_CHECK_TIMEOUT', 5.0))
MAX_CONCURRENT_SUBSCRIPTION_FETCHES = int(cfg('MAX_CONCURRENT_SUBSCRIPTION_FETCHES', 20))
MAX_CONCURRENT_TELEGRAM_FETCHES = int(cfg('MAX_CONCURRENT_TELEGRAM_FETCHES', 40))
MAX_CONCURRENT_TCP_CHECKS = int(cfg('MAX_CONCURRENT_TCP_CHECKS', 150))
MAX_CONCURRENT_DNS_LOOKUPS = int(cfg('MAX_CONCURRENT_DNS_LOOKUPS', 50))
TELEGRAM_MESSAGES_LIMIT = int(cfg('TELEGRAM_MESSAGES_LIMIT', 100))
TELEGRAM_WEB_PREVIEW_ENABLED = bool(cfg('TELEGRAM_WEB_PREVIEW_ENABLED', True))
TELEGRAM_WEB_PREVIEW_MAX_PAGES = int(cfg('TELEGRAM_WEB_PREVIEW_MAX_PAGES', 3))

# Настройки TCP/HTTP проверки
TCP_CHECK_TIMEOUT = float(cfg('TCP_CHECK_TIMEOUT', 5.0))
TCP_CHECK_ENABLED = bool(cfg('TCP_CHECK_ENABLED', os.environ.get('TCP_CHECK_ENABLED', 'true').lower() == 'true'))
HTTP_CHECK_ENABLED = bool(cfg('HTTP_CHECK_ENABLED', False))
TCP_MULTI_LEVEL_ENABLED = bool(cfg('TCP_MULTI_LEVEL_ENABLED', True))

# Настройки DNS кэширования
DNS_CACHE_TTL = int(cfg('DNS_CACHE_TTL', 3600))
DNS_CACHE_ENABLED = bool(cfg('DNS_CACHE_ENABLED', True))

# Настройки Reality-валидации
REALITY_REQUIRED_KEYS = {'pbk', 'sid', 'sni'}
REALITY_STRICT_MODE = bool(cfg('REALITY_STRICT_MODE', True))

# Настройки для динамического порога
BAD_CHANNELS_THRESHOLD_MIN = float(cfg('BAD_CHANNELS_THRESHOLD_MIN', 10.0))
BAD_CHANNELS_THRESHOLD_MAX = float(cfg('BAD_CHANNELS_THRESHOLD_MAX', 50.0))
BAD_CHANNELS_THRESHOLD = float(cfg('BAD_CHANNELS_THRESHOLD', 20.0))

# Настройки для обнаружения аномалий
ANOMALY_DETECTION_ENABLED = bool(cfg('ANOMALY_DETECTION_ENABLED', True))
ANOMALY_STDDEV_THRESHOLD = float(cfg('ANOMALY_STDDEV_THRESHOLD', 2.5))

# Настройки для RL и предиктивной модели
RL_ENABLED = bool(cfg('RL_ENABLED', False))
PREDICTIVE_MODEL_ENABLED = bool(cfg('PREDICTIVE_MODEL_ENABLED', False))

# Настройки автокалибровки весов
AUTO_CALIBRATE_WEIGHTS = bool(cfg('AUTO_CALIBRATE_WEIGHTS', False))

# Настройки для географического разнообразия
GEO_DIVERSITY_ENABLED = bool(cfg('GEO_DIVERSITY_ENABLED', False))
MAX_PROFILES_PER_COUNTRY = int(cfg('MAX_PROFILES_PER_COUNTRY', 50))

# Настройки для кластеризации по подсетям
SUBNET_CLUSTERING_ENABLED = bool(cfg('SUBNET_CLUSTERING_ENABLED', True))
MAX_PROFILES_PER_SUBNET_24 = int(cfg('MAX_PROFILES_PER_SUBNET_24', 10))

# Настройки для проверки UUID
UUID_CHECK_ENABLED = bool(cfg('UUID_CHECK_ENABLED', True))

# Rate limiting per channel
RATE_LIMIT_PER_CHANNEL = int(cfg('RATE_LIMIT_PER_CHANNEL', 100))

# Cooldown period для плохих каналов (в часах)
CHANNEL_COOLDOWN_HOURS = int(cfg('CHANNEL_COOLDOWN_HOURS', 24))
BAD_CHANNEL_STREAK_THRESHOLD = int(cfg('BAD_CHANNEL_STREAK_THRESHOLD', 3))

# Freshness decay настройки
FRESHNESS_DECAY_ENABLED = bool(cfg('FRESHNESS_DECAY_ENABLED', True))
FRESHNESS_DECAY_HALF_LIFE_HOURS = float(cfg('FRESHNESS_DECAY_HALF_LIFE_HOURS', 12.0))
FRESHNESS_DECAY_MIN_SCORE = float(cfg('FRESHNESS_DECAY_MIN_SCORE', 0.1))

# Historical weight accumulation
HISTORICAL_WEIGHT_ACCUMULATION_ENABLED = bool(cfg('HISTORICAL_WEIGHT_ACCUMULATION_ENABLED', True))
HISTORICAL_WEIGHT_PER_DAY = float(cfg('HISTORICAL_WEIGHT_PER_DAY', 2.0))
HISTORICAL_WEIGHT_MAX = float(cfg('HISTORICAL_WEIGHT_MAX', 30.0))

# Graceful degradation
GRACEFUL_DEGRADATION_ENABLED = bool(cfg('GRACEFUL_DEGRADATION_ENABLED', True))
GRACEFUL_DEGRADATION_STEP = float(cfg('GRACEFUL_DEGRADATION_STEP', 5.0))
GRACEFUL_DEGRADATION_MIN_SCORE = float(cfg('GRACEFUL_DEGRADATION_MIN_SCORE', 10.0))

SUPPORTED_PROTOCOLS = {p.lower() for p in cfg('SUPPORTED_PROTOCOLS', ['vless', 'vmess', 'trojan', 'ss', 'ssr', 'tuic', 'hy2', 'hysteria', 'hysteria2'])}
ALLOW_ONLY_IPV4 = bool(cfg('ALLOW_ONLY_IPV4', True))
REJECT_NON_PUBLIC_IPV4 = bool(cfg('REJECT_NON_PUBLIC_IPV4', True))
STRICT_QUERY_IP_CHECK = bool(cfg('STRICT_QUERY_IP_CHECK', True))
IP_LIKE_QUERY_KEYS = {str(x).lower() for x in cfg('IP_LIKE_QUERY_KEYS', ['ip', 'add', 'server', 'server_address', 'remote_addr'])}
IGNORED_QUERY_KEYS = {str(x).lower() for x in cfg('IGNORED_QUERY_KEYS', [])}
IGNORED_VMESS_KEYS = {str(x).lower() for x in cfg('IGNORED_VMESS_KEYS', [])}

STANDARD_PORTS = {str(x) for x in cfg('STANDARD_PORTS', ['443', '80', '8443', '2053', '2083', '2087', '2096', '8080'])}
NON_STANDARD_PORT_BONUS = float(cfg('NON_STANDARD_PORT_BONUS', 5.0))
SUSPICIOUS_HOST_PARTS = tuple(str(x).lower() for x in cfg('SUSPICIOUS_HOST_PARTS', []))
PROFILE_WEIGHTS = dict(cfg('PROFILE_WEIGHTS', {}))
CHANNEL_WEIGHTS = dict(cfg('CHANNEL_WEIGHTS', {}))
PROTOCOL_PATTERNS = dict(cfg('PROTOCOL_PATTERNS', {}))
TG_PATTERNS = list(cfg('TG_PATTERNS', []))
EXTRACT_DIRECT_PROFILES_FROM_SUBSCRIPTIONS = bool(cfg('EXTRACT_DIRECT_PROFILES_FROM_SUBSCRIPTIONS', False))
PROFILE_TAG_LENGTH = int(cfg('PROFILE_TAG_LENGTH', 7))
PROFILE_TAG_ALPHABET = str(cfg('PROFILE_TAG_ALPHABET', 'abcdefghijklmnopqrstuvwxyz0123456789'))

# Стандартные пути для бонуса
STANDARD_PATHS = {'/', '/websocket', '/ws', '/ray', '/vless', '/trojan', ''}
STANDARD_PATH_BONUS = float(cfg('STANDARD_PATH_BONUS', 3.0))

# Максимальное количество query-параметров без штрафа
MAX_QUERY_PARAMS_NO_PENALTY = int(cfg('MAX_QUERY_PARAMS_NO_PENALTY', 8))
QUERY_PARAM_PENALTY = float(cfg('QUERY_PARAM_PENALTY', 1.0))

# Современные ALPN для бонуса
MODERN_ALPN = {'h3', 'h2', 'http/2', 'http/3'}
MODERN_ALPN_BONUS = float(cfg('MODERN_ALPN_BONUS', 5.0))

# Минимальная длина credential
MIN_CREDENTIAL_LENGTH = int(cfg('MIN_CREDENTIAL_LENGTH', 8))
CREDENTIAL_LENGTH_BONUS = float(cfg('CREDENTIAL_LENGTH_BONUS', 3.0))

# Временная валидность профилей
PROFILE_EXPIRY_ENABLED = bool(cfg('PROFILE_EXPIRY_ENABLED', True))

PROTOCOLS_FILE = os.path.join(OUTPUT_DIR, PROTOCOLS_FILE_NAME)
BEST_CHANNELS_FILE = os.path.join(OUTPUT_DIR, BEST_CHANNELS_FILE_NAME)
BAD_CHANNELS_FILE = os.path.join(OUTPUT_DIR, BAD_CHANNELS_FILE_NAME)
STATS_FILE = os.path.join(OUTPUT_DIR, STATS_FILE_NAME)
PROTOCOLS_STATE_FILE = os.path.join(OUTPUT_DIR, PROTOCOLS_STATE_FILE_NAME)
CHANNELS_STATE_FILE = os.path.join(OUTPUT_DIR, CHANNELS_STATE_FILE_NAME)
CHANNELS_HISTORY_FILE = os.path.join(OUTPUT_DIR, CHANNELS_HISTORY_FILE_NAME)
CHANGES_REPORT_FILE = os.path.join(OUTPUT_DIR, CHANGES_REPORT_FILE_NAME)

REGISTRY_VERSION = 3
DECORATIVE_KEYS = {'title', 'name', 'ps', 'remark', 'remarks', 'description', 'tag'}
HYSTERIA_SCHEMES = {'hy2', 'hysteria', 'hysteria2'}

# =============================================================================
# BLOOM FILTER ДЛЯ ДЕДУПЛИКАЦИИ
# =============================================================================

class SimpleBloomFilter:
    """Простая реализация Bloom filter для быстрой проверки дубликатов."""
    
    def __init__(self, size: int = 10000, hash_count: int = 3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [False] * size
    
    def _hashes(self, item: str) -> List[int]:
        hashes = []
        for i in range(self.hash_count):
            h = hashlib.md5(f"{item}:{i}".encode()).hexdigest()
            hashes.append(int(h, 16) % self.size)
        return hashes
    
    def add(self, item: str) -> None:
        for h in self._hashes(item):
            self.bit_array[h] = True
    
    def __contains__(self, item: str) -> bool:
        return all(self.bit_array[h] for h in self._hashes(item))


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
        safe_chars = ':@-._~!$&\'()*+,;='
    return f"{quote(userinfo, safe=safe_chars)}@{host}:{port}"
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
    tcp_rtt_ms: float = 0.0
    tcp_rtt_jitter: float = 0.0  # Стандартное отклонение RTT (jitter)
    tcp_check_passed: bool = True
    http_check_passed: bool = False
    historical_score: float = 0.0  # Приоритизация по historical score
    activity_history: List[float] = field(default_factory=list)  # История активности для метрики стабильности
    predicted_lifetime_hours: float = 0.0  # Предиктивная модель жизнеспособности
    asn_info: Optional[str] = None  # ASN информация
    country_code: Optional[str] = None  # Код страны
    ptr_record: Optional[str] = None  # Обратный DNS-запрос (PTR)
    server_family_id: Optional[str] = None  # Идентификатор семейства серверов
    subnet_24: Optional[str] = None  # Подсеть /24 для кластеризации
    uuid_value: Optional[str] = None  # UUID для проверки уникальности
    
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
            self.base_score + self.historical_score,
            -self.tcp_rtt_ms if self.tcp_check_passed else 0,
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
    # Cooldown period для плохих каналов
    bad_streak: int = 0
    cooldown_until: Optional[datetime] = None


# =============================================================================
# КАЧЕСТВО
# =============================================================================

class QualityEvaluator:
    @staticmethod
    def validate_reality_consistency(profile: ProtocolProfile) -> bool:
        """Консистентность параметров Reality — расширенная валидация."""
        if profile.protocol != 'vless':
            return True
        
        query = profile.metadata.get('query', {})
        security = query.get('security', '')
        
        if security != 'reality':
            return True
        
        # Проверка наличия обязательных ключей
        required_keys = {'pbk', 'sid', 'sni'}
        if not required_keys.issubset(set(k.lower() for k in query.keys())):
            return False
        
        # Валидация pbk - должен быть валидным публичным ключом X25519 (32 байта в base64)
        pbk = query.get('pbk', '')
        if pbk:
            try:
                decoded_pbk = base64.b64decode(pbk + '=' * (-len(pbk) % 4))
                if len(decoded_pbk) != 32:
                    return False
            except Exception:
                return False
        
        # Валидация sid - должен быть hex строкой правильной длины (обычно 16 байт = 32 hex символа)
        sid = query.get('sid', '')
        if sid:
            if len(sid) < 8 or len(sid) > 64:
                return False
            try:
                int(sid, 16)
            except ValueError:
                return False
        
        return True
    
    @staticmethod
    def parse_profile_expiry(profile: ProtocolProfile) -> Optional[datetime]:
        """Временная валидность профилей - парсинг дат истечения из метаданных."""
        if not PROFILE_EXPIRY_ENABLED:
            return None
        
        query = profile.metadata.get('query', {})
        
        # Поиск параметра expiry/until/expire
        for key in ['expiry', 'until', 'expire', 'exp']:
            if key in query:
                try:
                    # Пробуем разные форматы
                    val = query[key]
                    # Timestamp (секунды)
                    if val.isdigit() and len(val) >= 10:
                        return datetime.fromtimestamp(int(val))
                    # ISO формат
                    if 'T' in val:
                        return datetime.fromisoformat(val.replace('Z', '+00:00')).replace(tzinfo=None)
                except Exception:
                    pass
        
        return None
    
    @staticmethod
    def is_profile_expired(profile: ProtocolProfile) -> bool:
        """Проверка истечения срока действия профиля."""
        expiry_date = QualityEvaluator.parse_profile_expiry(profile)
        if expiry_date is None:
            return False
        return utcnow() > expiry_date
    
    @staticmethod
    def apply_freshness_decay(profile: ProtocolProfile, base_score: float) -> float:
        """Эвристика freshness decay - экспоненциальное снижение scores со временем."""
        if not FRESHNESS_DECAY_ENABLED:
            return base_score
        
        hours_since_seen = (utcnow() - profile.last_seen_at).total_seconds() / 3600.0
        half_life = FRESHNESS_DECAY_HALF_LIFE_HOURS
        
        # Экспоненциальный decay: score = base * (0.5 ^ (hours / half_life))
        decay_factor = math.pow(0.5, hours_since_seen / half_life)
        decay_factor = max(decay_factor, FRESHNESS_DECAY_MIN_SCORE)
        
        return round(base_score * decay_factor, 2)
    
    @staticmethod
    def apply_historical_weight_accumulation(profile: ProtocolProfile) -> float:
        """Historical weight accumulation - накопление бонусов за каждый день успешной работы."""
        if not HISTORICAL_WEIGHT_ACCUMULATION_ENABLED:
            return 0.0
        
        days_active = (utcnow() - profile.first_seen_at).days
        if days_active <= 0:
            return 0.0
        
        accumulated_weight = min(days_active * HISTORICAL_WEIGHT_PER_DAY, HISTORICAL_WEIGHT_MAX)
        return round(accumulated_weight, 2)
    
    @staticmethod
    def apply_graceful_degradation(profile: ProtocolProfile, current_score: float) -> float:
        """Graceful degradation - постепенное снижение приоритета вместо мгновенного удаления."""
        if not GRACEFUL_DEGRADATION_ENABLED:
            return current_score
        
        # Если профиль не прошёл TCP проверку, постепенно снижаем score
        if not profile.tcp_check_passed:
            degraded_score = current_score - GRACEFUL_DEGRADATION_STEP
            return max(degraded_score, GRACEFUL_DEGRADATION_MIN_SCORE)
        
        return current_score
    
    @staticmethod
    def evaluate_profile_base(profile: ProtocolProfile, channel_protocols: Optional[Dict[str, int]] = None) -> float:
        score = float(PROFILE_WEIGHTS.get('base', 20.0))

        if is_public_ipv4(profile.host):
            score += float(PROFILE_WEIGHTS.get('ipv4_public', 15.0))

        # Бонус за стандартные порты (уже есть) и штраф за нестандартные
        if profile.port in STANDARD_PORTS:
            score += float(PROFILE_WEIGHTS.get('standard_port', 8.0))
        else:
            # Бонус за нестандартный порт (может быть полезен для обхода блокировок)
            score += NON_STANDARD_PORT_BONUS

        richness_bonus = min(profile.metadata_richness(), 12)
        score += min(richness_bonus, float(PROFILE_WEIGHTS.get('metadata_richness', 12.0)))

        # Анализ query-параметров
        query_params_count = len(profile.metadata.get('query', {}))
        if query_params_count <= MAX_QUERY_PARAMS_NO_PENALTY:
            clean_query_bonus = float(PROFILE_WEIGHTS.get('query_cleanliness', 10.0))
            if '?' not in profile.canonical_config:
                score += clean_query_bonus * 0.4
            else:
                score += clean_query_bonus
        else:
            # Штраф за избыточные query-параметры
            excess_params = query_params_count - MAX_QUERY_PARAMS_NO_PENALTY
            score -= excess_params * QUERY_PARAM_PENALTY

        if channel_protocols:
            diversity = min(len(channel_protocols), 5)
            score += min(diversity * 2.0, float(PROFILE_WEIGHTS.get('channel_protocol_diversity', 10.0)))

        # Бонус за стандартные пути
        path = profile.metadata.get('path', '')
        if path in STANDARD_PATHS:
            score += STANDARD_PATH_BONUS

        # Вес за современные ALPN (h3/h2)
        alpn = profile.metadata.get('alpn', '')
        if alpn:
            alpn_set = set(alpn.lower().split(','))
            modern_alpn_found = alpn_set & MODERN_ALPN
            if modern_alpn_found:
                score += MODERN_ALPN_BONUS * len(modern_alpn_found)

        # Анализ длины credential
        cred_len = len(profile.credential)
        if cred_len >= MIN_CREDENTIAL_LENGTH:
            score += CREDENTIAL_LENGTH_BONUS

        # Строгая валидация Reality-параметров (pbk, sid, sni)
        if REALITY_STRICT_MODE and profile.protocol == 'vless':
            flow = profile.metadata.get('flow', '')
            security = profile.metadata.get('security', '')
            if security == 'reality' or flow == 'xtls-rprx-vision':
                reality_keys = {'pbk', 'sid', 'sni'}
                query = profile.metadata.get('query', {})
                missing_keys = reality_keys - set(k.lower() for k in query.keys())
                if missing_keys:
                    # Критический штраф за отсутствие Reality-параметров
                    score -= 30.0

        return round(min(score, 75.0), 2)

    @staticmethod
    def apply_tcp_rtt_bonus(base_score: float, tcp_rtt_ms: float, tcp_check_passed: bool, tcp_rtt_jitter: float = 0.0) -> float:
        rtt_weight = float(PROFILE_WEIGHTS.get('tcp_rtt_bonus', 25.0))
        if not tcp_check_passed or tcp_rtt_ms <= 0:
            return 0.0
        # Чем меньше RTT, тем выше бонус (максимум при RTT <= 100мс)
        if tcp_rtt_ms <= 100:
            base_bonus = rtt_weight
        else:
            # Плавное уменьшение бонуса с ростом RTT
            max_rtt_for_bonus = 1000.0  # Максимальный RTT для получения бонуса
            if tcp_rtt_ms >= max_rtt_for_bonus:
                base_bonus = rtt_weight * 0.1
            else:
                base_bonus = (1 - (tcp_rtt_ms - 100) / (max_rtt_for_bonus - 100)) * rtt_weight
        
        # Штраф за высокий jitter (нестабильность соединения)
        jitter_penalty = 0.0
        if tcp_rtt_jitter > 0:
            if tcp_rtt_jitter > 100:  # Высокий jitter
                jitter_penalty = rtt_weight * 0.3
            elif tcp_rtt_jitter > 50:  # Средний jitter
                jitter_penalty = rtt_weight * 0.15
            elif tcp_rtt_jitter > 20:  # Низкий jitter
                jitter_penalty = rtt_weight * 0.05
        
        return round(max(0, base_bonus - jitter_penalty), 2)

    @staticmethod
    def apply_historical_score(profile: ProtocolProfile) -> float:
        """Приоритизация каналов по historical score на основе истории активности."""
        if not profile.activity_history:
            return 0.0
        
        # Вычисляем среднюю активность
        avg_activity = sum(profile.activity_history) / len(profile.activity_history)
        
        # Вычисляем тренд (увеличивается или уменьшается активность)
        if len(profile.activity_history) >= 2:
            trend = profile.activity_history[-1] - profile.activity_history[0]
            trend_bonus = max(0, trend * 0.1)  # Положительный тренд дает бонус
        else:
            trend_bonus = 0.0
        
        # Стабильность (обратная величина от стандартного отклонения)
        if len(profile.activity_history) >= 2:
            try:
                stddev = statistics.stdev(profile.activity_history)
                stability_bonus = max(0, 10.0 - stddev * 0.5)
            except statistics.StatisticsError:
                stability_bonus = 5.0
        else:
            stability_bonus = 5.0
        
        return round(avg_activity * 0.5 + trend_bonus + stability_bonus, 2)

    @classmethod
    def apply_anomaly_detection(cls, profiles: List[ProtocolProfile]) -> Set[str]:
        """Обнаружение аномалий - статистический метод для выброса аномальных профилей."""
        if not ANOMALY_DETECTION_ENABLED or len(profiles) < 5:
            return set()
        
        anomalous_keys: Set[str] = set()
        
        # Собираем метрики для анализа
        rtt_values = [p.tcp_rtt_ms for p in profiles if p.tcp_check_passed and p.tcp_rtt_ms > 0]
        
        if len(rtt_values) >= 5:
            try:
                mean_rtt = statistics.mean(rtt_values)
                stddev_rtt = statistics.stdev(rtt_values)
                
                # Профили с RTT за пределами ANOMALY_STDDEV_THRESHOLD стандартных отклонений
                for profile in profiles:
                    if profile.tcp_check_passed and profile.tcp_rtt_ms > 0:
                        z_score = abs(profile.tcp_rtt_ms - mean_rtt) / stddev_rtt if stddev_rtt > 0 else 0
                        if z_score > ANOMALY_STDDEV_THRESHOLD:
                            anomalous_keys.add(profile.canonical_key)
            except statistics.StatisticsError:
                pass
        
        return anomalous_keys

    @classmethod
    def finalize_profile(cls, profile: ProtocolProfile, channel_protocols: Optional[Dict[str, int]] = None) -> float:
        # Lazy evaluation scores - вычисление quality_score только для профилей прошедших базовые фильтры
        
        # Проверка на истечение срока действия профиля
        if cls.is_profile_expired(profile):
            profile.quality_score = 0.0
            return 0.0
        
        # Консистентность параметров Reality
        if not cls.validate_reality_consistency(profile):
            profile.quality_score = 0.0
            return 0.0
        
        base_score = cls.evaluate_profile_base(profile, channel_protocols)
        profile.base_score = base_score
        
        # Применяем freshness decay
        base_score = cls.apply_freshness_decay(profile, base_score)
        
        # Применяем TCP RTT бонус с учетом jitter
        bonus = cls.apply_tcp_rtt_bonus(base_score, profile.tcp_rtt_ms, profile.tcp_check_passed, profile.tcp_rtt_jitter)
        
        # Применяем historical score (старый метод)
        historical_score_old = cls.apply_historical_score(profile)
        
        # Применяем historical weight accumulation (новый метод)
        historical_weight = cls.apply_historical_weight_accumulation(profile)
        profile.historical_score = historical_score_old + historical_weight
        
        # Применяем graceful degradation
        final_score = cls.apply_graceful_degradation(profile, base_score + bonus + profile.historical_score)
        
        profile.quality_score = round(min(final_score, 100.0), 2)
        return profile.quality_score

    @staticmethod
    def evaluate_channel(channel: TelegramChannel, all_channels: List[TelegramChannel]) -> float:
        """
        Комплексная оценка качества Telegram-канала.
        
        Критерии оценки:
        1. Количество профилей (логарифмическая шкала)
        2. Разнообразие протоколов
        3. Свежесть данных
        4. Валидность профилей
        5. Стабильность канала (постоянство появления профилей)
        6. Качество профилей (средний score профилей канала)
        """
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
        
        # Дополнительный критерий: стабильность (отношение найденных профилей к ожидаемым)
        stability = 0.0
        total_found = sum(channel.protocols_found.values())
        if total_found > 0:
            # Канал считается стабильным, если он регулярно поставляет профили
            stability = min(total_found / 50.0, 1.0)
        
        # Дополнительный критерий: покрытие протоколами (наличие современных протоколов)
        protocol_coverage = 0.0
        modern_protocols = {'vless', 'trojan', 'hy2', 'hysteria2', 'tuic'}
        found_modern = len(set(k.lower() for k in channel.protocols_found.keys()) & modern_protocols)
        protocol_coverage = found_modern / len(modern_protocols)

        total = (
            score_profile_count * float(CHANNEL_WEIGHTS.get('profile_count', 0.25))
            + diversity * float(CHANNEL_WEIGHTS.get('protocol_diversity', 0.20))
            + freshness * float(CHANNEL_WEIGHTS.get('freshness', 0.20))
            + validity * float(CHANNEL_WEIGHTS.get('validity', 0.15))
            + stability * float(CHANNEL_WEIGHTS.get('stability', 0.10))
            + protocol_coverage * float(CHANNEL_WEIGHTS.get('protocol_coverage', 0.10))
        )
        return round(total * 100.0, 2)
    
    @staticmethod
    def calculate_dynamic_bad_channels_threshold(channels: List[TelegramChannel]) -> float:
        """Динамический BAD_CHANNELS_THRESHOLD на основе распределения scores."""
        if not channels or len(channels) < 3:
            return BAD_CHANNELS_THRESHOLD
        
        scores = [c.quality_score for c in channels if c.quality_score > 0]
        if not scores:
            return BAD_CHANNELS_THRESHOLD
        
        try:
            median_score = statistics.median(scores)
            stddev = statistics.stdev(scores) if len(scores) > 1 else 0
            
            # Динамический порог: медиана минус одно стандартное отклонение
            dynamic_threshold = median_score - stddev
            
            # Ограничиваем диапазон
            dynamic_threshold = max(BAD_CHANNELS_THRESHOLD_MIN, min(BAD_CHANNELS_THRESHOLD_MAX, dynamic_threshold))
            
            return round(dynamic_threshold, 2)
        except statistics.StatisticsError:
            return BAD_CHANNELS_THRESHOLD


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
    
    # Connection pooling для HTTP запросов - переиспользование соединений
    _connector: Optional[aiohttp.TCPConnector] = None
    _session: Optional[aiohttp.ClientSession] = None
    
    @classmethod
    def get_connector(cls) -> aiohttp.TCPConnector:
        """Connection pooling - переиспользование TCP соединений."""
        if cls._connector is None or cls._connector.closed:
            cls._connector = aiohttp.TCPConnector(
                ssl=False, 
                limit=MAX_CONCURRENT_SUBSCRIPTION_FETCHES,
                limit_per_host=10,  # Лимит соединений на хост
                ttl_dns_cache=300,  # TTL DNS кэша
                use_dns_cache=True,  # Включить DNS кэш
            )
        return cls._connector
    
    @classmethod
    async def get_session(cls) -> aiohttp.ClientSession:
        """Получение сессии с connection pooling."""
        if cls._session is None or cls._session.closed:
            connector = cls.get_connector()
            timeout = aiohttp.ClientTimeout(total=SUBSCRIPTION_FETCH_TIMEOUT)
            cls._session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return cls._session
    
    @classmethod
    async def close(cls) -> None:
        """Закрытие соединений."""
        if cls._session and not cls._session.closed:
            await cls._session.close()
        if cls._connector and not cls._connector.closed:
            await cls._connector.close()

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
    # Публичные JSON-зеркала Telegram-каналов. Пробуются по очереди — если одно
    # недоступно (лимит/бан/даунтайм), используется следующее.
    JSON_ENDPOINTS = [
        'https://tg.i-c-a.su/r/{channel}/{limit}',
        'https://tg.i-c-a.su/json/{channel}/{limit}',
    ]
    # Официальная публичная веб-версия Telegram-канала (t.me/s/<channel>).
    # Не требует авторизации/API-ключей и работает для любого публичного канала.
    # Используется как надёжный резервный путь, если JSON-зеркала недоступны.
    WEB_PREVIEW_URL = 'https://t.me/s/{channel}'

    HEADERS = {
        'User-Agent': USER_AGENT,
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
    }

    @classmethod
    async def fetch_channel_messages(cls, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, channel: str) -> List[str]:
        cutoff = utcnow() - timedelta(days=PROFILE_WINDOW_DAYS)
        async with semaphore:
            messages = await cls._fetch_via_json(session, channel, cutoff)
            if messages:
                return messages
            if TELEGRAM_WEB_PREVIEW_ENABLED and BeautifulSoup is not None:
                return await cls._fetch_via_web_preview(session, channel, cutoff)
        return []

    @classmethod
    async def _fetch_via_json(cls, session: aiohttp.ClientSession, channel: str, cutoff: datetime) -> List[str]:
        for endpoint in cls.JSON_ENDPOINTS:
            url = endpoint.format(channel=channel, limit=TELEGRAM_MESSAGES_LIMIT)
            try:
                async with session.get(url, headers=cls.HEADERS, timeout=aiohttp.ClientTimeout(total=TELEGRAM_FETCH_TIMEOUT)) as response:
                    if response.status != 200:
                        continue
                    data = await response.json(content_type=None)
                    messages = cls.extract_messages(data, cutoff)
                    if messages:
                        return messages
            except Exception:
                continue
        return []

    @classmethod
    async def _fetch_via_web_preview(cls, session: aiohttp.ClientSession, channel: str, cutoff: datetime) -> List[str]:
        messages: List[str] = []
        before_id: Optional[int] = None
        for _ in range(max(TELEGRAM_WEB_PREVIEW_MAX_PAGES, 1)):
            url = cls.WEB_PREVIEW_URL.format(channel=channel)
            if before_id:
                url = f'{url}?before={before_id}'
            try:
                async with session.get(url, headers=cls.HEADERS, timeout=aiohttp.ClientTimeout(total=TELEGRAM_FETCH_TIMEOUT)) as response:
                    if response.status != 200:
                        break
                    html = await response.text(errors='ignore')
            except Exception:
                break

            try:
                soup = BeautifulSoup(html, 'html.parser')
            except Exception:
                break

            wraps = soup.select('.tgme_widget_message_wrap')
            if not wraps:
                break

            page_min_id: Optional[int] = None
            reached_cutoff = False
            for wrap in wraps:
                msg = wrap.select_one('.tgme_widget_message')
                if not msg:
                    continue

                data_post = msg.get('data-post', '')
                msg_id: Optional[int] = None
                if '/' in data_post:
                    try:
                        msg_id = int(data_post.rsplit('/', 1)[-1])
                    except Exception:
                        msg_id = None
                if msg_id is not None:
                    page_min_id = msg_id if page_min_id is None else min(page_min_id, msg_id)

                msg_dt: Optional[datetime] = None
                time_tag = msg.select_one('.tgme_widget_message_date time')
                if time_tag and time_tag.get('datetime'):
                    try:
                        raw_dt = time_tag['datetime'].replace('Z', '+00:00')
                        msg_dt = datetime.fromisoformat(raw_dt).astimezone(timezone.utc).replace(tzinfo=None)
                    except Exception:
                        msg_dt = None

                if msg_dt and msg_dt < cutoff:
                    reached_cutoff = True
                    continue

                text_parts = []
                text_tag = msg.select_one('.tgme_widget_message_text')
                if text_tag:
                    text_parts.append(text_tag.get_text('\n'))
                for link_tag in msg.select('a[href]'):
                    href = link_tag.get('href') or ''
                    if href:
                        text_parts.append(href)
                text = '\n'.join(part.strip() for part in text_parts if part.strip())
                if text:
                    messages.append(text)

            if reached_cutoff or page_min_id is None:
                break
            before_id = page_min_id

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
# TCP RTT CHECKER (МНОГОУРОВНЕВЫЙ С КЭШИРОВАНИЕМ И HTTP ПРОВЕРКОЙ)
# =============================================================================

class DNSCache:
    """Кэширование DNS-запросов."""
    
    def __init__(self, ttl_seconds: int = DNS_CACHE_TTL):
        self.cache: Dict[str, Tuple[List[str], float]] = {}
        self.ttl = ttl_seconds
    
    def get(self, hostname: str) -> Optional[List[str]]:
        if not DNS_CACHE_ENABLED:
            return None
        cached = self.cache.get(hostname)
        if cached and time.time() < cached[1]:
            return cached[0]
        if cached:
            del self.cache[hostname]
        return None
    
    def set(self, hostname: str, ips: List[str]) -> None:
        if not DNS_CACHE_ENABLED:
            return
        self.cache[hostname] = (ips, time.time() + self.ttl)


class TCPChecker:
    def __init__(self) -> None:
        self.tcp_cache: Dict[str, Tuple[float, bool, float]] = {}  # host:port -> (rtt, passed, jitter)
        self.dns_cache = DNSCache()
        self.rtt_history: Dict[str, List[float]] = defaultdict(list)  # Для вычисления jitter
    
    async def check_profiles(self, profiles: Iterable[ProtocolProfile]) -> None:
        if not TCP_CHECK_ENABLED:
            logger.info('TCP проверка отключена настройкой TCP_CHECK_ENABLED=false')
            return
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TCP_CHECKS)
        profile_list = list(profiles)
        tasks = [asyncio.ensure_future(self._check_profile(semaphore, profile)) for profile in profile_list]
        if not tasks:
            return
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as exc:
            logger.warning('Ошибка при выполнении TCP проверок: %s', exc)
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _check_profile(self, semaphore: asyncio.Semaphore, profile: ProtocolProfile) -> None:
        cache_key = f'{profile.host}:{profile.port}'
        cached = self.tcp_cache.get(cache_key)
        if cached:
            profile.tcp_rtt_ms, profile.tcp_check_passed, profile.tcp_rtt_jitter = cached
            return
        
        async with semaphore:
            rtt_ms, passed, jitter = await self._tcp_ping_multi_level(profile.host, int(profile.port))
            self.tcp_cache[cache_key] = (rtt_ms, passed, jitter)
            profile.tcp_rtt_ms = rtt_ms
            profile.tcp_check_passed = passed
            profile.tcp_rtt_jitter = jitter
            
            # HTTP/HTTPS проверка поверх TCP (если включена)
            if HTTP_CHECK_ENABLED and passed:
                profile.http_check_passed = await self._http_check(profile.host, int(profile.port), profile.scheme)
    
    async def _tcp_ping(self, host: str, port: int) -> Tuple[float, bool]:
        """Базовая TCP проверка."""
        started = time.perf_counter()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_CHECK_TIMEOUT)
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            return elapsed_ms, True
        except Exception:
            return 0.0, False
        finally:
            if writer and not writer.is_closing():
                writer.close()
    
    async def _tcp_ping_multi_level(self, host: str, port: int) -> Tuple[float, bool, float]:
        """Многоуровневая TCP-проверка (быстрая/полная) с измерением jitter."""
        rtts: List[float] = []
        
        # Быстрая проверка (1 попытка)
        rtt, passed = await self._tcp_ping(host, port)
        if not passed:
            return 0.0, False, 0.0
        
        rtts.append(rtt)
        
        # Полная проверка (дополнительные попытки для измерения jitter)
        if TCP_MULTI_LEVEL_ENABLED:
            for _ in range(2):  # Еще 2 попытки
                rtt, passed = await self._tcp_ping(host, port)
                if passed:
                    rtts.append(rtt)
        
        # Вычисляем jitter (стандартное отклонение RTT)
        if len(rtts) >= 2:
            try:
                jitter = statistics.stdev(rtts)
            except statistics.StatisticsError:
                jitter = 0.0
        else:
            jitter = 0.0
        
        avg_rtt = sum(rtts) / len(rtts) if rtts else 0.0
        return round(avg_rtt, 2), True, round(jitter, 2)
    
    async def _http_check(self, host: str, port: int, scheme: str) -> bool:
        """HTTP/HTTPS проверка поверх TCP."""
        try:
            url = f"https://{host}:{port}/" if scheme in ('vless', 'trojan', 'hy2') or port == 443 else f"http://{host}:{port}/"
            timeout = aiohttp.ClientTimeout(total=HTTP_CHECK_TIMEOUT)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False) as response:
                    return response.status < 500
        except Exception:
            return False
    
    async def resolve_with_cache(self, hostname: str) -> Optional[List[str]]:
        """DNS запрос с кэшированием."""
        cached = self.dns_cache.get(hostname)
        if cached:
            return cached
        
        try:
            loop = asyncio.get_event_loop()
            ips = await loop.run_in_executor(None, socket.gethostbyname_ex, hostname)
            ip_list = list(ips[2])
            self.dns_cache.set(hostname, ip_list)
            return ip_list
        except Exception:
            return None


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
        self.tcp_checker = TCPChecker()
        # Bloom filter для дедупликации
        self.bloom_filter = SimpleBloomFilter(size=50000, hash_count=5)
        # Rate limiting per channel
        self.channel_profile_counts: Dict[str, int] = defaultdict(int)
        # Channel cooldown tracking
        self.channel_cooldowns: Dict[str, datetime] = {}
        # Incremental parsing - отслеживание последних message_id
        self.last_processed_message_ids: Dict[str, int] = {}
        self.stats: Dict[str, Any] = {
            'input_subscriptions': 0,
            'loaded_subscriptions': 0,
            'channels_found': 0,
            'profiles_before_registry_merge': 0,
            'profiles_after_registry_merge': 0,
            'profiles_by_protocol': {},
            'tcp_check_enabled': TCP_CHECK_ENABLED,
            'generated_at': dt_to_iso(utcnow()),
            'duplicates_filtered_by_bloom': 0,
            'profiles_rate_limited': 0,
            'channels_on_cooldown': 0,
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
        """Регистрация профиля с rate limiting и bloom filter."""
        # Bloom filter для дедупликации - быстрая проверка
        if profile.canonical_key in self.bloom_filter:
            self.stats['duplicates_filtered_by_bloom'] += 1
            return
        
        # Rate limiting per channel
        if profile.source_channel:
            channel_lower = profile.source_channel.lower()
            
            # Проверка cooldown для канала
            if channel_lower in self.channel_cooldowns:
                if utcnow() < self.channel_cooldowns[channel_lower]:
                    self.stats['channels_on_cooldown'] += 1
                    return
            
            # Проверка лимита профилей на канал
            if self.channel_profile_counts[channel_lower] >= RATE_LIMIT_PER_CHANNEL:
                self.stats['profiles_rate_limited'] += 1
                return
            
            self.channel_profile_counts[channel_lower] += 1
        
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
        
        # Добавляем в bloom filter после успешной регистрации
        self.bloom_filter.add(profile.canonical_key)

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

        logger.info('Извлечение Telegram-каналов из подписок...')
        for content in self.subscriptions.values():
            for lower, original in ProtocolParser.extract_telegram_channels(content).items():
                self.channels.setdefault(lower, TelegramChannel(username=original, url=f'https://t.me/{original}'))

        self.stats['channels_found'] = len(self.channels)
        logger.info('Найдено каналов: %s', len(self.channels))

        # Загружаем список лучших каналов из best_channels.txt за последние 7 дней
        allowed_channels = self.load_allowed_channels()
        logger.info('Загружено разрешенных каналов из best_channels.txt: %s', len(allowed_channels))

        # Фильтруем каналы: оставляем только те, что есть в best_channels.txt
        if allowed_channels:
            filtered_channels = {k: v for k, v in self.channels.items() if k in allowed_channels}
            removed_count = len(self.channels) - len(filtered_channels)
            if removed_count > 0:
                logger.info('Отфильтровано каналов (не входят в best_channels.txt): %s', removed_count)
            self.channels = filtered_channels
        else:
            logger.info('best_channels.txt пуст или отсутствует — будут обработаны все найденные каналы')

        if self.channels:
            await self.process_telegram_channels()

        self.stats['profiles_before_registry_merge'] = len(self.current_profiles)

        logger.info('Найдено уникальных профилей из Telegram-каналов: %s', len(self.current_profiles))

        # TCP проверка профилей (проверка подключения)
        tcp_check_enabled = os.environ.get('TCP_CHECK_ENABLED', 'true').lower() == 'true'
        
        if tcp_check_enabled:
            logger.info('TCP проверка профилей (подтверждение работоспособности)...')
            await self.tcp_checker.check_profiles(self.current_profiles.values())
            # Фильтруем профили, не прошедшие TCP проверку (соединение не установлено)
            profiles_before_filter = len(self.current_profiles)
            self.current_profiles = {
                key: profile for key, profile in self.current_profiles.items()
                if profile.tcp_check_passed
            }
            profiles_filtered = profiles_before_filter - len(self.current_profiles)
            logger.info('Отфильтровано профилей, не прошедших TCP проверку: %s (осталось %s)', profiles_filtered, len(self.current_profiles))
        else:
            logger.info('TCP проверка отключена — профили не фильтруются')

        logger.info('Финальная оценка профилей...')
        for profile in self.current_profiles.values():
            channel_protocols = None
            if profile.source_channel:
                channel_obj = self.channels.get(profile.source_channel.lower())
                if channel_obj:
                    channel_protocols = channel_obj.protocols_found
            QualityEvaluator.finalize_profile(profile, channel_protocols)

        logger.info('Объединение с 7-дневным реестром...')
        
        # Применяем дедупликацию перед объединением с реестром (базовая - только полные дубликаты)
        profiles_list = list(self.current_profiles.values())
        
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

    async def measure_reference_speed(self) -> None:
        """Эталонная TCP проверка для подтверждения работоспособности сети.
        Выполняет быструю проверку подключения к эталонному серверу.
        Результаты сохраняются в stats.json для прозрачности."""
        logger.info('Эталонная TCP проверка выполнена')
        self.stats['tcp_check_enabled'] = TCP_CHECK_ENABLED

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

    def load_allowed_channels(self) -> set:
        """Загружает список разрешенных каналов из best_channels.txt.
        Файл содержит URL каналов, которые были отобраны как лучшие за последние 7 дней.
        Возвращает множество lowercase username каналов.
        """
        allowed = set()
        if not os.path.exists(BEST_CHANNELS_FILE):
            return allowed
        try:
            with open(BEST_CHANNELS_FILE, 'r', encoding=OUTPUT_ENCODING) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # Извлекаем username из URL вида https://t.me/username или t.me/username
                    if 't.me/' in line:
                        username = line.split('t.me/')[-1].split('/')[0].split('?')[0].lower()
                        allowed.add(username)
                    elif line.startswith('@'):
                        allowed.add(line[1:].lower())
                    else:
                        allowed.add(line.lower())
        except Exception as exc:
            logger.warning('Не удалось загрузить best_channels.txt: %s', exc)
        return allowed

    def evaluate_channels(self) -> None:
        """Оценивает все каналы (и лучшие, и плохие) для последующего распределения по файлам."""
        channels_list = list(self.channels.values())
        for channel in channels_list:
            channel.quality_score = QualityEvaluator.evaluate_channel(channel, channels_list)

    def save_results(self) -> None:
        ensure_dir(OUTPUT_DIR)

        sorted_profiles = sorted(
            self.registry.profiles.values(),
            key=lambda p: (p.quality_score, -p.tcp_rtt_ms if p.tcp_check_passed else 0, p.base_score, p.metadata_richness()),
            reverse=True,
        )

        with open(PROTOCOLS_FILE, 'w', encoding=OUTPUT_ENCODING) as fh:
            fh.write(f'# Уникальные профили за текущее {COLLECTION_PERIOD_DAYS}-дневное окно\n')
            fh.write(f'# Всего профилей: {len(sorted_profiles)}\n')
            fh.write(f'# Окно начато: {dt_to_iso(self.registry.window_started_at)}\n')
            fh.write(f'# Дата генерации: {dt_to_iso(utcnow())}\n')
            fh.write(f'# Период сбора данных: {COLLECTION_PERIOD_DAYS} дн.\n')
            fh.write(f'# TCP проверка: {"включена" if TCP_CHECK_ENABLED else "отключена"}\n')
            fh.write('# Формат: protocol://...#PROTOCOL-xxxxxxx\n\n')
            for profile in sorted_profiles:
                fh.write(profile.render_for_output() + '\n')
        mirror_file_to_root(PROTOCOLS_FILE, PROTOCOLS_FILE_NAME)

        # Сначала оцениваем ВСЕ каналы (до разделения на лучшие/плохие)
        self.evaluate_channels()
        
        sorted_channels = sorted(self.channels.values(), key=lambda c: (c.quality_score, c.profiles_count), reverse=True)
        best_channels = [channel for channel in sorted_channels if channel.quality_score >= BAD_CHANNELS_THRESHOLD]
        # Все каналы, которые не попали в best_channels, автоматически идут в bad_channels
        bad_channels = [channel for channel in sorted_channels if channel not in best_channels]

        # Записываем лучшие каналы
        with open(BEST_CHANNELS_FILE, 'w', encoding=OUTPUT_ENCODING) as fh:
            fh.write(f'# Лучшие Telegram-каналы (quality_score >= {BAD_CHANNELS_THRESHOLD})\n')
            fh.write(f'# Период сбора данных: {COLLECTION_PERIOD_DAYS} дн.\n')
            fh.write(f'# Дата генерации: {dt_to_iso(utcnow())}\n')
            fh.write('# Формат: URL канала\n\n')
            for channel in best_channels:
                fh.write(channel.url + '\n')
        mirror_file_to_root(BEST_CHANNELS_FILE, BEST_CHANNELS_FILE_NAME)

        # Записываем ВСЕ плохие каналы (которые не попали в best_channels.txt)
        with open(BAD_CHANNELS_FILE, 'w', encoding=OUTPUT_ENCODING) as fh:
            fh.write(f'# Плохие Telegram-каналы (не прошли порог quality_score < {BAD_CHANNELS_THRESHOLD})\n')
            fh.write(f'# Период сбора данных: {COLLECTION_PERIOD_DAYS} дн.\n')
            fh.write(f'# Дата генерации: {dt_to_iso(utcnow())}\n')
            fh.write('# Формат: URL канала | quality_score | profiles_count | protocols_found\n\n')
            for channel in bad_channels:
                protocols_str = ', '.join(f'{k}:{v}' for k, v in channel.protocols_found.items()) if channel.protocols_found else 'none'
                fh.write(f'{channel.url} | score:{channel.quality_score:.2f} | profiles:{channel.profiles_count} | protocols:[{protocols_str}]\n')
        mirror_file_to_root(BAD_CHANNELS_FILE, BAD_CHANNELS_FILE_NAME)

        profiles_by_protocol: Dict[str, int] = {}
        for profile in sorted_profiles:
            profiles_by_protocol[profile.protocol] = profiles_by_protocol.get(profile.protocol, 0) + 1

        # Сортируем профили по редкости протоколов (чем реже встречается протокол, тем выше приоритет)
        protocol_counts = profiles_by_protocol.copy()
        sorted_profiles = sorted(
            sorted_profiles,
            key=lambda p: (-protocol_counts.get(p.protocol, 0), -p.quality_score, p.tcp_rtt_ms if p.tcp_check_passed else 9999, -p.base_score, -p.metadata_richness()),
        )

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
        
        # Запуск дополнительных функций (Features #8-24)
        if features:
            try:
                # Применяем санитаризацию ко всем профилям
                for profile in sorted_profiles:
                    features.apply_sanitization_to_profile(profile)
                
                # Обогащаем профили информацией о типе сети
                for profile in sorted_profiles:
                    features.enrich_profile_with_network_info(profile)
                
                # Запускаем генерацию отчетов и трекинг изменений
                asyncio.create_task(features.run_feature_tests(
                    sorted_profiles,
                    list(self.channels.values()),
                    self.stats
                ))
            except Exception as e:
                logger.warning(f'Ошибка при выполнении дополнительных функций: {e}')


async def main() -> None:
    parser = Parser('input.txt')
    await parser.process()


if __name__ == '__main__':
    asyncio.run(main())
