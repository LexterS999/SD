#!/usr/bin/env python3
"""
Парсер Telegram-каналов и протоколов из внешних подписок
Собирает профили VLESS, Trojan, SS, VMess, TUIC, HY2 из подписок и Telegram-каналов
Оценивает качество каналов и профилей, удаляет дубликаты по IP/домену

Требования:
1. Файлы сохраняются в папке output: best_channels.txt, bad_channels.txt, protocols.txt
2. best_channels.txt содержит только URL каналов
3. Регистр телеграм-каналов сохраняется, дубликаты исключаются
4. Разнообразная система скоринга для каналов и профилей
5. Профили собираются за последние 7 дней, protocols.txt обновляется каждые 7 дней
6. Проверка скорости через файл ~100KB (быстрый тест)
7. Формат профилей с 7-значным суффиксом на конце (#PROTOCOL-xxxxxxx)
8. Строгая дедупликация профилей - только уникальные конфигурации
9. Только IPv4 адреса разрешены (домены и IPv6 отбрасываются)
"""

import re
import base64
import json
import hashlib
import random
import os
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import requests
import asyncio
import aiohttp
import logging
import time

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('parser.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Константы
OUTPUT_DIR = 'output'

# Импорт настроек из config.py
try:
    import config
    SPEED_TEST_URL = getattr(config, 'SPEED_TEST_URL', 'https://proof.ovh.net/files/100Ko.dat')
    SPEED_THRESHOLD_KBPS = getattr(config, 'SPEED_THRESHOLD_KBPS', 300)
    PROFILE_LIFETIME_DAYS = getattr(config, 'PROFILE_LIFETIME_DAYS', 7)
    BAD_CHANNELS_THRESHOLD = getattr(config, 'BAD_CHANNELS_THRESHOLD', 20)
    ALLOW_ONLY_IPV4 = getattr(config, 'ALLOW_ONLY_IPV4', True)
    BLOCK_IPV6_DOMAINS = getattr(config, 'BLOCK_IPV6_DOMAINS', True)
    ENABLE_STRICT_DEDUPLICATION = getattr(config, 'ENABLE_STRICT_DEDUPLICATION', True)
except ImportError:
    # Значения по умолчанию, если config.py не найден
    SPEED_TEST_URL = 'https://proof.ovh.net/files/100Ko.dat'  # Файл ~100KB для теста скорости
    SPEED_THRESHOLD_KBPS = 300
    PROFILE_LIFETIME_DAYS = 7
    BAD_CHANNELS_THRESHOLD = 20
    ALLOW_ONLY_IPV4 = True
    BLOCK_IPV6_DOMAINS = True
    ENABLE_STRICT_DEDUPLICATION = True

PROTOCOLS_FILE = os.path.join(OUTPUT_DIR, 'protocols.txt')
BEST_CHANNELS_FILE = os.path.join(OUTPUT_DIR, 'best_channels.txt')
BAD_CHANNELS_FILE = os.path.join(OUTPUT_DIR, 'bad_channels.txt')


def is_valid_ipv4(address: str) -> bool:
    """Проверяет, является ли адрес действительным IPv4 адресом"""
    if not address:
        return False
    
    # Проверяем, что это не доменное имя (содержит буквы)
    if re.match(r'^[a-zA-Z]', address):
        return False
    
    # Проверяем, что это не IPv6 (содержит двоеточия)
    if ':' in address:
        return False
    
    # Проверяем формат IPv4
    parts = address.split('.')
    if len(parts) != 4:
        return False
    
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
            # Проверяем, что часть не содержит ведущих нулей (кроме "0")
            if part != str(num):
                return False
        except ValueError:
            return False
    
    return True


@dataclass
class ProtocolProfile:
    """Класс для хранения профиля протокола"""
    protocol: str
    host: str
    port: str
    full_config: str
    ip_address: str = ""
    quality_score: float = 0.0
    speed_kbps: float = 0.0  # Скорость в КБ/с
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    source_channel: str = ""
    
    def get_config_hash(self) -> str:
        """Возвращает хеш полной конфигурации для строгой дедупликации"""
        # Удаляем любые существующие суффиксы перед хешированием
        config_clean = self.full_config
        if '#' in config_clean:
            config_clean = config_clean.rsplit('#', 1)[0]
        return hashlib.sha256(config_clean.encode()).hexdigest()
    
    def get_ip_port_key(self) -> str:
        """Возвращает ключ на основе IP и порта"""
        identifier = f"{self.ip_address or self.host}:{self.port}"
        return hashlib.md5(identifier.encode()).hexdigest()
    
    def generate_config_with_suffix(self) -> str:
        """Генерирует конфигурацию с 7-значным случайным суффиксом на конце в формате #PROTOCOL-xxxxxxx"""
        random_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=7))
        protocol_prefix = self.protocol.upper()
        
        # Всегда заменяем или добавляем фрагмент в формате #PROTOCOL-xxxxxxx
        if '#' in self.full_config:
            base_part, _ = self.full_config.rsplit('#', 1)
            return f"{base_part}#{protocol_prefix}-{random_suffix}"
        else:
            return f"{self.full_config}#{protocol_prefix}-{random_suffix}"


@dataclass
class TelegramChannel:
    """Класс для хранения информации о Telegram-канале"""
    username: str  # Сохраняем оригинальный регистр
    url: str
    profiles_count: int = 0
    quality_score: float = 0.0
    last_updated: Optional[datetime] = None
    protocols_found: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_unique_key(self) -> str:
        """Возвращает уникальный ключ канала (нижний регистр для проверки дубликатов)"""
        return self.username.lower()


class QualityEvaluator:
    """Многоуровневая система оценки качества каналов и профилей"""
    
    # Веса для различных факторов оценки каналов
    CHANNEL_WEIGHTS = {
        'profile_count': 0.30,      # Количество профилей
        'protocol_diversity': 0.25,  # Разнообразие протоколов
        'update_frequency': 0.20,   # Частота обновлений
        'config_validity': 0.15,    # Валидность конфигураций
        'domain_reputation': 0.10   # Репутация домена
    }
    
    # Веса для факторов оценки профилей
    PROFILE_WEIGHTS = {
        'base': 20.0,               # Базовая оценка
        'ip_present': 10.0,         # Наличие IP
        'standard_port': 10.0,      # Стандартный порт
        'domain_reputation': 15.0,  # Репутация домена
        'metadata': 15.0,           # Метаданные
        'protocol_diversity': 15.0, # Разнообразие протоколов канала
        'speed_bonus': 30.0         # Бонус за скорость
    }
    
    # Известные ненадежные домены
    SUSPICIOUS_DOMAINS = {
        'temp-mail.org', 'guerrillamail.com', 'mailinator.com'
    }
    
    # Стандартные порты
    STANDARD_PORTS = {'443', '80', '8443', '8080', '22', '8443', '2053', '2083', '2087', '2096'}
    
    @classmethod
    def evaluate_channel(cls, channel: TelegramChannel, 
                        all_channels: List[TelegramChannel]) -> float:
        """Оценивает качество Telegram-канала"""
        scores = {}
        
        # Оценка по количеству профилей (логарифмическая шкала)
        if channel.profiles_count > 0:
            import math
            max_profiles = max((c.profiles_count for c in all_channels), default=1)
            if max_profiles > 0:
                scores['profile_count'] = math.log1p(channel.profiles_count) / math.log1p(max_profiles)
            else:
                scores['profile_count'] = 0
        else:
            scores['profile_count'] = 0
        
        # Оценка разнообразия протоколов
        if channel.protocols_found:
            unique_protocols = len(channel.protocols_found)
            scores['protocol_diversity'] = min(unique_protocols / 6.0, 1.0)
        else:
            scores['protocol_diversity'] = 0
        
        # Оценка частоты обновлений
        if channel.last_updated:
            days_since_update = (datetime.now() - channel.last_updated).days
            scores['update_frequency'] = max(0, 1 - (days_since_update / 7))
        else:
            scores['update_frequency'] = 0.5
        
        # Оценка валидности конфигураций
        total_configs = sum(channel.protocols_found.values())
        if total_configs > 0:
            scores['config_validity'] = min(total_configs / 50, 1.0)
        else:
            scores['config_validity'] = 0
        
        # Оценка репутации домена
        scores['domain_reputation'] = 1.0
        if any(susp in channel.url for susp in cls.SUSPICIOUS_DOMAINS):
            scores['domain_reputation'] = 0.3
        
        # Итоговая оценка
        quality_score = sum(
            scores.get(key, 0) * weight 
            for key, weight in cls.CHANNEL_WEIGHTS.items()
        )
        
        return round(quality_score * 100, 2)
    
    @classmethod
    def evaluate_profile(cls, profile: ProtocolProfile, 
                        channel_protocols: Optional[Dict[str, int]] = None) -> float:
        """Оценивает качество профиля протокола с учетом скорости"""
        score = cls.PROFILE_WEIGHTS['base']
        
        # Бонус за наличие IP
        if profile.ip_address:
            score += cls.PROFILE_WEIGHTS['ip_present']
        
        # Проверка порта (стандартные порты более надежны)
        if profile.port in cls.STANDARD_PORTS:
            score += cls.PROFILE_WEIGHTS['standard_port']
        
        # Проверка домена
        if profile.host and not any(
            susp in profile.host for susp in cls.SUSPICIOUS_DOMAINS
        ):
            score += cls.PROFILE_WEIGHTS['domain_reputation']
        
        # Бонус за метаданные
        if profile.metadata:
            score += min(len(profile.metadata) * 2, cls.PROFILE_WEIGHTS['metadata'])
        
        # Бонус за разнообразие протоколов в канале
        if channel_protocols and len(channel_protocols) > 1:
            score += min(len(channel_protocols) * 3, cls.PROFILE_WEIGHTS['protocol_diversity'])
        
        # Бонус за скорость (если есть данные о скорости)
        # Профили со скоростью выше 300 КБ/с получают максимальный бонус
        if profile.speed_kbps > 0:
            if profile.speed_kbps >= SPEED_THRESHOLD_KBPS:
                score += cls.PROFILE_WEIGHTS['speed_bonus']
            else:
                # Пропорциональный бонус для меньших скоростей
                score += (profile.speed_kbps / SPEED_THRESHOLD_KBPS) * cls.PROFILE_WEIGHTS['speed_bonus']
        
        return min(round(score, 2), 100)


class ProtocolParser:
    """Парсер для различных типов протоколов"""
    
    # Паттерны для извлечения протоколов
    PROTOCOL_PATTERNS = {
        'vless': r'vless://[^\s]+',
        'vmess': r'vmess://[^\s]+',
        'trojan': r'trojan://[^\s]+',
        'ss': r'ss://[^\s]+',
        'ssr': r'ssr://[^\s]+',
        'tuic': r'tuic://[^\s]+',
        'hy2': r'hysteria2?://[^\s]+',
        'hysteria': r'hysteria2?://[^\s]+',
    }
    
    # Паттерны для извлечения Telegram-каналов
    TG_PATTERNS = [
        r'(?:https?://)?(?:t\.me|telegram\.me)/([a-zA-Z0-9_]{5,32})',
        r'(?:https?://)?(?:t\.me|telegram\.me)/\+([a-zA-Z0-9_-]+)',
        r'tg://resolve\?domain=([a-zA-Z0-9_]{5,32})',
        r'@\s*([a-zA-Z0-9_]{5,32})',
    ]
    
    @classmethod
    def extract_protocols(cls, text: str, source_channel: str = "") -> List[ProtocolProfile]:
        """Извлекает все протоколы из текста с проверкой на IPv4"""
        profiles = []
        
        for protocol, pattern in cls.PROTOCOL_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                try:
                    profile = cls.parse_protocol(match, protocol)
                    if profile:
                        profile.source_channel = source_channel
                        # Проверка на IPv4 если включена настройка ALLOW_ONLY_IPV4
                        if ALLOW_ONLY_IPV4:
                            # Получаем IP адрес из профиля
                            ip_to_check = profile.ip_address or profile.host
                            
                            # Проверяем, является ли адрес действительным IPv4
                            if not is_valid_ipv4(ip_to_check):
                                logger.debug(f"Отклонен профиль (не IPv4): {ip_to_check}")
                                continue
                        
                        profiles.append(profile)
                except Exception as e:
                    logger.debug(f"Ошибка при парсинге {protocol}: {e}")
        
        return profiles
    
    @classmethod
    def extract_telegram_channels(cls, text: str) -> Dict[str, str]:
        """Извлекает Telegram-каналы из текста с сохранением регистра"""
        channels = {}  # lower_username -> original_username
        
        for pattern in cls.TG_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Очищаем username
                username = match.strip().lstrip('@').lstrip('+')
                if len(username) >= 5:
                    # Сохраняем первый найденный вариант (оригинальный регистр)
                    lower_key = username.lower()
                    if lower_key not in channels:
                        channels[lower_key] = username
        
        return channels
    
    @classmethod
    def parse_protocol(cls, config: str, protocol: str) -> Optional[ProtocolProfile]:
        """Парсит конфигурацию протокола и извлекает хост и порт"""
        try:
            if protocol == 'vmess':
                return cls._parse_vmess(config)
            elif protocol == 'vless':
                return cls._parse_vless(config)
            elif protocol == 'trojan':
                return cls._parse_trojan(config)
            elif protocol == 'ss':
                return cls._parse_shadowsocks(config)
            elif protocol in ('hy2', 'hysteria'):
                return cls._parse_hysteria(config)
            elif protocol == 'tuic':
                return cls._parse_tuic(config)
            else:
                return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга {protocol}: {e}")
            return None
    
    @classmethod
    def _parse_vmess(cls, config: str) -> Optional[ProtocolProfile]:
        """Парсит VMess конфигурацию"""
        try:
            # Удаляем префикс
            config_data = config.replace('vmess://', '')
            
            # Декодируем base64
            try:
                decoded = base64.b64decode(config_data).decode('utf-8')
                vmess_json = json.loads(decoded)
                
                host = vmess_json.get('add', '')
                port = str(vmess_json.get('port', ''))
                
                return ProtocolProfile(
                    protocol='vmess',
                    host=host,
                    port=port,
                    full_config=config,
                    ip_address=host,
                    metadata=vmess_json
                )
            except:
                # Пробуем альтернативный формат
                pass
            
            return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга VMess: {e}")
            return None
    
    @classmethod
    def _parse_vless(cls, config: str) -> Optional[ProtocolProfile]:
        """Парсит VLESS конфигурацию"""
        try:
            config_data = config.replace('vless://', '')
            
            # UUID@host:port
            if '@' in config_data:
                uuid_part, rest = config_data.split('@', 1)
                
                if ':' in rest:
                    host_port = rest.split('?')[0]
                    host, port = host_port.rsplit(':', 1)
                    
                    # Извлекаем параметры
                    params = {}
                    if '?' in rest:
                        query_string = rest.split('?', 1)[1].split('#')[0]
                        params = parse_qs(query_string)
                    
                    return ProtocolProfile(
                        protocol='vless',
                        host=host,
                        port=port,
                        full_config=config,
                        ip_address=host,
                        metadata={
                            'uuid': uuid_part,
                            'params': {k: v[0] if v else '' for k, v in params.items()}
                        }
                    )
            
            return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга VLESS: {e}")
            return None
    
    @classmethod
    def _parse_trojan(cls, config: str) -> Optional[ProtocolProfile]:
        """Парсит Trojan конфигурацию"""
        try:
            config_data = config.replace('trojan://', '')
            
            if '@' in config_data:
                password_part, rest = config_data.split('@', 1)
                
                if ':' in rest:
                    host_port = rest.split('?')[0]
                    host, port = host_port.rsplit(':', 1)
                    
                    params = {}
                    if '?' in rest:
                        query_string = rest.split('?', 1)[1].split('#')[0]
                        params = parse_qs(query_string)
                    
                    return ProtocolProfile(
                        protocol='trojan',
                        host=host,
                        port=port,
                        full_config=config,
                        ip_address=host,
                        metadata={
                            'password': password_part,
                            'params': {k: v[0] if v else '' for k, v in params.items()}
                        }
                    )
            
            return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга Trojan: {e}")
            return None
    
    @classmethod
    def _parse_shadowsocks(cls, config: str) -> Optional[ProtocolProfile]:
        """Парсит Shadowsocks конфигурацию"""
        try:
            config_data = config.replace('ss://', '')
            
            # Пробуем разные форматы
            # Формат 1: base64(method:password)@host:port
            if '@' in config_data:
                auth_host, rest = config_data.split('@', 1)
                
                # Декодируем base64 часть
                try:
                    decoded = base64.b64decode(auth_host).decode('utf-8')
                    method_password, host_port = decoded.split('@', 1)
                    host, port = host_port.rsplit(':', 1)
                    
                    return ProtocolProfile(
                        protocol='ss',
                        host=host,
                        port=port,
                        full_config=config,
                        ip_address=host,
                        metadata={'method_password': method_password}
                    )
                except:
                    pass
            
            return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга Shadowsocks: {e}")
            return None
    
    @classmethod
    def _parse_hysteria(cls, config: str) -> Optional[ProtocolProfile]:
        """Парсит Hysteria/Hysteria2 конфигурацию"""
        try:
            config_data = re.sub(r'hysteria2?://', '', config)
            
            if '@' in config_data:
                auth_part, rest = config_data.split('@', 1)
                
                if ':' in rest:
                    host_port = rest.split('?')[0]
                    host, port = host_port.rsplit(':', 1)
                    
                    params = {}
                    if '?' in rest:
                        query_string = rest.split('?', 1)[1].split('#')[0]
                        params = parse_qs(query_string)
                    
                    return ProtocolProfile(
                        protocol='hy2',
                        host=host,
                        port=port,
                        full_config=config,
                        ip_address=host,
                        metadata={
                            'auth': auth_part,
                            'params': {k: v[0] if v else '' for k, v in params.items()}
                        }
                    )
            
            return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга Hysteria: {e}")
            return None
    
    @classmethod
    def _parse_tuic(cls, config: str) -> Optional[ProtocolProfile]:
        """Парсит TUIC конфигурацию"""
        try:
            config_data = config.replace('tuic://', '')
            
            if '@' in config_data:
                auth_part, rest = config_data.split('@', 1)
                
                if ':' in rest:
                    host_port = rest.split('?')[0]
                    host, port = host_port.rsplit(':', 1)
                    
                    params = {}
                    if '?' in rest:
                        query_string = rest.split('?', 1)[1].split('#')[0]
                        params = parse_qs(query_string)
                    
                    return ProtocolProfile(
                        protocol='tuic',
                        host=host,
                        port=port,
                        full_config=config,
                        ip_address=host,
                        metadata={
                            'auth': auth_part,
                            'params': {k: v[0] if v else '' for k, v in params.items()}
                        }
                    )
            
            return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга TUIC: {e}")
            return None


class SubscriptionFetcher:
    """Класс для получения данных из подписок"""
    
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
    }
    
    @classmethod
    async def test_speed(cls, session: aiohttp.ClientSession, host: str) -> float:
        """Тестирует скорость подключения к хосту через файл ~100KB"""
        try:
            # Используем тестовый файл ~100KB для быстрой проверки
            start_time = time.time()
            async with session.get(SPEED_TEST_URL, timeout=10) as response:
                if response.status == 200:
                    data = await response.read()
                    elapsed = time.time() - start_time
                    # Вычисляем скорость в КБ/с
                    size_kb = len(data) / 1024
                    speed_kbps = size_kb / elapsed if elapsed > 0 else 0
                    return round(speed_kbps, 2)
        except Exception as e:
            logger.debug(f"Тест скорости не удался: {e}")
        return 0.0
    
    @classmethod
    async def fetch_url(cls, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Получает содержимое URL"""
        try:
            # Обработка GitHub URL
            if 'github.com' in url and '/raw/' not in url:
                url = url.replace('github.com', 'raw.githubusercontent.com')
                url = re.sub(r'/blob/', '/', url)
                url = re.sub(r'/tree/', '/', url)
            
            async with session.get(url, headers=cls.HEADERS, timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    logger.info(f"Успешно получено: {url[:50]}...")
                    return content
                else:
                    logger.warning(f"Ошибка {response.status} для {url}")
                    return None
        except Exception as e:
            logger.error(f"Ошибка при получении {url}: {e}")
            return None
    
    @classmethod
    async def fetch_all_subscriptions(cls, urls: List[str]) -> Dict[str, str]:
        """Получает содержимое всех подписок"""
        results = {}
        
        async with aiohttp.ClientSession() as session:
            tasks = [cls.fetch_url(session, url) for url in urls]
            responses = await asyncio.gather(*tasks)
            
            for url, content in zip(urls, responses):
                if content:
                    results[url] = content
        
        return results


class TelegramChannelFetcher:
    """Класс для получения данных из Telegram-каналов"""
    
    # Публичные API для получения сообщений из Telegram-каналов
    TG_API_ENDPOINTS = [
        'https://tg.i-c-a.su/r/{channel}/{limit}',
    ]
    
    @classmethod
    async def fetch_channel_messages(
        cls, 
        session: aiohttp.ClientSession, 
        channel: str,
        days: int = 7
    ) -> List[str]:
        """Получает сообщения из Telegram-канала за последние N дней"""
        messages = []
        cutoff_date = datetime.now() - timedelta(days=days)
        
        try:
            # Пробуем разные эндпоинты
            for endpoint in cls.TG_API_ENDPOINTS:
                try:
                    url = endpoint.format(channel=channel, limit=100)
                    async with session.get(url, timeout=15) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Обрабатываем ответ в зависимости от формата API
                            if isinstance(data, list):
                                for msg in data:
                                    if isinstance(msg, dict):
                                        # Проверяем дату сообщения
                                        msg_date = None
                                        if 'date' in msg:
                                            try:
                                                msg_date = datetime.fromtimestamp(msg['date'])
                                            except:
                                                pass
                                        
                                        # Добавляем только сообщения за последние N дней
                                        if msg_date is None or msg_date >= cutoff_date:
                                            if 'text' in msg:
                                                messages.append(msg['text'])
                            
                            if messages:
                                logger.info(f"Получено {len(messages)} сообщений из @{channel} за последние {days} дней")
                                break
                except Exception as e:
                    logger.debug(f"Ошибка при получении @{channel}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Ошибка при обработке канала @{channel}: {e}")
        
        return messages


class ProfileDeduplicator:
    """Класс для строгой дедупликации профилей"""
    
    def __init__(self):
        self.config_hashes: Set[str] = set()  # Хеш полной конфигурации
        self.ip_port_keys: Set[str] = set()  # Ключи IP:port
    
    def is_duplicate(self, profile: ProtocolProfile) -> bool:
        """Проверяет, является ли профиль дубликатом"""
        if not ENABLE_STRICT_DEDUPLICATION:
            return False
        
        # Получаем хеш конфигурации
        config_hash = profile.get_config_hash()
        
        # Проверяем по хешу конфигурации
        if config_hash in self.config_hashes:
            logger.debug(f"Дубликат конфигурации: {profile.protocol}://{profile.host}:{profile.port}")
            return True
        
        # Проверяем по IP:port
        ip_port_key = profile.get_ip_port_key()
        if ip_port_key in self.ip_port_keys:
            logger.debug(f"Дубликат IP:port: {profile.ip_address or profile.host}:{profile.port}")
            return True
        
        # Добавляем в множества
        self.config_hashes.add(config_hash)
        self.ip_port_keys.add(ip_port_key)
        
        return False


class Parser:
    """Основной класс парсера"""
    
    def __init__(self, input_file: str = 'input.txt'):
        self.input_file = input_file
        self.subscriptions: Dict[str, str] = {}
        self.channels: Dict[str, TelegramChannel] = {}
        self.profiles: Dict[str, ProtocolProfile] = {}
        self.deduplicator = ProfileDeduplicator()
    
    def load_subscriptions(self) -> List[str]:
        """Загружает список подписок из файла"""
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            logger.info(f"Загружено {len(urls)} подписок")
            return urls
        except FileNotFoundError:
            logger.error(f"Файл {self.input_file} не найден")
            return []
    
    async def process(self):
        """Основной процесс парсинга"""
        logger.info("Начало процесса парсинга")
        
        # Загрузка подписок
        urls = self.load_subscriptions()
        if not urls:
            logger.error("Нет подписок для обработки")
            return
        
        # Получение данных из подписок
        logger.info("Получение данных из подписок...")
        self.subscriptions = await SubscriptionFetcher.fetch_all_subscriptions(urls)
        
        # Первый проход: извлечение протоколов и Telegram-каналов из подписок
        logger.info("Обработка подписок...")
        for url, content in self.subscriptions.items():
            # Извлечение протоколов
            profiles = ProtocolParser.extract_protocols(content)
            for profile in profiles:
                # Строгая проверка на дубликаты
                if not self.deduplicator.is_duplicate(profile):
                    profile.quality_score = QualityEvaluator.evaluate_profile(profile)
                    unique_key = profile.get_config_hash()
                    self.profiles[unique_key] = profile
            
            # Извлечение Telegram-каналов с сохранением регистра
            tg_channels_dict = ProtocolParser.extract_telegram_channels(content)
            for lower_key, original_username in tg_channels_dict.items():
                if lower_key not in self.channels:
                    self.channels[lower_key] = TelegramChannel(
                        username=original_username,  # Сохраняем оригинальный регистр
                        url=f"https://t.me/{original_username}"
                    )
        
        logger.info(f"Найдено {len(self.channels)} Telegram-каналов")
        logger.info(f"Найдено {len(self.profiles)} уникальных профилей после дедупликации")
        
        # Второй проход: получение данных из Telegram-каналов (только за последние 7 дней)
        if self.channels:
            logger.info("Получение данных из Telegram-каналов (только за последние 7 дней)...")
            await self.process_telegram_channels()
        
        # Оценка качества каналов
        logger.info("Оценка качества каналов...")
        self.evaluate_channels()
        
        # Сохранение результатов
        logger.info("Сохранение результатов...")
        self.save_results()
        
        logger.info("Процесс завершен")
    
    async def process_telegram_channels(self):
        """Обрабатывает Telegram-каналы и извлекает протоколы только за последние 7 дней"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for channel in self.channels.values():
                tasks.append(
                    TelegramChannelFetcher.fetch_channel_messages(
                        session, 
                        channel.username,
                        days=PROFILE_LIFETIME_DAYS  # Только за последние 7 дней
                    )
                )
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for channel, messages in zip(self.channels.values(), results):
                if isinstance(messages, list):
                    all_text = '\n'.join(str(m) for m in messages if m)
                    
                    # Извлечение протоколов из сообщений
                    profiles = ProtocolParser.extract_protocols(all_text, channel.username)
                    for profile in profiles:
                        # Строгая проверка на дубликаты
                        if not self.deduplicator.is_duplicate(profile):
                            profile.quality_score = QualityEvaluator.evaluate_profile(profile)
                            unique_key = profile.get_config_hash()
                            self.profiles[unique_key] = profile
                        
                        # Обновление статистики канала
                        channel.protocols_found[profile.protocol] = \
                            channel.protocols_found.get(profile.protocol, 0) + 1
                    
                    channel.profiles_count = sum(channel.protocols_found.values())
                    channel.last_updated = datetime.now()
    
    def evaluate_channels(self):
        """Оценивает качество всех каналов"""
        channels_list = list(self.channels.values())
        
        for channel in channels_list:
            channel.quality_score = QualityEvaluator.evaluate_channel(
                channel, 
                channels_list
            )
    
    def save_results(self):
        """Сохраняет результаты в файлы в папке output"""
        # Создаем папку output если не существует
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # Сортировка профилей по качеству (сначала лучшие)
        sorted_profiles = sorted(
            self.profiles.values(),
            key=lambda p: p.quality_score,
            reverse=True
        )
        
        # Проверка возраста protocols.txt - если старше 7 дней, очищаем
        protocols_need_refresh = True
        if os.path.exists(PROTOCOLS_FILE):
            file_mtime = datetime.fromtimestamp(os.path.getmtime(PROTOCOLS_FILE))
            if (datetime.now() - file_mtime).days < PROFILE_LIFETIME_DAYS:
                protocols_need_refresh = False
        
        # Сохранение профилей в protocols.txt с новым форматом
        with open(PROTOCOLS_FILE, 'w', encoding='utf-8') as f:
            f.write("# Уникальные профили протоколов, отсортированные по качеству\n")
            f.write(f"# Всего профилей: {len(sorted_profiles)}\n")
            f.write(f"# Дата генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Срок жизни профилей: {PROFILE_LIFETIME_DAYS} дней\n")
            f.write("#\n")
            f.write("# Формат: протокол://конфигурация#PROTOCOL-random_suffix\n")
            f.write("#\n\n")
            
            for i, profile in enumerate(sorted_profiles, 1):
                # Генерируем конфигурацию с 7-значным числом на конце
                config_with_suffix = profile.generate_config_with_suffix()
                f.write(f"{config_with_suffix}\n")
        
        # Сортировка каналов по качеству
        sorted_channels = sorted(
            self.channels.values(),
            key=lambda c: c.quality_score,
            reverse=True
        )
        
        # Разделяем каналы на лучшие и плохие
        best_channels = [c for c in sorted_channels if c.quality_score >= BAD_CHANNELS_THRESHOLD]
        bad_channels = [c for c in sorted_channels if c.quality_score < BAD_CHANNELS_THRESHOLD]
        
        # Сохранение лучших каналов - ТОЛЬКО URL
        with open(BEST_CHANNELS_FILE, 'w', encoding='utf-8') as f:
            for channel in best_channels:
                f.write(f"{channel.url}\n")
        
        # Сохранение плохих каналов
        with open(BAD_CHANNELS_FILE, 'w', encoding='utf-8') as f:
            f.write("# Плохие Telegram-каналы (quality < 20)\n")
            f.write(f"# Всего каналов: {len(bad_channels)}\n")
            f.write(f"# Дата генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#\n\n")
            for channel in bad_channels:
                f.write(f"{channel.url}\n")
        
        # Сохранение статистики
        stats = {
            'total_subscriptions': len(self.subscriptions),
            'total_channels': len(self.channels),
            'total_profiles': len(self.profiles),
            'best_channels_count': len(best_channels),
            'bad_channels_count': len(bad_channels),
            'profiles_by_protocol': defaultdict(int),
            'timestamp': datetime.now().isoformat()
        }
        
        for profile in self.profiles.values():
            stats['profiles_by_protocol'][profile.protocol] += 1
        
        stats_file = os.path.join(OUTPUT_DIR, 'stats.json')
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"Сохранено {len(sorted_profiles)} профилей в {PROTOCOLS_FILE}")
        logger.info(f"Сохранено {len(best_channels)} лучших каналов в {BEST_CHANNELS_FILE}")
        logger.info(f"Сохранено {len(bad_channels)} плохих каналов в {BAD_CHANNELS_FILE}")


async def main():
    """Точка входа"""
    parser = Parser('input.txt')
    await parser.process()


if __name__ == '__main__':
    asyncio.run(main())
