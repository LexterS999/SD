#!/usr/bin/env python3
"""
Парсер Telegram-каналов и протоколов из внешних подписок
Собирает профили VLESS, Trojan, SS, VMess, TUIC, HY2 из подписок и Telegram-каналов
Оценивает качество каналов и профилей, удаляет дубликаты по IP/домену
Применяет многоуровневую дедупликацию для сокращения количества профилей
"""

import re
import base64
import json
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
import asyncio
import aiohttp
import logging

# Импорт модуля дедупликации
from dedup import run_deduplication, DedupStats

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


@dataclass
class ProtocolProfile:
    """Класс для хранения профиля протокола"""
    protocol: str
    host: str
    port: str
    full_config: str
    ip_address: str = ""
    quality_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_unique_key(self) -> str:
        """Возвращает уникальный ключ на основе IP/домена и порта"""
        identifier = f"{self.ip_address or self.host}:{self.port}"
        return hashlib.md5(identifier.encode()).hexdigest()


@dataclass
class TelegramChannel:
    """Класс для хранения информации о Telegram-канале"""
    username: str
    url: str
    profiles_count: int = 0
    quality_score: float = 0.0
    last_updated: Optional[datetime] = None
    protocols_found: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_unique_key(self) -> str:
        """Возвращает уникальный ключ канала"""
        return self.username.lower()


class QualityEvaluator:
    """Многоуровневая система оценки качества каналов и профилей"""
    
    # Веса для различных факторов оценки
    WEIGHTS = {
        'profile_count': 0.25,      # Количество профилей
        'protocol_diversity': 0.20,  # Разнообразие протоколов
        'update_frequency': 0.20,   # Частота обновлений
        'config_validity': 0.20,    # Валидность конфигураций
        'domain_reputation': 0.15   # Репутация домена
    }
    
    # Известные ненадежные домены
    SUSPICIOUS_DOMAINS = {
        'temp-mail.org', 'guerrillamail.com', 'mailinator.com'
    }
    
    @classmethod
    def evaluate_channel(cls, channel: TelegramChannel, 
                        all_channels: List[TelegramChannel]) -> float:
        """Оценивает качество Telegram-канала"""
        scores = {}
        
        # Оценка по количеству профилей (логарифмическая шкала)
        if channel.profiles_count > 0:
            import math
            max_profiles = max((c.profiles_count for c in all_channels), default=1)
            scores['profile_count'] = math.log1p(channel.profiles_count) / math.log1p(max_profiles)
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
        
        # Оценка валидности конфигураций (базовая)
        total_configs = sum(channel.protocols_found.values())
        if total_configs > 0:
            scores['config_validity'] = min(total_configs / 100, 1.0)
        else:
            scores['config_validity'] = 0
        
        # Оценка репутации домена
        scores['domain_reputation'] = 1.0
        if any(susp in channel.url for susp in cls.SUSPICIOUS_DOMAINS):
            scores['domain_reputation'] = 0.3
        
        # Итоговая оценка
        quality_score = sum(
            scores.get(key, 0) * weight 
            for key, weight in cls.WEIGHTS.items()
        )
        
        return round(quality_score * 100, 2)
    
    @classmethod
    def evaluate_profile(cls, profile: ProtocolProfile) -> float:
        """Оценивает качество профиля протокола"""
        score = 50.0  # Базовая оценка
        
        # Бонус за наличие IP
        if profile.ip_address:
            score += 10
        
        # Проверка порта (стандартные порты более надежны)
        standard_ports = {'443', '80', '8443', '8080', '22'}
        if profile.port in standard_ports:
            score += 5
        
        # Проверка домена
        if profile.host and not any(
            susp in profile.host for susp in cls.SUSPICIOUS_DOMAINS
        ):
            score += 10
        
        # Бонус за метаданные
        if profile.metadata:
            score += min(len(profile.metadata) * 2, 15)
        
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
    def extract_protocols(cls, text: str) -> List[ProtocolProfile]:
        """Извлекает все протоколы из текста"""
        profiles = []
        
        for protocol, pattern in cls.PROTOCOL_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                try:
                    profile = cls.parse_protocol(match, protocol)
                    if profile:
                        profiles.append(profile)
                except Exception as e:
                    logger.debug(f"Ошибка при парсинге {protocol}: {e}")
        
        return profiles
    
    @classmethod
    def extract_telegram_channels(cls, text: str) -> Set[str]:
        """Извлекает Telegram-каналы из текста"""
        channels = set()
        
        for pattern in cls.TG_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Очищаем username
                username = match.strip().lstrip('@').lstrip('+')
                if len(username) >= 5:
                    channels.add(username.lower())
        
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
            
            # Парсим URL
            if '#' in config_data:
                config_part, fragment = config_data.split('#', 1)
            else:
                config_part = config_data
                fragment = ''
            
            # UUID@host:port
            if '@' in config_part:
                uuid_part, rest = config_part.split('@', 1)
                
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
                            'params': {k: v[0] if v else '' for k, v in params.items()},
                            'fragment': fragment
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
            
            # Пробуем декодировать base64 часть
            if '@' in config_data:
                encoded_part, rest = config_data.split('@', 1)
                try:
                    decoded = base64.b64decode(encoded_part).decode('utf-8')
                    if ':' in decoded:
                        method_password, host_port = decoded.rsplit('@', 1)
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
        'https://api.telegram.org/s/{channel}',
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
                                    if isinstance(msg, dict) and 'text' in msg:
                                        messages.append(msg['text'])
                            elif isinstance(data, dict):
                                if 'messages' in data:
                                    for msg in data['messages']:
                                        if isinstance(msg, dict) and 'text' in msg:
                                            messages.append(msg['text'])
                                elif 'result' in data:
                                    # Telegram Bot API формат
                                    pass
                            
                            if messages:
                                logger.info(f"Получено {len(messages)} сообщений из @{channel}")
                                break
                except Exception as e:
                    logger.debug(f"Ошибка при получении @{channel}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Ошибка при обработке канала @{channel}: {e}")
        
        return messages


class Parser:
    """Основной класс парсера"""
    
    def __init__(self, input_file: str = 'input.txt'):
        self.input_file = input_file
        self.subscriptions: Dict[str, str] = {}
        self.channels: Dict[str, TelegramChannel] = {}
        self.profiles: Dict[str, ProtocolProfile] = {}
        self.seen_hosts: Set[str] = set()
    
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
                unique_key = profile.get_unique_key()
                if unique_key not in self.profiles:
                    profile.quality_score = QualityEvaluator.evaluate_profile(profile)
                    self.profiles[unique_key] = profile
            
            # Извлечение Telegram-каналов
            tg_channels = ProtocolParser.extract_telegram_channels(content)
            for channel_username in tg_channels:
                if channel_username not in self.channels:
                    self.channels[channel_username] = TelegramChannel(
                        username=channel_username,
                        url=f"https://t.me/{channel_username}"
                    )
        
        logger.info(f"Найдено {len(self.channels)} Telegram-каналов")
        logger.info(f"Найдено {len(self.profiles)} уникальных профилей")
        
        # Второй проход: получение данных из Telegram-каналов
        if self.channels:
            logger.info("Получение данных из Telegram-каналов...")
            await self.process_telegram_channels()
        
        # Оценка качества каналов
        logger.info("Оценка качества каналов...")
        self.evaluate_channels()
        
        # Применение дедупликации профилей
        logger.info("Применение многоуровневой дедупликации профилей...")
        self.profiles, dedup_stats = run_deduplication(self.profiles, strict_mode=False)
        logger.info(f"Результат дедупликации: {dedup_stats.summary()}")

        # Сохранение результатов
        logger.info("Сохранение результатов...")
        self.save_results(dedup_stats)
        logger.info("Процесс завершен")
    
    async def process_telegram_channels(self):
        """Обрабатывает Telegram-каналы и извлекает протоколы"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for channel in self.channels.values():
                tasks.append(
                    TelegramChannelFetcher.fetch_channel_messages(
                        session, 
                        channel.username,
                        days=7
                    )
                )
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for channel, messages in zip(self.channels.values(), results):
                if isinstance(messages, list):
                    all_text = '\n'.join(str(m) for m in messages if m)
                    
                    # Извлечение протоколов из сообщений
                    profiles = ProtocolParser.extract_protocols(all_text)
                    for profile in profiles:
                        unique_key = profile.get_unique_key()
                        if unique_key not in self.profiles:
                            profile.quality_score = QualityEvaluator.evaluate_profile(profile)
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
    
    def save_results(self, dedup_stats=None):
        """Сохраняет результаты в файлы"""
        # Сортировка профилей по качеству
        sorted_profiles = sorted(
            self.profiles.values(),
            key=lambda p: p.quality_score,
            reverse=True
        )
        
        # Сохранение профилей
        with open('protocols.txt', 'w', encoding='utf-8') as f:
            f.write("# Уникальные профили протоколов, отсортированные по качеству\n")
            f.write(f"# Всего профилей: {len(sorted_profiles)}\n")
            f.write(f"# Дата генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#\n")
            f.write("# Формат: [Качество: XX.XX] протокол://конфигурация\n")
            f.write("#\n\n")
            
            for i, profile in enumerate(sorted_profiles, 1):
                f.write(f"[{i}] [Quality: {profile.quality_score:.2f}] {profile.full_config}\n")
        
        # Сортировка каналов по качеству
        sorted_channels = sorted(
            self.channels.values(),
            key=lambda c: c.quality_score,
            reverse=True
        )
        
        # Сохранение каналов
        with open('best_channels.txt', 'w', encoding='utf-8') as f:
            f.write("# Лучшие Telegram-каналы, отсортированные по качеству\n")
            f.write(f"# Всего каналов: {len(sorted_channels)}\n")
            f.write(f"# Дата генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#\n")
            f.write("# Формат: [Качество: XX.XX] @username - Профилей: N - Протоколы: ...\n")
            f.write("#\n\n")
            
            for i, channel in enumerate(sorted_channels, 1):
                protocols_str = ', '.join(
                    f"{proto}: {count}" 
                    for proto, count in channel.protocols_found.items()
                )
                f.write(
                    f"[{i}] [Quality: {channel.quality_score:.2f}] "
                    f"@{channel.username} - Профилей: {channel.profiles_count} - "
                    f"Протоколы: {protocols_str or 'нет данных'}\n"
                    f"    URL: {channel.url}\n\n"
                )
        
        # Сохранение статистики
        stats = {
            'total_subscriptions': len(self.subscriptions),
            'total_channels': len(self.channels),
            'total_profiles': len(self.profiles),
            'profiles_by_protocol': defaultdict(int),
            'timestamp': datetime.now().isoformat()
        }
        
        for profile in self.profiles.values():
            stats['profiles_by_protocol'][profile.protocol] += 1
        
        with open('stats.json', 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Сохранено {len(sorted_profiles)} профилей в protocols.txt")
        logger.info(f"Сохранено {len(sorted_channels)} каналов в best_channels.txt")


async def main():
    """Точка входа"""
    parser = Parser('input.txt')
    await parser.process()


if __name__ == '__main__':
    asyncio.run(main())
