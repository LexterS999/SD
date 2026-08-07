#!/usr/bin/env python3
"""
Модуль дедупликации профилей протоколов
Использует множественные стратегии для сокращения количества дубликатов
"""

import re
import hashlib
from typing import Dict, List, Set, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class DedupStats:
    """Статистика дедупликации"""
    total_profiles: int = 0
    after_host_port_dedup: int = 0
    after_config_hash_dedup: int = 0
    after_similar_config_dedup: int = 0
    after_ip_similarity_dedup: int = 0
    final_count: int = 0
    removed_duplicates: int = 0
    
    def summary(self) -> str:
        return (
            f"Дедупликация: {self.total_profiles} -> {self.final_count} "
            f"(удалено {self.removed_duplicates} дубликатов)"
        )


class ProfileDeduplicator:
    """
    Класс для дедупликации профилей с использованием множественных стратегий
    
    Стратегии:
    1. Дедупликация по host:port (базовая)
    2. Дедупликация по хешу конфигурации
    3. Дедупликация по схожим конфигурациям (нормализация)
    4. Дедупликация по IP-адресам из разных подсетей
    5. Дедупликация по доменным алиасам
    """
    
    # Паттерны для извлечения параметров из конфигураций
    CONFIG_PARAM_PATTERNS = {
        'vless': r'vless://[^@]+@([^:]+):(\d+)',
        'vmess': r'vmess://',
        'trojan': r'trojan://[^@]+@([^:]+):(\d+)',
        'ss': r'ss://([^@]+)@([^:]+):(\d+)',
        'hy2': r'hysteria2?://[^@]+@([^:]+):(\d+)',
        'tuic': r'tuic://[^@]+@([^:]+):(\d+)',
    }
    
    # Известные CDN и прокси-сервисы (группируем по базовым доменам)
    CDN_ALIASES = {
        'cloudflare.com': ['cloudflare.com', 'cdn.cloudflare.net'],
        'workers.dev': ['workers.dev', 'pages.dev'],
        'vercel.app': ['vercel.app', 'now.sh'],
        'netlify.app': ['netlify.app', 'netlify.com'],
        'github.io': ['github.io', 'githubusercontent.com'],
    }
    
    # Подсети для группировки IP
    IP_SUBNET_MASK = 24  # /24 для IPv4
    
    def __init__(self, strict_mode: bool = True):
        """
        Инициализация дедупликатора
        
        Args:
            strict_mode: Если True, использовать строгую дедупликацию (включает уровень 4)
        """
        self.strict_mode = strict_mode
        self.stats = DedupStats()
    
    def normalize_config(self, config: str) -> str:
        """
        Нормализует конфигурацию для сравнения
        
        Удаляет переменные параметры (теги, описания) оставляя только ключевые
        """
        try:
            # Удаляем фрагменты (имена/теги после #)
            if '#' in config:
                config = config.split('#')[0]
            
            # Нормализуем параметры запроса
            if '?' in config:
                base, query = config.split('?', 1)
                # Сортируем параметры для одинакового представления
                params = query.split('&')
                params.sort()
                config = f"{base}?{'&'.join(params)}"
            
            # Удаляем пробелы
            config = config.strip()
            
            return config
        except Exception as e:
            logger.debug(f"Ошибка нормализации конфигурации: {e}")
            return config
    
    def extract_config_signature(self, config: str) -> str:
        """
        Извлекает сигнатуру конфигурации (ключевые параметры)
        
        Возвращает хеш основных параметров для сравнения
        """
        try:
            normalized = self.normalize_config(config)
            
            # Извлекаем только критические параметры
            critical_params = []
            
            # Протокол
            if '://' in normalized:
                protocol = normalized.split('://')[0]
                critical_params.append(f"proto:{protocol}")
            
            # Хост и порт
            match = re.search(r'://[^@]*@?([^:/?#]+)(?::(\d+))?', normalized)
            if match:
                host = match.group(1)
                port = match.group(2) if match.group(2) else ''
                critical_params.append(f"host:{host}")
                if port:
                    critical_params.append(f"port:{port}")
            
            # Ключевые параметры безопасности
            for param in ['security', 'type', 'encryption', 'flow', 'alpn', 'fp']:
                param_match = re.search(rf'(?:^|&){param}=([^&]+)', normalized)
                if param_match:
                    critical_params.append(f"{param}:{param_match.group(1)}")
            
            signature = '|'.join(sorted(critical_params))
            return hashlib.md5(signature.encode()).hexdigest()
            
        except Exception as e:
            logger.debug(f"Ошибка извлечения сигнатуры: {e}")
            return hashlib.md5(normalized.encode()).hexdigest()
    
    def get_canonical_domain(self, domain: str) -> str:
        """
        Приводит домен к каноническому виду
        
        Группирует алиасы CDN и прокси-сервисов
        """
        domain = domain.lower().rstrip('.')
        
        for canonical, aliases in self.CDN_ALIASES.items():
            if domain in aliases or domain.endswith('.' + canonical):
                return canonical
        
        return domain
    
    def get_ip_subnet(self, ip: str) -> str:
        """
        Получает подсеть IP-адреса для группировки
        
        Для IPv4 использует /24 маску
        """
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                # IPv4: берем первые 3 октета
                return '.'.join(parts[:3]) + '.0/24'
            else:
                # IPv6: упрощенная группировка по первым 4 сегментам
                ipv6_parts = ip.split(':')
                if len(ipv6_parts) >= 4:
                    return ':'.join(ipv6_parts[:4]) + '::/48'
                return ip
        except Exception:
            return ip
    
    def deduplicate(
        self, 
        profiles: Dict[str, Any], 
        progress_callback=None
    ) -> Dict[str, Any]:
        """
        Выполняет многоуровневую дедупликацию профилей
        
        Args:
            profiles: Словарь профилей {unique_key: profile_object}
            progress_callback: Callback для отображения прогресса
            
        Returns:
            Словарь уникальных профилей
        """
        if not profiles:
            return {}
        
        self.stats = DedupStats()
        self.stats.total_profiles = len(profiles)
        
        # Уровень 1: Базовая дедупликация по host:port
        logger.info("Уровень 1: Дедупликация по host:port...")
        host_port_map: Dict[str, List[Any]] = defaultdict(list)
        
        for key, profile in profiles.items():
            host_port_key = f"{profile.host.lower()}:{profile.port}"
            host_port_map[host_port_key].append((key, profile))
        
        # Выбираем лучший профиль для каждого host:port
        deduped_after_level1 = {}
        for host_port_key, profile_list in host_port_map.items():
            if len(profile_list) > 1:
                # Выбираем профиль с highest quality score
                best_profile = max(profile_list, key=lambda x: x[1].quality_score)
                deduped_after_level1[best_profile[0]] = best_profile[1]
            else:
                deduped_after_level1[profile_list[0][0]] = profile_list[0][1]
        
        self.stats.after_host_port_dedup = len(deduped_after_level1)
        logger.info(f"  После уровня 1: {len(deduped_after_level1)} профилей")
        
        if progress_callback:
            progress_callback("config_hash", len(deduped_after_level1))
        
        # Уровень 2: Дедупликация по хешу конфигурации
        logger.info("Уровень 2: Дедупликация по хешу конфигурации...")
        config_hash_map: Dict[str, Tuple[str, Any]] = {}
        
        for key, profile in deduped_after_level1.items():
            config_hash = hashlib.md5(profile.full_config.encode()).hexdigest()
            
            if config_hash not in config_hash_map:
                config_hash_map[config_hash] = (key, profile)
            else:
                # Сохраняем профиль с лучшим качеством
                existing_key, existing_profile = config_hash_map[config_hash]
                if profile.quality_score > existing_profile.quality_score:
                    config_hash_map[config_hash] = (key, profile)
        
        deduped_after_level2 = dict(config_hash_map.values())
        self.stats.after_config_hash_dedup = len(deduped_after_level2)
        logger.info(f"  После уровня 2: {len(deduped_after_level2)} профилей")
        
        if progress_callback:
            progress_callback("similar_config", len(deduped_after_level2))
        
        # Уровень 3: Дедупликация по схожим конфигурациям (нормализация + расширенная)
        logger.info("Уровень 3: Дедупликация по схожим конфигурациям...")
        config_sig_map: Dict[str, Tuple[str, Any]] = {}
        
        for key, profile in deduped_after_level2.items():
            config_sig = self.extract_config_signature(profile.full_config)
            
            if config_sig not in config_sig_map:
                config_sig_map[config_sig] = (key, profile)
            else:
                existing_key, existing_profile = config_sig_map[config_sig]
                if profile.quality_score > existing_profile.quality_score:
                    config_sig_map[config_sig] = (key, profile)
        
        deduped_after_level3 = dict(config_sig_map.values())
        self.stats.after_similar_config_dedup = len(deduped_after_level3)
        logger.info(f"  После уровня 3: {len(deduped_after_level3)} профилей")
        
        # Уровень 3.5: Дополнительная дедупликация по доменам с одинаковыми параметрами
        logger.info("Уровень 3.5: Дедупликация по доменам с одинаковыми параметрами...")
        domain_params_map: Dict[str, Dict[str, Tuple[str, Any]]] = defaultdict(dict)
        
        for key, profile in deduped_after_level3.items():
            canonical_domain = self.get_canonical_domain(profile.host)
            # Ключ параметров: протокол + порт + security + type
            params_key = f"{profile.protocol}:{profile.port}"
            if profile.metadata:
                security = profile.metadata.get('params', {}).get('security', 'none')
                ptype = profile.metadata.get('params', {}).get('type', 'tcp')
                params_key += f":{security}:{ptype}"
            
            if params_key not in domain_params_map[canonical_domain]:
                domain_params_map[canonical_domain][params_key] = (key, profile)
            else:
                existing_key, existing_profile = domain_params_map[canonical_domain][params_key]
                if profile.quality_score > existing_profile.quality_score:
                    domain_params_map[canonical_domain][params_key] = (key, profile)
        
        deduped_after_level35 = {}
        for domain_dict in domain_params_map.values():
            for entry in domain_dict.values():
                deduped_after_level35[entry[0]] = entry[1]
        
        logger.info(f"  После уровня 3.5: {len(deduped_after_level35)} профилей")
        deduped_after_level3 = deduped_after_level35
        self.stats.after_similar_config_dedup = len(deduped_after_level3)
        
        if progress_callback:
            progress_callback("ip_similarity", len(deduped_after_level3))
        
        # Уровень 4: Дедупликация по IP-подсетям (только в strict_mode)
        if self.strict_mode:
            logger.info("Уровень 4: Дедупликация по IP-подсетям...")
            subnet_map: Dict[str, Dict[str, Tuple[str, Any]]] = defaultdict(dict)
            
            for key, profile in deduped_after_level3.items():
                # Определяем подсеть
                if profile.ip_address:
                    subnet = self.get_ip_subnet(profile.ip_address)
                else:
                    # Используем канонический домен
                    subnet = self.get_canonical_domain(profile.host)
                
                protocol = profile.protocol
                
                # Для каждой подсети и протокола выбираем лучший профиль
                entry_key = f"{subnet}:{protocol}"
                if entry_key not in subnet_map or \
                   profile.quality_score > subnet_map[entry_key][1].quality_score:
                    subnet_map[entry_key] = (key, profile)
            
            deduped_after_level4 = dict(subnet_map.values())
            self.stats.after_ip_similarity_dedup = len(deduped_after_level4)
            logger.info(f"  После уровня 4: {len(deduped_after_level4)} профилей")
            
            final_profiles = deduped_after_level4
        else:
            self.stats.after_ip_similarity_dedup = len(deduped_after_level3)
            final_profiles = deduped_after_level3
        
        self.stats.final_count = len(final_profiles)
        self.stats.removed_duplicates = self.stats.total_profiles - self.stats.final_count
        
        logger.info(f"Итого: {self.stats.summary()}")
        
        return final_profiles
    
    def get_stats(self) -> DedupStats:
        """Возвращает статистику последней дедупликации"""
        return self.stats


def run_deduplication(profiles: Dict[str, Any], strict_mode: bool = False) -> Tuple[Dict[str, Any], DedupStats]:
    """
    convenience функция для запуска дедупликации
    
    Args:
        profiles: Словарь профилей для дедупликации
        strict_mode: Строгий режим дедупликации
        
    Returns:
        Кортеж (уникальные профили, статистика)
    """
    deduplicator = ProfileDeduplicator(strict_mode=strict_mode)
    unique_profiles = deduplicator.deduplicate(profiles)
    return unique_profiles, deduplicator.get_stats()


if __name__ == '__main__':
    # Тестовый запуск
    logging.basicConfig(level=logging.INFO)
    
    print("Модуль дедупликации профилей готов к использованию")
    print("Импортируйте run_deduplication() для использования в parser.py")
