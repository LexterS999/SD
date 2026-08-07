import re
import base64
import json
import logging
import os
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)

# Получаем уровень дедупликации из переменной окружения (устанавливается в GitHub Actions)
DEDUP_LEVEL = os.environ.get('DEDUP_LEVEL', 'medium').lower()

def normalize_profile(uri):
    """Нормализует профиль для дедупликации (без вреда для качества)."""
    if not uri or not isinstance(uri, str):
        return None

    uri = uri.strip()
    # Проверяем, является ли строка валидным прокси-URI
    if not re.match(r'^(vless|vmess|trojan|ssr|ss|hysteria2?|tuic)://', uri, re.IGNORECASE):
        return None

    try:
        # Удаляем фрагмент (название профиля), он не влияет на работу
        base_uri = uri.split('#')[0]
        
        # Обработка VMess (Base64)
        if base_uri.lower().startswith('vmess://'):
            try:
                decoded = base64.b64decode(base_uri[8:] + '==').decode('utf-8')
                config = json.loads(decoded)
                # Создаем уникальный ключ на основе сетевых параметров
                key = f"vmess|{config.get('add','').lower()}|{config.get('port')}|{config.get('id','').lower()}|{config.get('net')}|{config.get('tls')}"
                return key
            except Exception:
                return None

        # Обработка SS/SSR
        if base_uri.lower().startswith('ss://'):
            try:
                # ss://base64@host:port или ss://method:pass@host:port
                if '@' in base_uri:
                    user_info, host_info = base_uri[5:].split('@', 1)
                    if not host_info.startswith('http'):
                        host_info = '//' + host_info
                    parsed = urlparse(host_info)
                    host = parsed.hostname
                    port = parsed.port
                    # Если user_info в base64
                    if ':' not in user_info:
                        user_info = base64.b64decode(user_info + '==').decode('utf-8')
                    method, _, password = user_info.partition(':')
                    return f"ss|{host.lower()}|{port}|{method}|{password}"
            except Exception:
                return None

        # Обработка VLESS, Trojan, Hysteria, TUIC
        parsed = urlparse(base_uri)
        host = parsed.hostname
        if not host:
            return None

        port = parsed.port or (443 if parsed.scheme.lower() in ['vless', 'trojan'] else 80)
        password = unquote(parsed.username or '')
        
        # Извлекаем важные query параметры (sni, path, pbk, sid)
        query = parse_qs(parsed.query)
        important_params = ['type', 'host', 'path', 'security', 'sni', 'fp', 'pbk', 'sid', 'sps']
        query_str = "&".join(f"{k}={query[k][0]}" for k in important_params if k in query)

        return f"{parsed.scheme.lower()}|{host.lower()}|{port}|{password}|{query_str}"

    except Exception:
        return None

def get_host_port(uri):
    """Извлекает хост и порт для жесткой дедупликации по IP/Домену."""
    norm = normalize_profile(uri)
    if norm:
        parts = norm.split('|')
        if len(parts) >= 3:
            return f"{parts[1]}:{parts[2]}"
    return None

def get_host_only(uri):
    """Извлекает только хост для сверх-агрессивной дедупликации."""
    norm = normalize_profile(uri)
    if norm:
        parts = norm.split('|')
        if len(parts) >= 2:
            return parts[1]
    return None

def light_deduplicate(profiles):
    """
    ЛЕГКИЙ уровень дедупликации:
    - Удаляет только полные дубликаты (одинаковые URI после нормализации)
    - Сохраняет все профили с разными настройками
    """
    initial_count = len(profiles)
    logger.info(f"[ЛЕГКИЙ] Запуск дедупликации. Исходное количество: {initial_count}")
    
    unique_profiles = {}
    
    for p in profiles:
        key = normalize_profile(p)
        if not key:
            continue
            
        # Только строгая дедупликация по полному ключу
        if key not in unique_profiles:
            unique_profiles[key] = p
    
    final_profiles = list(unique_profiles.values())
    final_count = len(final_profiles)
    logger.info(f"[ЛЕГКИЙ] Дедупликация завершена. Удалено дубликатов: {initial_count - final_count}. Осталось: {final_count}")
    
    return final_profiles

def medium_deduplicate(profiles):
    """
    СРЕДНИЙ уровень дедупликации (по умолчанию):
    - Удаляет полные дубликаты
    - Удаляет дубликаты по IP:Port (один профиль на сервер:порт)
    """
    initial_count = len(profiles)
    logger.info(f"[СРЕДНИЙ] Запуск дедупликации. Исходное количество: {initial_count}")
    
    unique_profiles = {}
    seen_host_port = set()
    
    for p in profiles:
        key = normalize_profile(p)
        if not key:
            continue
            
        # Уровень 1: Строгая дедупликация (одинаковые URI/настройки)
        if key in unique_profiles:
            continue
        
        # Уровень 2: Дедупликация по IP:Port
        hp = get_host_port(p)
        if hp and hp in seen_host_port:
            continue
            
        if hp:
            seen_host_port.add(hp)
            
        unique_profiles[key] = p
    
    final_profiles = list(unique_profiles.values())
    final_count = len(final_profiles)
    logger.info(f"[СРЕДНИЙ] Дедупликация завершена. Удалено дубликатов: {initial_count - final_count}. Осталось: {final_count}")
    
    return final_profiles

def aggressive_deduplicate(profiles):
    """
    АГРЕССИВНЫЙ уровень дедупликации:
    - Удаляет полные дубликаты
    - Удаляет дубликаты по IP:Port
    - Удаляет дубликаты только по хосту (один профиль на домен/IP)
    """
    initial_count = len(profiles)
    logger.info(f"[АГРЕССИВНЫЙ] Запуск дедупликации. Исходное количество: {initial_count}")
    
    unique_profiles = {}
    seen_host_port = set()
    seen_hosts = set()
    
    for p in profiles:
        key = normalize_profile(p)
        if not key:
            continue
            
        # Уровень 1: Строгая дедупликация (одинаковые URI/настройки)
        if key in unique_profiles:
            continue
        
        # Уровень 2: Дедупликация по IP:Port
        hp = get_host_port(p)
        if hp and hp in seen_host_port:
            continue
            
        # Уровень 3: Дедупликация только по хосту
        host = get_host_only(p)
        if host and host in seen_hosts:
            continue
        
        if hp:
            seen_host_port.add(hp)
        if host:
            seen_hosts.add(host)
            
        unique_profiles[key] = p
    
    final_profiles = list(unique_profiles.values())
    final_count = len(final_profiles)
    logger.info(f"[АГРЕССИВНЫЙ] Дедупликация завершена. Удалено дубликатов: {initial_count - final_count}. Осталось: {final_count}")
    
    return final_profiles

def deduplicate(profiles, level=None):
    """
    Универсальная функция дедупликации с выбором уровня.
    
    Args:
        profiles: Список профилей для дедупликации
        level: Уровень дедупликации ('light', 'medium', 'aggressive')
               Если None, используется значение из переменной окружения DEDUP_LEVEL
    """
    if level is None:
        level = DEDUP_LEVEL
    
    if level == 'light':
        return light_deduplicate(profiles)
    elif level == 'aggressive':
        return aggressive_deduplicate(profiles)
    else:  # medium по умолчанию
        return medium_deduplicate(profiles)

# Для обратной совместимости оставляем старую функцию
aggressive_deduplicate_old = aggressive_deduplicate
