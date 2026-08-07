import re
import base64
import json
import logging
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)

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

def aggressive_deduplicate(profiles):
    """Применяет все возможные фильтры для сокращения объема профилей."""
    initial_count = len(profiles)
    logger.info(f"Запуск глубокой дедупликации. Исходное количество: {initial_count}")
    
    unique_profiles = {}
    seen_host_port = set()

    for p in profiles:
        key = normalize_profile(p)
        if not key:
            continue
            
        # Уровень 1: Строгая дедупликация (одинаковые URI/настройки)
        if key in unique_profiles:
            continue

        # Уровень 2: Дедупликация по IP:Port (оставляем только 1 профиль на 1 сервер:порт)
        # Это радикально сократит количество, убрав дубликаты серверов с разными UUID
        hp = get_host_port(p)
        if hp and hp in seen_host_port:
            continue
            
        if hp:
            seen_host_port.add(hp)
            
        unique_profiles[key] = p

    final_profiles = list(unique_profiles.values())
    final_count = len(final_profiles)
    logger.info(f"Дедупликация завершена. Удалено дубликатов: {initial_count - final_count}. Осталось: {final_count}")
    
    return final_profiles
