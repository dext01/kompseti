import csv
import subprocess
import datetime
import socket
import sys

from pathlib import Path


# Список доменов для проверки
DOMAINS = [
    'ya.ru',
    'google.com',
    'vk.com',
    'github.com',
    'rt.com'
]

MAX_HOPS = 15  # Количество хопов (как в задании)
TIMEOUT_PER_HOP = 2  # Таймаут на хоп в секундах
DNS_TIMEOUT = 10  # Таймаут DNS-запроса

# Пути для сохранения
OUTPUT_DIR = Path.home()  # Домашняя папка пользователя
CSV_FILENAME = f'network_report_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
CSV_PATH = OUTPUT_DIR / CSV_FILENAME


# ================= ФУНКЦИИ =================

def get_dns_ip(domain: str) -> str:
    """
    Выполняет DNS-запрос через dig и возвращает первый IP-адрес.

    Args:
        domain: Доменное имя (например, 'google.com')

    Returns:
        str: IP-адрес или сообщение об ошибке
    """
    try:
        result = subprocess.run(
            ['dig', '+short', domain],
            capture_output=True,
            text=True,
            timeout=DNS_TIMEOUT,
            check=False
        )

        # Получаем все IP, берём первый непустой
        ips = [ip.strip() for ip in result.stdout.strip().split('\n') if ip.strip()]

        if ips:
            return ips[0]
        return "NO_DNS_RESPONSE"

    except subprocess.TimeoutExpired:
        return "DNS_TIMEOUT"
    except FileNotFoundError:
        return "DIG_NOT_INSTALLED"
    except Exception as e:
        return f"DNS_ERROR: {type(e).__name__}"


def run_traceroute(target: str, max_hops: int = MAX_HOPS) -> dict:
    """
    Выполняет traceroute и возвращает структурированный результат.

    Args:
        target: Целевой IP или домен
        max_hops: Максимальное количество прыжков

    Returns:
        dict: {
            'success': bool,
            'hops': list of dicts with hop data,
            'reached_target': bool,
            'raw_output': str
        }
    """
    result = {
        'success': False,
        'hops': [],
        'reached_target': False,
        'raw_output': '',
        'error': None
    }

    try:
        # Команда traceroute:
        # -n : не резолвить имена (быстрее)
        # -m : макс хопов
        # -w : таймаут на ответ от хопа
        # -q 1 : один запрос на хоп (для компактности)
        cmd = [
            'traceroute',
            '-n',  # IP вместо имён
            '-m', str(max_hops),
            '-w', str(TIMEOUT_PER_HOP),
            '-q', '1',  # 1 пакет на хоп
            target
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_hops * TIMEOUT_PER_HOP + 10,  # Общий таймаут
            check=False
        )

        result['raw_output'] = proc.stdout
        result['success'] = True

        # Парсим вывод построчно
        lines = proc.stdout.strip().split('\n')
        target_ip = None

        # Первая строка содержит целевой IP
        if lines and 'traceroute to' in lines[0]:
            import re
            match = re.search(r'\(([\d.]+)\)', lines[0])
            if match:
                target_ip = match.group(1)

        # Парсим каждый хоп
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            hop_data = parse_hop_line(line, target_ip)
            if hop_data:
                result['hops'].append(hop_data)
                # Проверяем, достигли ли цели
                if hop_data.get('ip') == target_ip:
                    result['reached_target'] = True

        return result

    except subprocess.TimeoutExpired:
        result['error'] = f"TIMEOUT after {max_hops * TIMEOUT_PER_HOP + 10}s"
        return result
    except FileNotFoundError:
        result['error'] = "traceroute command not found"
        return result
    except Exception as e:
        result['error'] = f"{type(e).__name__}: {str(e)}"
        return result


def parse_hop_line(line: str, target_ip: str = None) -> dict:
    """
    Парсит одну строку вывода traceroute.

    Пример строки:
      " 5  178.49.128.2  8.709 ms"
      " 7  * * *"

    Returns:
        dict: {'hop_num': int, 'ip': str|None, 'rtt_ms': float|None, 'timeout': bool}
    """
    import re

    line = ' '.join(line.split())


    parts = line.split()
    if len(parts) < 2:
        return None

    try:
        hop_num = int(parts[0])
    except ValueError:
        return None

    hop_data = {
        'hop_num': hop_num,
        'ip': None,
        'rtt_ms': None,
        'timeout': False
    }

    # Проверяем, есть ли звёздочки (таймаут)
    if '*' in parts:
        hop_data['timeout'] = True
        return hop_data

    # Ищем IP-адрес (простая проверка: содержит точки и цифры)
    for part in parts[1:]:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', part):
            hop_data['ip'] = part
            break

    # Ищем время в мс (например, "8.709 ms")
    for i, part in enumerate(parts):
        if part == 'ms' and i > 0:
            try:
                hop_data['rtt_ms'] = float(parts[i - 1])
            except ValueError:
                pass
            break

    return hop_data


def format_traceroute_for_csv(hops: list, max_display: int = 15) -> str:
    """
    Форматирует список хопов в компактную строку для CSV.

    Args:
        hops: Список словарей с данными хопов
        max_display: Сколько хопов показывать в ячейке

    Returns:
        str: Отформатированная строка
    """
    if not hops:
        return "NO_DATA"

    parts = []
    for hop in hops[:max_display]:
        num = hop['hop_num']
        ip = hop.get('ip') or ('*' if hop.get('timeout') else '?')
        rtt = f"{hop['rtt_ms']:.1f}ms" if hop.get('rtt_ms') else '--'
        parts.append(f"H{num}:{ip}({rtt})")

    if len(hops) > max_display:
        parts.append(f"...(+{len(hops) - max_display})")

    return ' | '.join(parts)


def main():
    """Главная функция запуска сканирования."""

    print("=" * 70)
    print("Сканирование сети (DNS + Traceroute)")
    print("=" * 70)

    for cmd in ['dig', 'traceroute']:
        if subprocess.run(['which', cmd], capture_output=True).returncode != 0:
            print(f"Ошибка: утилита '{cmd}' не найдена!")
            print(f"Установите: sudo apt install {'dnsutils' if cmd == 'dig' else 'traceroute'}")
            sys.exit(1)

    print(f"Утилиты найдены")
    print(f"Результат будет сохранён: {CSV_PATH}")
    print(f"Максимальное количество хопов: {MAX_HOPS}")
    print("-" * 70)

    # === ПОДГОТОВКА CSV ===
    csv_headers = [
        'Domain',
        'Resolved_IP',
        'Traceroute_Success',
        'Reached_Target',
        'Total_Hops',
        'Hops_Detail',
        'Error',
        'Timestamp'
    ]

    results = []

    for idx, domain in enumerate(DOMAINS, 1):
        print(f"\n[{idx}/{len(DOMAINS)}] Обработка: {domain}")

        # 1. DNS-запрос
        print(f"DNS-запрос...", end=' ')
        ip = get_dns_ip(domain)
        print(f"{ip}")

        # 2. Traceroute
        print(f" Traceroute (до {MAX_HOPS} хопов)...", end=' ')
        trace_result = run_traceroute(ip if ip and not ip.startswith('ERROR') else domain)

        status = "OK" if trace_result['success'] else "FAIL"
        print(f"{status}")

        if trace_result['error']:
            print(f"Ошибка: {trace_result['error']}")

        # 3. Формируем строку для CSV
        row = {
            'Domain': domain,
            'Resolved_IP': ip,
            'Traceroute_Success': 'Yes' if trace_result['success'] else 'No',
            'Reached_Target': 'Yes' if trace_result.get('reached_target') else 'No',
            'Total_Hops': len(trace_result['hops']),
            'Hops_Detail': format_traceroute_for_csv(trace_result['hops']),
            'Error': trace_result.get('error') or '',
            'Timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        results.append(row)

        if trace_result['success']:
            reached = "ДОШЁЛ" if trace_result['reached_target'] else "Не дошёл"
            print(f"     {reached} | Хопов: {len(trace_result['hops'])}/{MAX_HOPS}")


    try:
        with open(CSV_PATH, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=csv_headers, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(results)

        print(f"Успешно сохранено: {CSV_PATH}")

    except Exception as e:
        print(f"Ошибка сохранения: {e}")
        sys.exit(1)

    # === ИТОГОВЫЙ ОТЧЁТ ===
    print("\n" + "=" * 70)
    print("ИТОГОВЫЙ ОТЧЁТ")
    print("=" * 70)

    for row in results:
        status_icon = "ок" if row['Reached_Target'] == 'Yes' else "ждем"
        print(f"{status_icon} {row['Domain']:15} → {row['Resolved_IP']:15} | "
              f"Хопов: {row['Total_Hops']:2} | "
              f"{'OK' if row['Traceroute_Success'] == 'Yes' else 'FAIL'}")

    print("\n" + "=" * 70)
    print(f"Готово! Откройте файл в Excel или просмотрите:")
    print(f"   cat {CSV_PATH}")
    print("=" * 70)


if __name__ == '__main__':
    main()
