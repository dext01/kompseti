import csv

from icmplib import ping


hosts = [
    'google.com', 'yandex.ru', 'github.com', 'rutracker-net.ru',
    'wikipedia.org', 'nsu.ru', 'nstu.ru', 'apple.com', 'vk.com', 'mail.ru'
]

results = []

for target in hosts:
    try:
        host = ping(target, count=4, interval=0.2, timeout=2, privileged=False)
        status = 100 if host.packet_loss == 1.0 else 0

        results.append({
            'Host': target,
            'Min RTT': host.min_rtt,
            'Max RTT': host.max_rtt,
            'Avg RTT': host.avg_rtt,
            'Status': status
        })
        print(f"Готово: {target}")
    except Exception:
        print(f"Ошибка при проверке {target}: {Exception}")
        results.append({'Host': target, 'Min RTT': '-', 'Max RTT': '-', 'Avg RTT': '-', 'Status': 100})

with open('ping_results.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=['Host', 'Min RTT', 'Max RTT', 'Avg RTT', 'Status'])
    writer.writeheader()
    writer.writerows(results)

print("\nРезультаты в ping_results.csv")
