#### Парсинг статей с хабра (https://habr.com/ru/hubs/artificial_intelligence/articles/page3/)

##### 1) Запуск вирт. окружения:
```
python3 -m venv venv
source venv/bin/activate
```

##### 2) Установка зависимостей:
```
pip install scapy selenium requests webdriver-manager
```

##### 3) Запуск программы:
```
sudo ./venv/bin/python parsing.py
```

```
Результат парсинга хранится в:

habr__page3.csv
```

#### Также программа анализирует трафик по ходу выполнения программы
```
Результат хранится в:

traffic_dump.csv
```

#### Различия между HTTP и HTTPS
```
Результат хранится в:

network_analysis_real.csv
```
