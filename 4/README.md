# Парсер Habr с управлением через API (FastAPI + PostgreSQL)

Этот проект представляет собой сервис для парсинга статей с сайта Habr.com. Управление парсером происходит через HTTP-запросы, а данные сохраняются в реляционную базу данных PostgreSQL.

## Технологический стек
* **Python 3.13+**
* **FastAPI** — веб-фреймворк для создания API.
* **Selenium** — инструмент для парсинга динамического контента.
* **SQLAlchemy** — ORM для работы с базой данных.
* **PostgreSQL** — основное хранилище данных.

---

## 1. Установка и настройка

### Виртуальное окружение
Создайте и активируйте виртуальное окружение:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Установка зависимостей
```bash
pip install -r requirements.txt
```

### Настройка базы данных PostgreSQL
#### Зайдите в консоль Postgres и выполните следующие команды для создания базы и настройки прав:
```bash
Запуск PostgreSQL-клиента:
sudo -u postgres psql

-- Создание базы данных
CREATE DATABASE my_database;

-- Создание пользователя
CREATE USER stepan WITH PASSWORD '1234';

-- Передача прав на базу
ALTER DATABASE my_database OWNER TO stepan;

-- Подключение к базе
\c my_database

-- Права на схему и объекты
GRANT ALL ON SCHEMA public TO stepan;
GRANT ALL ON ALL TABLES IN SCHEMA public TO stepan;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO stepan;

-- Выход из psql
\q
```
## 2. Запуск приложения
```bash
python main.py
```
### Использование API (В НОВОМ ТЕРМИНАЛЕ!)
```
Парсим:
curl "http://127.0.0.1:8000/parse?url=https://habr.com/ru/hubs/artificial_intelligence/articles/page3/"
```
```
Извлекаем в json:
curl "http://127.0.0.1:8000/get_data" | jq
```
### Структура данных в БД
Каждая запись о статье содержит следующие поля:

    id — уникальный идентификатор.
    title — заголовок статьи.
    author — имя автора.
    views — количество просмотров.
    time — время чтения.
    link — прямая ссылка на статью.
