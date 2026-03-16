# Задание 6: Проксирование через Nginx

## Условие
Настроить проксирование: запросы на **порт 80** → приложение в Docker (порт 5000)

## Файлы
- `nginx.conf` — конфигурация nginx для проксирования

## Как запустить

```bash
# 1. Клонировать репозиторий
git clone https://github.com/dext01/kompseti.git
cd kompseti

# 2. Скопировать конфиг в nginx
sudo cp 6/nginx.conf /etc/nginx/sites-available/docker-app

# 3. Включить конфиг
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/docker-app /etc/nginx/sites-enabled/

# 4. Проверить и перезагрузить nginx
sudo nginx -t && sudo systemctl reload nginx
```

## Как првоерить
```
# Запрос через nginx (порт 80)
curl http://localhost/
# Ожидается: {"message":"Hello from Flask app!"}

# Проверка подключения к БД
curl http://localhost/health
# Ожидается: {"status":"OK","database":"connected"}
```
## Как работает
```
Пользователь → порт 80 → nginx → proxy_pass → Flask:5000 → PostgreSQL:5432
```
