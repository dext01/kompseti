## В ВЕТКЕ МАСТЕР!


### Задание 5: Docker Network
Что сделано
Развернуты 2 контейнера Docker с сетью между ними (без docker-compose):

    Flask-приложение (порт 5000)
    PostgreSQL база данных (порт 5432)
Как это работает
Сеть:

    Создана сеть my-app-network
    Оба контейнера подключены к одной сети
    Контейнеры видят друг друга по именам (DNS)
Логика работы:

    PostgreSQL запускается первым → создаёт базу данных myapp
    Flask-приложение запускается → подключается к БД по имени postgres-db
    При запросе GET /health → приложение пытается подключиться к БД → если успешно, возвращает {"status":"OK","database":"connected"}
    Связь: браузер -> localhost:5000 -> flask-app -> postgres-db:5432

### Как запустить
# 1. Создать сеть
docker network create my-app-network

# 2. Запустить базу данных
docker run -d --name postgres-db --network my-app-network \
  -e POSTGRES_USER=stepan \
  -e POSTGRES_PASSWORD=secret123 \
  -e POSTGRES_DB=myapp \
  postgres:16

# 3. Собрать и запустить приложение
docker build -t my-flask-app:1.0 .
docker run -d --name flask-app --network my-app-network \
  -p 5000:5000 my-flask-app:1.0

### Как протестировать
# 1. Проверить, что контейнеры запущены
docker ps
(CONTAINER ID   IMAGE              NAMES          STATUS          PORTS
xxx            my-flask-app:1.0   flask-app      Up ...          0.0.0.0:5000->5000/tcp
yyy            postgres:16        postgres-db    Up ...          5432/tcp)

2. Проверить сеть
docker network inspect my-app-network --format='{{range .Containers}}{{.Name}} {{end}}'
(flask-app postgres-db)

# 3. Проверить главную страницу
curl http://localhost:5000/
# Ожидается: {"message":"Hello from Flask app!"}

# 4. Проверить подключение к базе данных (главный тест!)
curl http://localhost:5000/health
# Ожидается: {"status":"OK","database":"connected"}

# 5. Проверить связь между контейнерами
docker exec flask-app ping -c 3 postgres-db
# Ожидается: 3 packets transmitted, 3 received

### Остановка контейнеров
docker stop flask-app postgres-db
docker start flask-app postgres-db  # для повторного запуска
