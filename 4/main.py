import threading

from fastapi import FastAPI
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager


DATABASE_URL = "postgresql://stepan:1234@localhost:5432/my_database"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Article(Base):
    __tablename__ = "articles"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    author = Column(String)
    views = Column(String)
    time = Column(String)
    link = Column(String)


Base.metadata.create_all(bind=engine)

app = FastAPI()


def run_parser(target_url: str):
    print(f"--- Парсинг начат: {target_url} ---")
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    db = SessionLocal()
    try:
        driver.get(target_url)
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "article.tm-articles-list__item"))
        )
        items = driver.find_elements(By.CSS_SELECTOR, "article.tm-articles-list__item")
        for item in items[:7]:
            try:
                title_el = item.find_element(By.CSS_SELECTOR, "a.tm-title__link")
                new_article = Article(
                    title=title_el.text.strip(),
                    author=item.find_element(By.CSS_SELECTOR, ".tm-user-info__username").text.strip(),
                    views=item.find_element(By.CSS_SELECTOR, ".tm-icon-counter__value").text.strip(),
                    time=item.find_element(By.CSS_SELECTOR, ".tm-article-reading-time__label").text.strip(),
                    link=title_el.get_attribute("href")
                )
                db.add(new_article)
            except:
                continue
        db.commit()
        print("--- Готово! Данные в базе. ---")
    finally:
        db.close()
        driver.quit()


@app.get("/parse")
def parse(url: str):
    threading.Thread(target=run_parser, args=(url,)).start()
    return {"status": "success", "message": "Парсер запущен"}


@app.get("/get_data")
def get_data():
    db = SessionLocal()
    articles = db.query(Article).all()
    db.close()
    return articles


if __name__ == "__main__":
    import uvicorn

    print("--- СЕРВЕР ЗАПУСКАЕТСЯ ---")
    uvicorn.run(app, host="127.0.0.1", port=8000)
