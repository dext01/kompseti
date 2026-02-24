import csv
import requests
import threading

from scapy.all import sniff, IP
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager


options = Options()
options.add_argument("--headless=new")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")

driver = webdriver.Chrome(
    service=Service(ChromeDriverManager().install()),
    options=options
)

captured_data = []


def capture_traffic(stop_event):
    def process_packet(packet):
        if packet.haslayer(IP) and packet.haslayer("TCP"):
            port_src = packet["TCP"].sport
            port_dst = packet["TCP"].dport
            protocol = "HTTPS" if port_src == 443 or port_dst == 443 else "HTTP"

            captured_data.append({
                "Source": packet[IP].src,
                "Destination": packet[IP].dst,
                "Protocol": protocol,
                "Size": len(packet)
            })
    sniff(prn=process_packet, stop_filter=lambda x: stop_event.is_set(),
          store=0, timeout=60)

def analyze_traffic_difference():
    sites = [
        {"name": "Habr (HTTPS)", "url": "https://habr.com"},
        {"name": "Crimea (HTTP)", "url": "http://ueu.crimea.ru"}
    ]
    analysis_results = []
    for site in sites:
        try:
            response = requests.get(site['url'], timeout=10)
            is_https = response.url.startswith("https")
            analysis_results.append({
                "Site": site['name'],
                "URL": response.url,
                "Protocol": "HTTPS" if is_https else "HTTP",
                "Port": "443" if is_https else "80",
                "Encryption": "TLS/SSL" if is_https else "None",
                "Cert_Verified": str(is_https),
                "Server_Header": response.headers.get("Server", "Hidden")
            })
        except Exception as e:
            print(f"Ошибка доступа к {site['name']}: {e}")
            continue

    if analysis_results:
        with open("network_analysis_real.csv", "w", newline="", encoding="utf-8") as f:
            fieldnames = ["Site", "URL", "Protocol", "Port", "Encryption", "Cert_Verified", "Server_Header"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(analysis_results)

def main():
    stop_sniff = threading.Event()
    sniff_thread = threading.Thread(target=capture_traffic, args=(stop_sniff,))
    sniff_thread.start()
    url_habr = "https://habr.com/ru/hubs/artificial_intelligence/articles/page3/"

    try:
        driver.get(url_habr)
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "a.tm-title__link"))
        )

        items = driver.find_elements(By.CSS_SELECTOR, "article.tm-articles-list__item")
        articles = []

        for item in items[:7]:
            try:
                title_el = item.find_element(By.CSS_SELECTOR, "a.tm-title__link")
                articles.append({
                    "Title": title_el.text.strip(),
                    "Author": item.find_element(By.CSS_SELECTOR, ".tm-user-info__username").text.strip(),
                    "Views": item.find_element(By.CSS_SELECTOR, ".tm-icon-counter__value").text.strip(),
                    "Time": item.find_element(By.CSS_SELECTOR, ".tm-article-reading-time__label").text.strip(),
                    "Link": title_el.get_attribute("href")
                })
            except:
                continue

        if articles:
            with open("habr_page3.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Title", "Author", "Views", "Time", "Link"])
                writer.writeheader()
                writer.writerows(articles)
        analyze_traffic_difference()

        stop_sniff.set()
        sniff_thread.join()

        if captured_data:
            with open("traffic_dump.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Source", "Destination", "Protocol", "Size"])
                writer.writeheader()
                writer.writerows(captured_data[:100])
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
