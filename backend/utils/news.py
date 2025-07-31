# utils/news.py
import os
import requests

def fetch_market_news(limit=5):
    try:
        api_key = os.getenv("NEWSDATA_API_KEY")
        if not api_key:
            print("[Error] Missing NEWSDATA_API_KEY")
            return []

        url = "https://newsdata.io/api/1/news"
        params = {
            "apikey": api_key,
            "category": "business,technology",
            "language": "en"
        }

        response = requests.get(url, params=params)
        response.raise_for_status()
        articles = response.json().get("results", [])[:limit]

        return [{
            "title": article["title"],
            "link": article["link"],
            "pubDate": article.get("pubDate", "N/A")
        } for article in articles]

    except Exception as e:
        print(f"[NewsData Error] {e}")
        return []
