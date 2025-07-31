# backend/utils/dashboard_helpers.py

import requests
import os
from .news import fetch_market_news  # optional, if news is separate

def fetch_dashboard_data(coin_limit=5, news_limit=5):
    trending_coins, market_news = [], []

    try:
        coin_data = requests.get("https://api.coingecko.com/api/v3/search/trending").json()
        for coin in coin_data.get('coins', [])[:coin_limit]:
            item = coin.get('item', {})
            trending_coins.append({
                "name": item.get("name"),
                "symbol": item.get("symbol"),
                "market_cap_rank": item.get("market_cap_rank"),
                "thumb": item.get("thumb"),
                "score": item.get("score"),
                "id": item.get("id"),
                "url": f"https://www.coingecko.com/en/coins/{item.get('id')}" if item.get('id') else "#"
            })
    except Exception as e:
        print(f"[Trending Coins Error] {e}")

    try:
        market_news = fetch_market_news(news_limit)
    except Exception as e:
        print(f"[Market News Error] {e}")

    return {
        "trending_coins": trending_coins,
        "market_news": market_news
    }
