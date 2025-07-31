import os
import time
import random
import threading
import requests
from flask import make_response, render_template
from admin.routes import admin_bp  # ✅ Absolute
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, make_response
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token, set_access_cookies, unset_jwt_cookies,
    jwt_required, get_jwt_identity, JWTManager, get_csrf_token
)
from flask_mail import Mail, Message
from utils.dashboard_helpers import fetch_dashboard_data
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from dotenv import load_dotenv
from weasyprint import HTML
from models import db, User, Trade
import jwt as pyjwt

# ---------------- OTP Store (global) ----------------
otp_store = {}  # email → {"otp": "123456", "expires": datetime}

def cleanup_otp_store():
    now = datetime.utcnow()
    for email in list(otp_store.keys()):
        if otp_store[email]['expires'] < now:
            del otp_store[email]

def cleanup_loop():
    while True:
        cleanup_otp_store()
        time.sleep(600)

threading.Thread(target=cleanup_loop, daemon=True).start()

# Load environment variables
load_dotenv()

# Initialize app
app = Flask(__name__)
csrf = CSRFProtect(app)


#admin register
app.register_blueprint(admin_bp, url_prefix="/admin")

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_COOKIE_SECURE'] = False

# Mail setup
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD')
)

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
db.init_app(app)
migrate = Migrate(app, db)
CORS(app, supports_credentials=True)

# JWT expired token handler
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    flash("Your session has expired. Please log in again.", "info")
    return redirect(url_for('sign_page'))

# Currency Helpers
currency_symbols = {
    "USD": "$", "EUR": "€", "GBP": "£", "JPY": "¥", "CAD": "C$",
    "AUD": "A$", "CHF": "Fr.", "CNY": "¥", "INR": "₹", "NZD": "NZ$",
    "ZAR": "R", "SEK": "kr", "NOK": "kr", "DKK": "kr", "MXN": "Mex$",
    "BRL": "R$", "RUB": "₽", "HKD": "HK$", "SGD": "S$", "KRW": "₩",
    "TRY": "₺", "AED": "د.إ", "SAR": "ر.س", "NGN": "₦", "KES": "KSh",
    "GHS": "GH₵", "EGP": "E£", "TZS": "TSh", "UGX": "USh", "PKR": "Rs",
    "BDT": "৳", "THB": "฿", "MYR": "RM", "IDR": "Rp", "VND": "₫"
}

def get_currency_symbol(code):
    return currency_symbols.get(code.upper(), code.upper())

def convert_currency(amount, from_currency, to_currency):
    if from_currency == to_currency:
        return amount

    rate_from_usd = get_exchange_rate(from_currency)
    if rate_from_usd == 0:
        print(f"Warning: rate for {from_currency} is zero.")
        return amount

    usd_amount = amount / rate_from_usd
    rate_to = get_exchange_rate(to_currency)
    return usd_amount * rate_to

@app.context_processor
def inject_currency_utils():
    return dict(get_currency_symbol=get_currency_symbol, convert_currency=convert_currency)

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%b %d, %Y'):
    try:
        if isinstance(value, str):
            value = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(value)
        elif isinstance(value, datetime):
            dt = value
        else:
            return "Invalid date"
        return dt.strftime(format)
    except Exception:
        return "Invalid date"

def send_reset_email(to_email, code):
    msg = Message("Reset Your Password",
                  sender=os.getenv('MAIL_USERNAME'),
                  recipients=[to_email])
    msg.body = f"Your reset code is: {code}\nThis code expires in 10 minutes."
    mail.send(msg)

def get_exchange_rate(target_currency):
    target_currency = target_currency.upper()
    cache = session.get("fx_cache", {})

    if cache and "timestamp" in cache and (time.time() - cache["timestamp"] < 3600):
        return cache.get("rates", {}).get(target_currency, 1.0)

    try:
        response = requests.get("https://open.er-api.com/v6/latest/USD")
        response.raise_for_status()
        rates = response.json().get("rates", {})
        session["fx_cache"] = {
            "timestamp": time.time(),
            "rates": rates
        }
        return rates.get(target_currency, 1.0)
    except:
        return 1.0

def fetch_market_news(limit=5):
    try:
        api_key = os.getenv("NEWSDATA_API_KEY")
        url = f"https://newsdata.io/api/1/news?apikey={api_key}&category=business,technology&language=en"
        response = requests.get(url)
        response.raise_for_status()
        articles = response.json().get("results", [])[:limit]
        return [{
            "title": article["title"],
            "link": article["link"],
            "pubDate": article["pubDate"]
        } for article in articles]
    except Exception as e:
        print(f"[NewsData.io error] {e}")
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return '', 204  # No Content


@app.route('/sign.html')
def sign_page():
    return render_template('sign.html')

@app.route('/reset_password.html')
def reset_password_page():
    return render_template('reset_password.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash("Please enter your email address.", "danger")
            return render_template('reset_password.html')

        user = User.query.filter_by(email=email).first()
        if user:
            db.session.commit()
            flash("A password reset code has been sent to your email.", "success")
        else:
            flash("Email not found.", "danger")

        return render_template('reset_password.html', email=email)
    return render_template('reset_password.html')

@app.route('/api/request-reset', methods=['POST'])
@csrf.exempt
def request_password_reset():
    try:
        data = request.get_json()
        email = data.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        otp = str(random.randint(100000, 999999))
        expiry = datetime.utcnow() + timedelta(minutes=10)
        otp_store[email] = {'otp': otp, 'expires': expiry}

        token = pyjwt.encode({
            'email': email,
            'otp': otp,
            'exp': expiry.timestamp()
        }, app.config['SECRET_KEY'], algorithm='HS256')

        send_reset_email(email, otp)

        return jsonify({'message': 'OTP sent to your email', 'token': token}), 200
    except Exception as e:
        print(f"OTP Request Error: {e}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/verify-otp', methods=['POST'])
@csrf.exempt
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    code = data.get('otp')

    record = otp_store.get(email)
    if not record:
        return jsonify({'error': 'No OTP found'}), 400

    if datetime.utcnow() > record['expires']:
        return jsonify({'error': 'OTP expired'}), 400

    if record['otp'] != code:
        return jsonify({'error': 'Incorrect OTP'}), 400

    return jsonify({'message': 'OTP verified'}), 200

@app.route('/api/reset-password', methods=['POST'])
@csrf.exempt
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('password')
    token = data.get('token')

    if token:
        try:
            decoded = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if decoded.get('email') != email:
                return jsonify({'error': 'Token mismatch'}), 400
        except pyjwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 400
        except pyjwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 400

    if not email or not new_password:
        return jsonify({'error': 'Email and password required'}), 400

    otp_store.pop(email, None)

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': 'Password reset successful', 'redirect': '/sign.html'}), 200


@app.route('/api/get-username', methods=['POST'])
@csrf.exempt
def get_username():
    try:
        data = request.get_json()
    except:
        return jsonify({'error': 'Invalid JSON'}), 400

    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({'username': user.name}), 200

@app.route('/dashboard')
@jwt_required()
def dashboard():
    from collections import defaultdict, Counter
    from datetime import datetime

    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('sign_page'))

    # Fetch both trending coins and market news using the combined function
    dashboard_data = fetch_dashboard_data(coin_limit=5, news_limit=5)
    trending_coins = dashboard_data["trending_coins"]
    market_news = dashboard_data["market_news"]

    currency_code = user.currency or "USD"
    exchange_rate = get_exchange_rate(currency_code)

    trades = Trade.query.filter_by(user_id=user_id).order_by(Trade.entry_time.desc()).all()
    closed_trades = [t for t in trades if t.exit_time is not None]
    open_trades = [t for t in trades if t.exit_time is None]

    profits_usd = [t.profit for t in closed_trades if t.profit is not None]
    profits_conv = [p * exchange_rate for p in profits_usd]
    wins = [p for p in profits_conv if p > 0]
    losses = [abs(p) for p in profits_conv if p < 0]

    total_profit = round(sum(profits_conv), 2) if profits_conv else 0
    win_rate = round(len(wins) / len(profits_conv) * 100, 2) if profits_conv else 0
    risk_reward = f"1:{round(sum(wins)/sum(losses), 1)}" if losses else "1:0"
    total_balance = round((user.initial_balance or 0) + total_profit, 2)

    # --- Cumulative Equity Curve Data ---
    cumulative_data = []
    running_value = user.initial_balance or 0

    if closed_trades:
        cumulative_data.append({
            "date": (user.created_at or datetime.now()).strftime('%Y-%m-%d'),
            "value": round(running_value, 2)
        })

    sorted_closed_trades = sorted(closed_trades, key=lambda t: t.entry_time)

    for trade in sorted_closed_trades:
        if trade.profit is not None:
            profit_in_user_currency = convert_currency(trade.profit, 'USD', currency_code)
            running_value += profit_in_user_currency
        cumulative_data.append({
            "date": trade.entry_time.strftime('%Y-%m-%d'),
            "value": round(running_value, 2)
        })

    # --- Drawdown Chart Data ---
    drawdown_data = []
    peak = user.initial_balance or 0
    running_value_drawdown = user.initial_balance or 0

    if sorted_closed_trades:
        drawdown_data.append({
            "date": (user.created_at or datetime.now()).strftime('%Y-%m-%d'),
            "value": 0
        })

    for trade in sorted_closed_trades:
        if trade.profit is not None:
            profit_in_user_currency = convert_currency(trade.profit, 'USD', currency_code)
            running_value_drawdown += profit_in_user_currency
            peak = max(peak, running_value_drawdown)
            drawdown = running_value_drawdown - peak
            drawdown_data.append({
                "date": trade.entry_time.strftime('%Y-%m-%d'),
                "value": round(drawdown, 2)
            })

    # --- Dynamic Portfolio % Change ---
    portfolio_change = 0
    if (user.initial_balance or 0) > 0:
        portfolio_change = ((total_balance - (user.initial_balance or 0)) / (user.initial_balance or 1)) * 100

    # --- Stats Dict ---
    stats = {
        "total_profit": total_profit,
        "win_rate": win_rate,
        "open_trades": len(open_trades),
        "risk_reward": risk_reward,
        "profit_change": round(portfolio_change, 2),
        "profit_change_abs": round(abs(portfolio_change), 2),
        "profit_change_positive": portfolio_change >= 0,

        # Static placeholders (customize later if needed)
        "win_rate_change": -2.3,
        "win_rate_change_abs": abs(-2.3),
        "win_rate_change_positive": -2.3 >= 0,
        "open_trades_change": 1,
        "open_trades_change_abs": abs(1),
        "open_trades_change_positive": 1 >= 0,
    }

    return render_template(
        'dashboard.html',
        user=user,
        stats=stats,
        recent_trades=[t.to_dict() for t in closed_trades[:5]],
        time_series_data=cumulative_data,
        drawdown_data=drawdown_data,
        trending_coins=trending_coins,
        market_news=market_news
    )

@app.route('/analytics')
@jwt_required()
def analytics():
    from collections import Counter, defaultdict
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('sign_page'))

    currency = user.currency or "USD"
    exchange_rate = get_exchange_rate(currency)

    trades = Trade.query.filter_by(user_id=user_id).order_by(Trade.entry_time.desc()).all()
    closed_trades = [t for t in trades if t.exit_time is not None]
    open_trades = [t for t in trades if t.exit_time is None]

    profits_usd = [t.profit for t in closed_trades if t.profit is not None]
    profits = [p * exchange_rate for p in profits_usd]
    wins = [p for p in profits if p > 0]
    losses = [abs(p) for p in profits if p < 0]

    avg_win = round(sum(wins) / len(wins), 2) if wins else 0
    avg_loss = round(sum(losses) / len(losses), 2) if losses else 0
    win_rate = round((len(wins) / len(profits)) * 100, 2) if profits else 0
    profit_factor = round(sum(wins) / sum(losses), 2) if losses and sum(losses) != 0 else 0
    total_profit = round(sum(profits), 2) if profits else 0
    total_trades = len(trades)

    total_balance = round((user.initial_balance or 0) + total_profit, 2)
    equity = total_balance

    growth_percent = 0
    if (user.initial_balance or 0) > 0:
        growth_percent = ((total_balance - (user.initial_balance or 0)) / (user.initial_balance or 0) * 100)
    balance_change_str = f"{'↑' if growth_percent >= 0 else '↓'} {abs(round(growth_percent, 2))}%"

    cumulative_data = []
    running_value = user.initial_balance or 0
    sorted_closed_trades = sorted(closed_trades, key=lambda t: t.entry_time)

    if sorted_closed_trades:
        cumulative_data.append({
            "date": (user.created_at or datetime.now()).strftime('%Y-%m-%d'),
            "value": round(running_value, 2)
        })

    for trade in sorted_closed_trades:
        if trade.profit is not None:
            profit_in_user_currency = convert_currency(trade.profit, 'USD', currency)
            running_value += profit_in_user_currency
        cumulative_data.append({
            "date": trade.entry_time.strftime('%Y-%m-%d'),
            "value": round(running_value, 2)
        })

    drawdown_data = []
    peak = user.initial_balance or 0
    running_value_drawdown = user.initial_balance or 0

    if sorted_closed_trades:
        drawdown_data.append({
            "date": (user.created_at or datetime.now()).strftime('%Y-%m-%d'),
            "value": 0
        })

    for trade in sorted_closed_trades:
        if trade.profit is not None:
            profit_in_user_currency = convert_currency(trade.profit, 'USD', currency)
            running_value_drawdown += profit_in_user_currency
            
            peak = max(peak, running_value_drawdown)
            drawdown = running_value_drawdown - peak
            drawdown_data.append({
                "date": trade.entry_time.strftime('%Y-%m-%d'),
                "value": round(drawdown, 2)
            })

    profit_vs_loss_data = {
        "profit": round(sum(wins), 2),
        "loss": round(sum(losses), 2)
    }

    asset_counts = Counter([t.symbol for t in trades])
    allocation_data = {
        "labels": list(asset_counts.keys()),
        "values": list(asset_counts.values()),
        "colors": ["#2563eb", "#8b5cf6", "#10b981", "#f59e0b", "#ef4444", "#3b82f6", "#f87171", "#34d399"][:len(asset_counts)]
    }

    session_data = {
        "labels": ["London", "New York", "Tokyo"],
        "values": [10, 8, 5],
        "colors": ["#3b82f6", "#f87171", "#34d399"]
    }

    best_pair_trade = max(closed_trades, key=lambda t: t.profit or -float('inf'), default=None)
    worst_pair_trade = min(closed_trades, key=lambda t: t.profit or float('inf'), default=None)

    best_pair = best_pair_trade.symbol if best_pair_trade else "N/A"
    best_pair_profit = round(convert_currency(best_pair_trade.profit, 'USD', currency), 2) if best_pair_trade and best_pair_trade.profit is not None else 0
    worst_pair = worst_pair_trade.symbol if worst_pair_trade else "N/A"
    worst_pair_loss = abs(round(convert_currency(worst_pair_trade.profit, 'USD', currency), 2)) if worst_pair_trade and worst_pair_trade.profit is not None else 0

    symbol_freq = defaultdict(int)
    for t in trades:
        symbol_freq[t.symbol] += 1
    most_traded_pair = max(symbol_freq, key=symbol_freq.get, default="N/A")
    most_traded_count = symbol_freq[most_traded_pair]

    highest_winrate_pair = best_pair
    highest_winrate = win_rate
    best_session = "London"
    best_session_profitability = 65

    return render_template(
        'analytics.html',
        user=user,
        allocation_data=allocation_data,
        abs=abs,
        profit_vs_loss_data=profit_vs_loss_data,
        session_data=session_data,
        time_series_data=cumulative_data,
        best_pair=best_pair,
        best_pair_profit=best_pair_profit,
        worst_pair=worst_pair,
        worst_pair_loss=worst_pair_loss,
        most_traded_pair=most_traded_pair,
        most_traded_count=most_traded_count,
        highest_winrate_pair=highest_winrate_pair,
        highest_winrate=highest_winrate,
        best_session=best_session,
        best_session_profitability=best_session_profitability,
        avg_win=avg_win,
        avg_loss=avg_loss,
        total_balance=total_balance,
        total_balance_change=balance_change_str,
        equity=equity,
        equity_change=balance_change_str,
        running_trades=len(open_trades),
        running_trades_change="↑ 0",
        total_trades=total_trades,
        trades_change=0,
        recent_trades=[t.to_dict() for t in closed_trades[:5]],
        drawdown_data=drawdown_data,
    )

@app.route('/report')
@jwt_required()
def report():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('sign_page'))

    trades = Trade.query.filter_by(user_id=user_id).all()
    now = datetime.utcnow()
    preferred_currency = user.currency or 'USD'
    initial_balance_converted = convert_currency((user.initial_balance or 0), 'USD', preferred_currency)

    # ✅ FIX: Define the list before using it
    trades_converted = []

    for trade in trades:
        trades_converted.append({
            'entry_time': trade.entry_time,
            'symbol': trade.symbol,
            'trade_type': trade.trade_type,
            'entry_position': round(trade.entry_position, 5) if trade.entry_position else None,
            'entry_position_converted': convert_currency(trade.entry_position, 'USD', preferred_currency) if trade.entry_position else None,
            'closing_position': round(trade.closing_position, 5) if trade.closing_position else None,
            'exit_position_converted': convert_currency(trade.closing_position, 'USD', preferred_currency) if trade.closing_position is not None else None,
            'quantity': round(trade.lot_size, 2) if trade.lot_size else None,
            'profit_converted': convert_currency(trade.profit, 'USD', preferred_currency) if trade.profit is not None else None,
            'notes': trade.notes,
        })

    currency_symbol = get_currency_symbol(preferred_currency)

    return render_template('report.html',
                           trades=trades_converted,
                           user=user,
                           now=now,
                           initial_balance=initial_balance_converted,
                           currency_symbol=currency_symbol)

@app.route('/report/download')
@jwt_required()
def download_report():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('sign_page'))

    trades = Trade.query.filter_by(user_id=user_id).all()
    now = datetime.utcnow()
    preferred_currency = user.currency or 'USD'
    initial_balance_converted = convert_currency((user.initial_balance or 0), 'USD', preferred_currency)

    trades_converted = []
    for trade in trades:
        trades_converted.append({
            'entry_time': trade.entry_time,
            'symbol': trade.symbol,
            'trade_type': trade.trade_type,
            'entry_position': round(trade.entry_position, 5) if trade.entry_position else None,
            'entry_position_converted': convert_currency(trade.entry_position, 'USD', preferred_currency) if trade.entry_position else None,
            'closing_position': round(trade.closing_position, 5) if trade.closing_position else None,
            'exit_position_converted': convert_currency(trade.closing_position, 'USD', preferred_currency) if trade.closing_position is not None else None,
            'quantity': round(trade.lot_size, 2) if trade.lot_size else None,
            'profit_converted': convert_currency(trade.profit, 'USD', preferred_currency) if trade.profit is not None else None,
            'notes': trade.notes,
        })

    currency_symbol = get_currency_symbol(preferred_currency)

    # Render the report HTML
    rendered_html = render_template(
        'report.html',
        trades=trades_converted,
        user=user,
        now=now,
        initial_balance=initial_balance_converted,
        currency_symbol=currency_symbol
    )

    # Convert HTML to PDF using WeasyPrint
    pdf = HTML(string=rendered_html).write_pdf()

    # Return the PDF as a downloadable response
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=trade_report.pdf'
    return response


@app.route('/settings', methods=['GET', 'POST'])
@jwt_required()
def settings():
    user = User.query.get(int(get_jwt_identity()))
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('sign_page'))

    if request.method == 'POST':
        name = request.form.get('username')
        email = request.form.get('email')
        
        if name is not None and email is not None:
            if not name or not email:
                flash("Username and email are required.", "danger")
                return redirect(url_for('settings'))

            user.name = name
            user.email = email
            user.currency = request.form.get('currency', 'USD')
            user.timezone = request.form.get('timezone', 'Etc/GMT+0')
            try:
                user.initial_balance = float(request.form.get('initial_balance') or 0)
            except ValueError:
                flash("Initial balance must be a valid number.", "danger")
                return redirect(url_for('settings'))

            notification_keys = ['email', 'trade_alerts', 'news', 'performance', 'ai_insights']
            user.notifications = {
                key: request.form.get(key) == 'on'
                for key in notification_keys
            }

            user.two_factor_enabled = request.form.get('two_factor') == 'on'
            user.login_alerts = request.form.get('login_alerts') == 'on'

        # Password change logic
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password or confirm_password or current_password:
            if not current_password:
                flash("Current password is required to change your password.", "danger")
                return redirect(url_for('settings'))

            try:
                if not user.check_password(current_password):
                    flash("Current password is incorrect.", "danger")
                    return redirect(url_for('settings'))
            except ValueError:
                # Invalid salt — likely a plain-text password stored previously
                print(f"⚠️ Fixing invalid password hash for user: {user.email}")
                user.set_password(user.password_hash)  # treat as plain text and hash it
                db.session.commit()

                # Retry check
                if not user.check_password(current_password):
                    flash("Current password is incorrect.", "danger")
                    return redirect(url_for('settings'))

            if not new_password or not confirm_password:
                flash("New password and confirm password are required.", "danger")
                return redirect(url_for('settings'))

            if new_password != confirm_password:
                flash("New passwords do not match.", "danger")
                return redirect(url_for('settings'))

            user.set_password(new_password)
            flash("✅ Password changed successfully!", "success")

        # Trade entry logic
        if request.form.get('trade_pair'):
            if not request.form.get('trade_type'):
                flash("Trade type is required.", "danger")
                return redirect(url_for('settings'))

            try:
                trade_id = request.form.get('trade_id')
                if trade_id and trade_id.isdigit():
                    trade = Trade.query.filter_by(id=trade_id, user_id=user.id).first()
                    if not trade:
                        flash("Trade not found for update or unauthorized.", "danger")
                        return redirect(url_for('settings'))
                else:
                    trade = Trade(user_id=user.id)
                    db.session.add(trade)

                trade.symbol = request.form.get('trade_pair')
                trade.trade_type = request.form.get('trade_type')
                trade.lot_size = float(request.form.get('position_size') or 0)
                trade.entry_position = float(request.form.get('entry_position') or 0)
                trade.closing_position = float(request.form.get('closing_position') or 0) if request.form.get('closing_position') else None

                trade_date_str = request.form.get('trade_date')
                if trade_date_str:
                    trade.entry_time = datetime.strptime(trade_date_str, '%Y-%m-%d')
                else:
                    flash("Trade entry date is required.", "danger")
                    return redirect(url_for('settings'))
                
                if trade.closing_position is not None:
                    trade_exit_date_str = request.form.get('trade_exit_date')
                    if trade_exit_date_str:
                        trade.exit_time = datetime.strptime(trade_exit_date_str, '%Y-%m-%d')
                    else:
                        trade.exit_time = datetime.utcnow()
                else:
                    trade.exit_time = None

                trade.notes = request.form.get('trade_notes')

                if trade.closing_position is not None and trade.entry_position is not None and trade.lot_size is not None:
                    trade.calculate_profit()
                else:
                    trade.profit = None

                flash("Trade saved successfully!", "success")

            except ValueError as ve:
                db.session.rollback()
                flash(f"Invalid number format for trade data. Please ensure numbers are correct. Error: {ve}", "danger")
                return redirect(url_for('settings'))
            except Exception as e:
                db.session.rollback()
                flash(f"Failed to save trade: {str(e)}", "danger")
                return redirect(url_for('settings'))

        try:
            db.session.commit()
            session['currency'] = user.currency
            flash("Settings updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error saving data: {str(e)}", "danger")

        return redirect(url_for('settings'))

    trades = Trade.query.filter_by(user_id=user.id).order_by(Trade.entry_time.desc()).all()
    
    timezone_options={
       "Etc/GMT+12": "(GMT-12:00) International Date Line West",
       "Pacific/Midway": "(GMT-11:00) Midway Island, Samoa",
       "Pacific/Honolulu": "(GMT-10:00) Hawaii",
       "America/Anchorage": "(GMT-09:00) Alaska",
       "America/Los_Angeles": "(GMT-08:00) Los Angeles",
       "America/Denver": "(GMT-07:00) Denver",
       "America/Chicago": "(GMT-06:00) Chicago",
       "America/New_York": "(GMT-05:00) New York",
       "America/Halifax": "(GMT-04:00) Halifax",
       "America/Argentina/Buenos_Aires": "(GMT-03:00) Buenos Aires",
       "Atlantic/South_Georgia": "(GMT-02:00) South Georgia",
       "Atlantic/Azores": "(GMT-01:00) Azores",
       "Etc/GMT+0": "(GMT+00:00) Greenwich Mean Time",
       "Europe/London": "(GMT+00:00) London",
       "Europe/Berlin": "(GMT+01:00) Berlin, Rome, Paris",
       "Europe/Athens": "(GMT+02:00) Athens, Bucharest",
       "Africa/Nairobi": "(GMT+03:00) Nairobi, Kampala, Mogadishu",
       "Asia/Tehran": "(GMT+03:30) Tehran",
       "Asia/Dubai": "(GMT+04:00) Dubai, Muscat",
       "Asia/Kabul": "(GMT+04:30) Kabul",
       "Asia/Karachi": "(GMT+05:00) Karachi, Tashkent",
       "Asia/Kolkata": "(GMT+05:30) New Delhi, Mumbai",
       "Asia/Kathmandu": "(GMT+05:45) Kathmandu",
       "Asia/Dhaka": "(GMT+06:00) Dhaka",
       "Asia/Yangon": "(GMT+06:30) Yangon",
       "Asia/Bangkok": "(GMT+07:00) Bangkok, Hanoi",
       "Asia/Shanghai": "(GMT+08:00) Beijing, Hong Kong, Singapore",
       "Asia/Tokyo": "(GMT+09:00) Tokyo, Seoul",
       "Australia/Darwin": "(GMT+09:30) Darwin",
       "Australia/Sydney": "(GMT+10:00) Sydney, Melbourne",
       "Asia/Magadan": "(GMT+11:00) Magadan",
       "Pacific/Auckland": "(GMT+12:00) Auckland, Wellington",
       "Pacific/Tongatapu": "(GMT+13:00) Nuku'alofa",
       "Pacific/Kiritimati": "(GMT+14:00) Kiritimati Island"
    }

    currency_name_map={
        "USD": "US Dollar", "EUR": "Euro", "GBP": "British Pound", "JPY": "Japanese Yen", "CAD": "Canadian Dollar",
        "AUD": "Australian Dollar", "CHF": "Swiss Franc", "CNY": "Chinese Yuan", "INR": "Indian Rupee", "NZD": "New Zealand Dollar",
        "ZAR": "South African Rand", "SEK": "Swedish Krona", "NOK": "Norwegian Krone", "DKK": "Danish Krone", "MXN": "Mexican Peso",
        "BRL": "Brazilian Real", "RUB": "Russian Ruble", "HKD": "Hong Kong Dollar", "SGD": "Singapore Dollar", "KRW": "South Korean Won",
        "TRY": "Turkish Lira", "AED": "UAE Dirham", "SAR": "Saudi Riyal", "NGN": "Nigerian Naira", "KES": "Kenyan Shilling",
        "GHS": "Ghanaian Cedi", "EGP": "Egyptian Pound", "TZS": "Tanzanian Shilling", "UGX": "Ugandan Shilling", "PKR": "Pakistani Rupee",
        "BDT": "Bangladeshi Taka", "THB": "Thai Baht", "MYR": "Malaysian Ringgit", "IDR": "Indonesian Rupiah", "VND": "Vietnamese Dong"
    }

    notification_map={
        "email": "Email Notifications",
        "trade_alerts": "Trade Alerts",
        "news": "Market News",
        "performance": "Performance Reports",
        "ai_insights": "AI Insights Updates"
    }

    return render_template("settings.html",
        user=user,
        trades=trades,
        now=datetime.utcnow(),
        timezone_options=timezone_options,
        currency_name_map=currency_name_map,
        notifications=notification_map
    )

@app.route('/delete_trade', methods=['POST'])
@jwt_required()
def delete_trade():
    user_id = int(get_jwt_identity())
    trade_id = request.form.get('trade_id')

    if not trade_id:
        flash("Trade ID is missing.", "danger")
        return redirect(url_for('settings'))

    trade = Trade.query.filter_by(id=trade_id, user_id=user_id).first()
    if trade:
        db.session.delete(trade)
        db.session.commit()
        flash("Trade deleted successfully.", "success")
    else:
        flash("Trade not found or unauthorized.", "danger")

    return redirect(url_for('settings'))

@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message_body = request.form.get('message')

        if not name or not email or not message_body:
            flash("All fields are required.", "danger")
            return render_template('support.html')

        msg = Message(subject=f"Support Message from Trading Journal Pro: {name}",
                      sender=os.getenv("MAIL_USERNAME"),
                      recipients=[os.getenv("SUPPORT_EMAIL")],
                      body=f"From: {name} <{email}>\n\nMessage:\n{message_body}")
        try:
            mail.send(msg)
            flash("Message sent successfully! We will get back to you soon.", "success")
            return redirect(url_for('support'))
        except Exception as e:
            flash(f"Error sending message: {str(e)}. Please try again later.", "danger")

    return render_template('support.html')

@csrf.exempt
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing registration data'}), 400

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    admin_code = data.get('admin_code')  # ✅ optional field

    if not name or not email or not password:
        return jsonify({'error': 'Name, email, and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    valid_groups = {'forex', 'stock', 'crypto', 'multi_asset'}
    user_group = data.get('user_group', 'multi_asset')
    if user_group not in valid_groups:
        return jsonify({'error': 'Invalid user group'}), 400

    is_admin = admin_code == os.getenv('ADMIN_SECRET')  # ✅ compare with secret

    user = User(
        name=name,
        email=email,
        is_admin=is_admin,
        account_type='free',
        user_group=user_group
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=str(user.id))

    response = jsonify({
        'success': True,
        'access_token': access_token,
        'is_admin': user.is_admin
    })
    set_access_cookies(response, access_token)
    return response, 201


@csrf.exempt
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))

    response = jsonify({
        'access_token': access_token,
        'is_admin': user.is_admin
    })
    set_access_cookies(response, access_token)
    return response, 200

@app.route('/api/trades', methods=['POST'])
@jwt_required()
def create_trade():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify(success=False, message="User not found."), 404

    data = request.get_json()
    if not data:
        return jsonify(success=False, message="Missing trade data"), 400

    symbol = data.get('symbol')
    trade_type = data.get('trade_type')
    entry_position = float(data.get('entry_position')) if data.get('entry_position') else 0.0
    lot_size = float(data.get('lot_size')) if data.get('lot_size') else 0.0
    closing_position = float(data.get('closing_position')) if data.get('closing_position') else None
    notes = data.get('notes', '')

    entry_time_str = data.get('entry_time')
    entry_time = None
    if entry_time_str:
        try:
            entry_time = datetime.strptime(entry_time_str, '%Y-%m-%d')
        except ValueError:
            return jsonify(success=False, message="Invalid entry_time format. Use YYYY-MM-DD"), 400
    else:
        entry_time = datetime.utcnow()

    exit_time_str = data.get('exit_time')
    exit_time = None
    if exit_time_str:
        try:
            exit_time = datetime.strptime(exit_time_str, '%Y-%m-%d')
        except ValueError:
            return jsonify(success=False, message="Invalid exit_time format. Use YYYY-MM-DD"), 400

    if not symbol or not trade_type:
        return jsonify(success=False, message="Symbol and trade type are required."), 400

    # Validate trade_type
    if trade_type.lower() not in ['buy', 'sell']:
        return jsonify(success=False, message="Invalid trade_type. Must be 'buy' or 'sell'."), 400

    # Calculate profit if both entry and closing positions are provided
    profit = None
    if entry_position and closing_position and lot_size:
        if trade_type.lower() == 'buy':
            profit = (closing_position - entry_position) * lot_size
        elif trade_type.lower() == 'sell':
            profit = (entry_position - closing_position) * lot_size

    try:
        new_trade = Trade(
            user_id=user.id,
            symbol=symbol,
            trade_type=trade_type.lower(),
            entry_position=entry_position,
            lot_size=lot_size,
            closing_position=closing_position,
            entry_time=entry_time,
            exit_time=exit_time,
            profit=profit,
            notes=notes
        )

        db.session.add(new_trade)
        db.session.commit()

        return jsonify(success=True, message="Trade created successfully!", trade_id=new_trade.id, trade=new_trade.to_dict()), 201

    except ValueError as ve:
        db.session.rollback()
        return jsonify(success=False, message=f"Invalid number format: {ve}"), 400
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f"Failed to create trade: {str(e)}"), 500


@app.route('/api/logout', methods=['POST'])
def logout():
    response = jsonify({'message': 'Successfully logged out'})
    unset_jwt_cookies(response)
    return response, 200

@app.route('/news-feed')
def news_feed():
    try:
        news_items = fetch_market_news()
        return jsonify(news_items)
    except Exception as e:
        print(f"[Error] News feed fetch failed: {e}")
        return jsonify({"error": "Could not load news"}), 500

@app.route("/api/csrf-token", methods=["GET"])
def get_csrf_token():
    token = generate_csrf()
    response = jsonify({'csrf_token': token})
    response.set_cookie('csrf_token', token, httponly=False, samesite='Lax')
    return response

@app.errorhandler(404)
def page_not_found(e):
    flash("The page you are looking for does not exist.", "warning")
    return redirect(url_for('index')), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        if not User.query.filter_by(email='test@example.com').first():
            user = User(name='Test User', email='test@example.com', is_admin=True)
            user.set_password('test123')
            db.session.add(user)
            db.session.commit()
            print("Test user 'test@example.com' created with password 'test123'. (Admin user)")
        
        if not User.query.filter_by(email='user@example.com').first():
            user = User(name='Regular User', email='user@example.com', is_admin=False)
            user.set_password('user123')
            db.session.add(user)
            db.session.commit()
            print("Regular user 'user@example.com' created with password 'user123'.")
            
    app.run(debug=True)