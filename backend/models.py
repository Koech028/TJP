from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.dialects.sqlite import JSON
from flask import session
import random
import string
import enum

db = SQLAlchemy()

# ---------------------- ENUM: User Group ----------------------

class UserGroup(enum.Enum):
    forex = "forex"
    stock = "stock"
    crypto = "crypto"
    multi_asset = "multi_asset"

# ---------------------- USER MODEL ----------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    account_type = db.Column(db.String(50), default='standard')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    initial_balance = db.Column(db.Float, default=10000.0)
    currency = db.Column(db.String(10), default='USD')
    role = db.Column(db.String(50), default='Professional Trader')
    timezone = db.Column(db.String(50), default='Africa/Nairobi')

    two_factor_enabled = db.Column(db.Boolean, default=False)
    login_alerts = db.Column(db.Boolean, default=True)

    notifications = db.Column(
        MutableDict.as_mutable(JSON),
        default=lambda: {
            "email": True,
            "trade_alerts": True,
            "news": False,
            "performance": True,
            "ai_insights": False,
        },
        nullable=True
    )

    reset_code = db.Column(db.String(6), nullable=True)
    reset_expiration = db.Column(db.DateTime, nullable=True)

    # 🛠 Admin-specific
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    user_group = db.Column(db.Enum(UserGroup), default=UserGroup.multi_asset, nullable=False)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)

    # 🔄 Relationships
    trades = db.relationship('Trade', backref='trader', lazy=True)
    strategies = db.relationship('TradingStrategy', backref='creator', lazy=True)
    brokers = db.relationship('BrokerConnection', backref='user', lazy=True, cascade="all, delete-orphan")
    contact_messages = db.relationship('ContactMessage', backref='user', lazy=True)
    notes = db.relationship('JournalNote', backref='author', lazy=True)
    watchlists = db.relationship('Watchlist', backref='user', lazy=True)
    login_history = db.relationship('LoginLog', backref='user', lazy=True)
    admin_logs = db.relationship('AdminLog', backref='admin', lazy=True)

    # 🔐 Security helpers
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str):
        return check_password_hash(self.password_hash, password)

    def generate_reset_code(self):
        self.reset_code = ''.join(random.choices(string.digits, k=6))
        self.reset_expiration = datetime.utcnow() + timedelta(minutes=15)

    # 📊 Dashboard helpers
    def get_stats(self):
        from app import get_exchange_rate

        exchange_rate = get_exchange_rate(self.currency or "USD")
        trades = Trade.query.filter_by(user_id=self.id).all()
        closed = [t for t in trades if t.exit_time is not None]
        profits_usd = [t.profit for t in closed if t.profit is not None]

        profits = [p * exchange_rate for p in profits_usd]
        wins = [p for p in profits if p > 0]
        losses = [abs(p) for p in profits if p < 0]

        return {
            "total_trades": len(trades),
            "open_trades": len([t for t in trades if t.exit_time is None]),
            "total_profit": round(sum(profits), 2),
            "win_rate": round((len(wins) / len(profits)) * 100, 2) if profits else 0,
            "avg_win": round(sum(wins)/len(wins), 2) if wins else 0,
            "avg_loss": round(sum(losses)/len(losses), 2) if losses else 0,
            "risk_reward": f"1:{round(sum(wins)/sum(losses), 1)}" if losses else "1:0",
            "currency": self.currency,
            "exchange_rate": exchange_rate,
        }

# ---------------------- TRADE MODEL ----------------------

class Trade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    strategy_id = db.Column(db.Integer, db.ForeignKey('trading_strategy.id'))
    symbol = db.Column(db.String(20), nullable=False)
    trade_type = db.Column(db.String(10), nullable=False)  # 'buy' or 'sell'
    asset_type = db.Column(db.String(20))
    lot_size = db.Column(db.Float, nullable=False)  # renamed from quantity
    entry_position = db.Column(db.Float, nullable=False)  # renamed from entry_price
    closing_position = db.Column(db.Float)  # renamed from exit_price
    entry_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    exit_time = db.Column(db.DateTime)
    profit = db.Column(db.Float)
    pnl_percentage = db.Column(db.Float)
    risk_reward = db.Column(db.Float)
    commission = db.Column(db.Float, default=0.0)
    notes = db.Column(db.Text)
    emotional_state = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def calculate_profit(self):
        if self.entry_position and self.closing_position and self.lot_size:
            if self.trade_type == 'buy':
                self.profit = (self.closing_position - self.entry_position) * self.lot_size
            elif self.trade_type == 'sell':
                self.profit = (self.entry_position - self.closing_position) * self.lot_size
            else:
                self.profit = None

            if self.profit is not None and self.entry_position and self.lot_size:
                self.pnl_percentage = (self.profit / (self.entry_position * self.lot_size)) * 100
            return self.profit
        return None

    def to_dict(self):
     return {
        "id": self.id,
        "symbol": self.symbol or "N/A",
        "trade_type": (self.trade_type.capitalize() if self.trade_type else "Unknown"),
        "entry_position": round(self.entry_position, 5) if self.entry_position is not None else None,
        "closing_position": round(self.closing_position, 5) if self.closing_position is not None else None,
        "lot_size": round(self.lot_size, 2) if self.lot_size is not None else None,
        "profit": round(self.profit or 0, 2),
        "pnl_percentage": round(self.pnl_percentage or 0, 2) if self.pnl_percentage is not None else None,
        "entry_time": self.entry_time.strftime('%Y-%m-%d') if self.entry_time else None,
        "exit_time": self.exit_time.strftime('%b %d, %Y %I:%M %p') if self.exit_time else None,
        "notes": self.notes or "",
        "emotional_state": self.emotional_state or "Not Recorded",
        "asset_type": self.asset_type or "Unknown"  # Include this if you added asset_type to the model
    }



# ---------------------- STRATEGY MODEL ----------------------

class TradingStrategy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    asset_class = db.Column(db.String(50))
    time_frame = db.Column(db.String(50))
    risk_per_trade = db.Column(db.Float)
    success_rate = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    trades = db.relationship('Trade', backref='strategy', lazy=True)

# ---------------------- BROKER ----------------------

class BrokerConnection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    connected = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

# ---------------------- CONTACT MESSAGES ----------------------

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # nullable for guests
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(30), default='open')  # open, replied, closed
    reply_text = db.Column(db.Text)
    replied_at = db.Column(db.DateTime)

# ---------------------- WATCHLISTS ----------------------

class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('WatchlistItem', backref='watchlist', lazy=True)

class WatchlistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    watchlist_id = db.Column(db.Integer, db.ForeignKey('watchlist.id'), nullable=False)
    symbol = db.Column(db.String(20), nullable=False)
    notes = db.Column(db.Text)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------------- JOURNAL NOTES ----------------------

class JournalNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    mood = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ---------------------- LOGIN LOGS (Optional) ----------------------

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))

# ---------------------- ADMIN AUDIT LOG (Optional) ----------------------

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    target = db.Column(db.String(200))  # e.g. "Blocked user test@example.com"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

