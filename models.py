from database import Base
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy_utils.types import ChoiceType
from datetime import datetime

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True, index= True)
    username = Column(String(25), unique= True)
    email = Column(String(80), unique= True)
    password = Column(Text, nullable= True)
    is_staff = Column(Boolean, default=False)
    is_active = Column(Boolean, default= False)
    orders = relationship('Order', back_populates= 'user')

    def __repr__(self):
        return f"<User {self.username}>"

class TokenBlacklist(Base):
    __tablename__ = 'token_blacklist'
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(500), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<BlacklistedToken {self.token}>"

class PasswordResetToken(Base):
    __tablename__ = 'password_reset_tokens'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(80), nullable=False)
    token = Column(String(100), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)

    def __repr__(self):
        return f"<PasswordResetToken {self.token}>"

class Order(Base):
    ORDER_STATUSES = (
        ('PENDING', 'pending'),
        ('IN-TRANSIT', 'in-transit'),
        ('DELIVERED', 'delivered')

    )

    PIZZA_SIZES = (
        ('SMALL', 'small'),
        ('MEDIUM', 'medium'),
        ('LARGE', 'large'),
        ('EXTRA-LARGE', 'extra-large')
    )

    __tablename__ = 'orders'
    id = Column(Integer, primary_key=True)
    quantity = Column(Integer, nullable= False)
    order_status = Column(ChoiceType(choices=ORDER_STATUSES), default= 'PENDING')
    pizza_size = Column(ChoiceType(choices=PIZZA_SIZES), default= 'SMALL')
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship('User', back_populates= 'orders')

    def __repr__(self):
        return f"<Order {self.id}>"



