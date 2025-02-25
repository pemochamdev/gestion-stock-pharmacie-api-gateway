import uuid
import sqlalchemy as sa
from core.config import Base
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID, JSONB



class UserModel(Base):
    __tablename__ = "users"
    
    id = sa.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = sa.Column(sa.String(50), unique=True, nullable=False, index=True)
    email = sa.Column(sa.String(100), unique=True, nullable=False, index=True)
    hashed_password = sa.Column(sa.String(255), nullable=False)
    full_name = sa.Column(sa.String(100))
    disabled = sa.Column(sa.Boolean, default=False)
    roles = sa.Column(sa.ARRAY(sa.String), default=["user"])
    failed_login_attempts = sa.Column(sa.Integer, default=0)
    last_failed_login = sa.Column(sa.DateTime)
    account_locked_until = sa.Column(sa.DateTime)
    password_last_changed = sa.Column(sa.DateTime, default=func.now())
    require_password_change = sa.Column(sa.Boolean, default=False)
    mfa_secret = sa.Column(sa.String(32))
    mfa_enabled = sa.Column(sa.Boolean, default=False)
    created_at = sa.Column(sa.DateTime, default=func.now())
    updated_at = sa.Column(sa.DateTime, default=func.now(), onupdate=func.now())

class TokenBlacklistModel(Base):
    __tablename__ = "token_blacklist"
    
    id = sa.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_jti = sa.Column(sa.String(36), unique=True, nullable=False, index=True)
    user_id = sa.Column(UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False)
    expires_at = sa.Column(sa.DateTime, nullable=False)
    created_at = sa.Column(sa.DateTime, default=func.now())

class RefreshTokenModel(Base):
    __tablename__ = "refresh_tokens"
    
    id = sa.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token = sa.Column(sa.String(255), unique=True, nullable=False, index=True)
    user_id = sa.Column(UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False)
    expires_at = sa.Column(sa.DateTime, nullable=False)
    revoked = sa.Column(sa.Boolean, default=False)
    issued_at = sa.Column(sa.DateTime, default=func.now())
    ip_address = sa.Column(sa.String(45))
    user_agent = sa.Column(sa.String(255))
    device_id = sa.Column(sa.String(255))

class AuditLogModel(Base):
    __tablename__ = "audit_logs"
    
    id = sa.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = sa.Column(UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True)
    action = sa.Column(sa.String(100), nullable=False)
    resource = sa.Column(sa.String(100))
    ip_address = sa.Column(sa.String(45))
    user_agent = sa.Column(sa.String(255))
    request_path = sa.Column(sa.String(255))
    request_method = sa.Column(sa.String(10))
    status_code = sa.Column(sa.Integer)
    details = sa.Column(JSONB)
    timestamp = sa.Column(sa.DateTime, default=func.now())
