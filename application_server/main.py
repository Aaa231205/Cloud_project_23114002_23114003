from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
import sys
import jwt
from fastapi import Request
from fastapi.responses import JSONResponse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from security_modules.monitoring.logger import log_auth_success, log_auth_failure, log_ip_blocked, log_account_locked, log_security_event

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/cloud_db")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

import time
from sqlalchemy.exc import OperationalError

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db_container:5432/cloud_db")

def get_engine(retries=5, delay=5):
    for i in range(retries):
        try:
            engine = create_engine(DATABASE_URL)
            with engine.connect() as conn:
                pass
            print("Database connected!")
            return engine
        except OperationalError:
            print(f"Database not ready, retrying in {delay} seconds... ({i+1}/{retries})")
            time.sleep(delay)
    raise Exception("Could not connect to database")

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="user")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

class IPBlacklist(Base):
    __tablename__ = "ip_blacklist"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    failed_attempts = Column(Integer, default=1)
    blocked_until = Column(DateTime, nullable=True)
    last_attempt = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

app = FastAPI(root_path="/api")

@app.middleware("http")
async def ip_block_middleware(request: Request, call_next):
    client_ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For") or request.client.host
    
    db = SessionLocal()
    try:
        blocked_ip = db.query(IPBlacklist).filter(IPBlacklist.ip_address == client_ip).first()
        if blocked_ip and blocked_ip.blocked_until and blocked_ip.blocked_until > datetime.utcnow():
            remaining = (blocked_ip.blocked_until - datetime.utcnow()).seconds // 60
            return JSONResponse(status_code=403, content={"detail": f"IP is temporarily blocked. Try again in {remaining} minutes."})
            
        if blocked_ip and blocked_ip.blocked_until and blocked_ip.blocked_until <= datetime.utcnow():
            blocked_ip.failed_attempts = 0
            blocked_ip.blocked_until = None
            db.commit()
            
    finally:
        db.close()
        
    response = await call_next(request)
    return response

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.get("/")
def read_root():
    return {"message": "Secure Cloud App Server Running"}

@app.post("/auth/register")
def register(username: str, password: str, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = pwd_context.hash(password)
    new_user = User(username=username, password_hash=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"username": new_user.username, "msg": "User created"}

@app.post("/auth/login")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    client_ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For") or request.client.host
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        remaining = (user.locked_until - datetime.utcnow()).seconds // 60
        log_security_event("Account Locked Status Check", f"Attempted login on locked account: {user.username}", client_ip)
        raise HTTPException(status_code=403, detail=f"Account is locked. Try again in {remaining} minutes.")
        
    if user and user.locked_until and user.locked_until <= datetime.utcnow():
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

    if not user or not pwd_context.verify(form_data.password, user.password_hash):
        log_auth_failure(form_data.username, client_ip)
        
        ip_tracker = db.query(IPBlacklist).filter(IPBlacklist.ip_address == client_ip).first()
        if not ip_tracker:
            ip_tracker = IPBlacklist(ip_address=client_ip, failed_attempts=1)
            db.add(ip_tracker)
        else:
            if (datetime.utcnow() - ip_tracker.last_attempt).seconds > 60:
                ip_tracker.failed_attempts = 1
            else:
                ip_tracker.failed_attempts += 1
                
            ip_tracker.last_attempt = datetime.utcnow()
            
            if ip_tracker.failed_attempts >= 5:
                ip_tracker.blocked_until = datetime.utcnow() + timedelta(minutes=15)
                log_ip_blocked(client_ip, 15)
                
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                log_account_locked(user.username, 30)
                
        db.commit()
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    if user:
         user.failed_login_attempts = 0
         user.locked_until = None
    
    ip_tracker = db.query(IPBlacklist).filter(IPBlacklist.ip_address == client_ip).first()
    if ip_tracker:
         ip_tracker.failed_attempts = 0
         ip_tracker.blocked_until = None
         
    db.commit()
    log_auth_success(user.username, client_ip)
    
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
def read_users_me(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"username": username, "role": payload.get("role")}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
