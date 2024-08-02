from fastapi import FastAPI, File, UploadFile, Form, Request, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import List, Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
import shutil
import os
import uvicorn
from datetime import datetime, timedelta

# to get a string like this run: openssl rand -hex 32
SECRET_KEY = "a64cbf29e36e1bb3dfc24f56ec53f26b65e70309b6822d11afae14bf32be04fc"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 해싱된 비밀번호 업데이트
hashed_password = "$2b$12$bAuH2qimdvKlPvxo7TpuOuBPkz5p1XnVtbcXSF55dhu4efC0qJsHm"  # secret

fake_users_db = {
    "admin": {
        "username": "admin",
        "full_name": "Admin User",
        "email": "admin@example.com",
        "hashed_password": hashed_password,
        "disabled": False,
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="자격 증명을 확인할 수 없습니다.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="비활성화된 사용자입니다.")
    return current_user

app = FastAPI()

# Static and Template directories
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/uploaded_files", StaticFiles(directory="uploaded_files"), name="uploaded_files")
templates = Jinja2Templates(directory="templates")

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    year = Column(Integer, index=True)
    company_name = Column(String, index=True)
    file_path = Column(String, index=True)

Base.metadata.create_all(bind=engine)

# Schemas
class ReportBase(BaseModel):
    year: int
    company_name: str
    file_path: str

class ReportCreate(ReportBase):
    pass

class ReportResponse(ReportBase):
    id: int
    class Config:
        orm_mode = True

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Routes
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="잘못된 사용자 이름 또는 비밀번호",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/uploadfile/", response_model=ReportResponse)
async def create_upload_file(year: int = Form(...), company_name: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    upload_dir = "uploaded_files"
    os.makedirs(upload_dir, exist_ok=True)
    file_location = os.path.join(upload_dir, f"{year}_{file.filename}")
    with open(file_location, "wb+") as file_object:
        shutil.copyfileobj(file.file, file_object)

    db_report = Report(year=year, company_name=company_name, file_path=file_location)
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report

@app.get("/api/reports/", response_model=List[ReportResponse])
def read_reports(skip: int = 0, limit: int = 10, search: str = "", db: Session = Depends(get_db)):
    query = db.query(Report)
    if search:
        query = query.filter(Report.company_name.contains(search))
    reports = query.offset(skip).limit(limit).all()
    return reports

@app.delete("/api/reports/{report_id}", response_model=ReportResponse)
def delete_report(report_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="보고서를 찾을 수 없습니다.")
    db.delete(report)
    db.commit()
    if os.path.exists(report.file_path):
        os.remove(report.file_path)
    return report

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)