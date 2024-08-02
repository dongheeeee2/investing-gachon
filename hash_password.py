from passlib.context import CryptContext

# bcrypt 해싱 알고리즘을 사용하는 CryptContext 생성
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 비밀번호를 해싱
password = "secret"
hashed_password = pwd_context.hash(password)
print(hashed_password)