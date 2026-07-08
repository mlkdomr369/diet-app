from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from google import genai
from google.genai import types
from pydantic import BaseModel
from passlib.context import CryptContext
import os
import json
import sqlite3
import jwt
import uuid
from datetime import datetime, timedelta

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("/var/pic", exist_ok=True)
app.mount("/static-images", StaticFiles(directory="/var/pic"), name="static-images")

SECRET_KEY = "CORE_IT_SUPER_SECRET_KEY_FOR_JWT"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def init_db():
    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            api_key TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            name TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS food_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            date TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            items TEXT NOT NULL,
            cal INTEGER NOT NULL,
            carb INTEGER NOT NULL,
            prot INTEGER NOT NULL,
            fat INTEGER NOT NULL,
            image_filename TEXT NOT NULL,
            feedback TEXT NOT NULL
        )
    """)
    cursor.execute("SELECT * FROM users WHERE id='admin'")
    if not cursor.fetchone():
        hashed_pw = pwd_context.hash("admin1234")
        cursor.execute("INSERT INTO users (id, password, api_key, is_admin, name) VALUES (?, ?, ?, ?, ?)",
                       ("admin", hashed_pw, "DEFAULT_KEY_CHANGE_ME", 1, "관리자"))
    conn.commit()
    conn.close()

init_db()

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreateRequest(BaseModel):
    username: str
    password: str
    api_key: str
    name: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

class LogSaveRequest(BaseModel):
    items: list
    total: dict
    image_filename: str
    feedback: str

def verify_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="인증 토큰이 누락되었습니다.")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

def verify_admin(payload: dict = Depends(verify_token)):
    if not payload.get("is_admin"):
        raise HTTPException(status_code=403, detail="관리자 권한이 없습니다.")
    return payload

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password, is_admin, name FROM users WHERE id = ?", (req.username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row or not pwd_context.verify(req.password, row[0]):
        raise HTTPException(status_code=400, detail="아이디 또는 비밀번호가 틀렸습니다.")
    
    token_data = {
        "sub": req.username,
        "is_admin": row[1],
        "name": row[2],
        "exp": datetime.utcnow() + timedelta(days=1)
    }
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token, "is_admin": bool(row[1]), "name": row[2]}

@app.get("/api/admin/users")
async def get_users(admin_info: dict = Depends(verify_admin)):
    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, api_key, is_admin, name FROM users")
    rows = cursor.fetchall()
    conn.close()
    return [{"username": r[0], "api_key": r[1], "is_admin": bool(r[2]), "name": r[3]} for r in rows]

@app.post("/api/admin/users")
async def create_user(req: UserCreateRequest, admin_info: dict = Depends(verify_admin)):
    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE id = ?", (req.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="이미 존재하는 계정입니다.")
    
    hashed_pw = pwd_context.hash(req.password)
    cursor.execute("INSERT INTO users (id, password, api_key, is_admin, name) VALUES (?, ?, ?, 0, ?)",
                   (req.username, hashed_pw, req.api_key, req.name))
    conn.commit()
    conn.close()
    return {"success": True}

@app.delete("/api/admin/users/{username}")
async def delete_user(username: str, admin_info: dict = Depends(verify_admin)):
    if username == "admin":
        raise HTTPException(status_code=400, detail="최초 관리자 계정은 삭제할 수 없습니다.")
    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (username,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/api/admin/change-password")
async def change_admin_password(req: PasswordChangeRequest, admin_info: dict = Depends(verify_admin)):
    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE id = 'admin'")
    row = cursor.fetchone()
    
    if not row or not pwd_context.verify(req.current_password, row[0]):
        conn.close()
        raise HTTPException(status_code=400, detail="현재 비밀번호가 일치하지 않습니다.")
    
    hashed_pw = pwd_context.hash(req.new_password)
    cursor.execute("UPDATE users SET password = ? WHERE id = 'admin'", (hashed_pw,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/api/user/change-password")
async def change_user_password(req: PasswordChangeRequest, user_info: dict = Depends(verify_token)):
    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE id = ?", (user_info["sub"],))
    row = cursor.fetchone()
    
    if not row or not pwd_context.verify(req.current_password, row[0]):
        conn.close()
        raise HTTPException(status_code=400, detail="현재 비밀번호가 일치하지 않습니다.")
    
    hashed_pw = pwd_context.hash(req.new_password)
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_pw, user_info["sub"]))
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/api/analyze-food")
async def analyze_food(file: UploadFile = File(...), user_info: dict = Depends(verify_token)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="이미지 파일만 업로드 가능합니다.")

    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("SELECT api_key FROM users WHERE id = ?", (user_info["sub"],))
    row = cursor.fetchone()
    conn.close()
    
    if not row or not row[0]:
        raise HTTPException(status_code=400, detail="할당된 API 키가 없습니다.")
    
    user_api_key = row[0]

    try:
        image_bytes = await file.read()
        
        file_ext = os.path.splitext(file.filename)[1]
        if not file_ext:
            file_ext = ".png"
        unique_filename = f"{uuid.uuid4().hex}{file_ext}"
        save_path = os.path.join("/var/pic", unique_filename)
        with open(save_path, "wb") as f:
            f.write(image_bytes)

        client = genai.Client(api_key=user_api_key)
        
        prompt = """
        당신은 전문 영양사입니다. 사진 속 음식을 한 덩어리로 뭉뚱그리지 마세요.
        포함된 개별 메뉴를 완전히 분리하여 각 메뉴당 이름 하나씩 부여하고 개별적으로 영양 정보를 분석하세요.
        마지막에는 분리된 모든 메뉴들의 영양 정보 총합(total)을 계산하여 포함해야 합니다.
        추가로 이 식단의 탄단지 밸런스를 분석하여 전문 영양사로서 사용자에게 전하는 냉철한 일침 및 강평(feedback)을 반드시 한 문장으로 작성해 포함하세요.
        반드시 아래 JSON 형식으로만 응답해야 하며 다른 텍스트는 절대 포함하지 마세요.
        {"items": [{"name": "쌀밥", "cal": 300, "carb": 65, "prot": 6, "fat": 1}], "total": {"cal": 300, "carb": 65, "prot": 6, "fat": 1}, "feedback": "한 줄 강평 내용"}
        """

        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=[
                prompt,
                types.Part.from_bytes(data=image_bytes, mime_type=file.content_type)
            ],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
            )
        )

        result = json.loads(response.text)
        result["image_filename"] = unique_filename
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"이미지 분석 중 오류 발생: {str(e)}")

@app.post("/api/logs")
async def save_log(req: LogSaveRequest, user_info: dict = Depends(verify_token)):
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")
    
    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO food_logs (user_id, date, timestamp, items, cal, carb, prot, fat, image_filename, feedback)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_info["sub"], date_str, time_str, json.dumps(req.items), req.total["cal"], req.total["carb"], req.total["prot"], req.total["fat"], req.image_filename, req.feedback))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/api/logs")
async def get_logs(user_info: dict = Depends(verify_token)):
    conn = sqlite3.connect("diet.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT date, timestamp, items, cal, carb, prot, fat, image_filename, feedback 
        FROM food_logs 
        WHERE user_id = ? 
        ORDER BY id DESC
    """, (user_info["sub"],))
    rows = cursor.fetchall()
    conn.close()
    
    return [{
        "date": r[0],
        "timestamp": r[1],
        "items": json.loads(r[2]),
        "cal": r[3],
        "carb": r[4],
        "prot": r[5],
        "fat": r[6],
        "image_filename": r[7],
        "feedback": r[8]
    } for r in rows]
