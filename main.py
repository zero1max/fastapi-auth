from fastapi import FastAPI, HTTPException, Depends
from models import User
from utils import hash_password, verify_password
from auth import create_access_token
from tortoise.contrib.fastapi import register_tortoise

app = FastAPI()

@app.post("/register/")
async def register(username: str, password: str):
    user = await User.filter(username=username).first()
    if user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    hashed_password = hash_password(password)
    new_user = await User.create(username=username, password_hash=hashed_password)
    return {"message": "User registered successfully"}


@app.post("/login/")
async def login(username: str, password: str):
    user = await User.filter(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={"models": ["models"]},
    generate_schemas=True,
    add_exception_handlers=True
)
