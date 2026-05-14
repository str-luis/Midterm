from fastapi import FastAPI, HTTPException, Depends
from sqlmodel import SQLModel, Session, select

from database import engine, get_session
from models import User, UserAuth
from security import get_password_hash, verify_password

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

app = FastAPI(on_startup=[create_db_and_tables])

@app.post("/register")
def register(user_data: UserAuth, session: Session = Depends(get_session)):
    db_user = session.exec(select(User).where(User.username == user_data.username)).first()
    if db_user:
        raise HTTPException(status_code=400, detail="El usuario ya existe")

    hashed = get_password_hash(user_data.password)
    
    new_user = User(username=user_data.username, hashed_password=hashed)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    
    return {"mensaje": "Usuario registrado con éxito", "usuario": new_user.username}

@app.post("/login")
def login(user_data: UserAuth, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == user_data.username)).first()
    if not user:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")

    if not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")

    return {"mensaje": "¡Login exitoso!"}