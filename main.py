from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import jwt

# ----------------------------------------------------
# CONFIGURACIÓN DE SEGURIDAD Y BASE DE DATOS
# ----------------------------------------------------
SECRET_KEY = "SUPER_SECRET_KEY_PARA_TU_PROYECTO_FINANCIERO"
ALGORITHM = "HS256"
# Encriptación nativa ultra estable
def hashear_contrasena(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verificar_contrasena(password_plana: str, password_hasheada: str) -> bool:
    return hashear_contrasena(password_plana) == password_hasheada

DATABASE_URL = "sqlite:///./finanzas.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# MIDDLEWARE CORS (Permiso para la web)
app = FastAPI(title="Finance Tracker API con Usuarios v3")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

# ----------------------------------------------------
# MODELOS DE LA BASE DE DATOS (Tablas SQL)
# ----------------------------------------------------
class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    correo = Column(String, unique=True, index=True, nullable=False)
    contrasena_hasheada = Column(String, nullable=False)
    
    presupuestos = relationship("PresupuestoDB", back_populates="usuario")
    transacciones = relationship("TransaccionDB", back_populates="usuario")

class PresupuestoDB(Base):
    __tablename__ = "presupuestos"
    id = Column(Integer, primary_key=True, index=True)
    categoria = Column(String, index=True)
    limite_maximo = Column(Float)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))

    usuario = relationship("UsuarioDB", back_populates="presupuestos")

class TransaccionDB(Base):
    __tablename__ = "transacciones"
    id = Column(Integer, primary_key=True, index=True)
    tipo = Column(String)  # 'ingreso' o 'gasto'
    categoria = Column(String)
    monto = Column(Float)
    fecha = Column(DateTime, default=datetime.utcnow)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))

    usuario = relationship("UsuarioDB", back_populates="transacciones")

Base.metadata.create_all(bind=engine)

# Dependencia de Conexión a Base de Datos
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# ----------------------------------------------------
# FUNCIONES DE AYUDA (Autenticación)
# ----------------------------------------------------
def obtener_usuario_por_token(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        correo: str = payload.get("sub")
        if correo is None: raise HTTPException(status_code=401, detail="Token inválido")
    except Exception:
        raise HTTPException(status_code=401, detail="Sesión expirada o inválida")
    
    usuario = db.query(UsuarioDB).filter(UsuarioDB.correo == correo).first()
    if usuario is None: raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return usuario

# ----------------------------------------------------
# MODELOS DE ENTRADA (Pydantic)
# ----------------------------------------------------
class AuthInput(BaseModel):
    correo: EmailStr = Field(..., example="usuario@correo.com")
    contrasena: str = Field(..., min_length=4, example="1234")

class PresupuestoConfig(BaseModel):
    categoria: str = Field(..., example="alimentacion")
    limite_maximo: float = Field(..., gt=0, example=300.0)

class TransaccionInput(BaseModel):
    tipo: str = Field(..., example="gasto")
    categoria: str = Field(..., example="alimentacion")
    monto: float = Field(..., gt=0, example=50.0)

# ----------------------------------------------------
# ENDPOINTS / RUTAS DE LA API
# ----------------------------------------------------

@app.post("/auth/registrar", tags=["Autenticación"])
def registrar_usuario(datos: AuthInput, db: Session = Depends(get_db)):
    existe = db.query(UsuarioDB).filter(UsuarioDB.correo == datos.correo.lower()).first()
    if existe: raise HTTPException(status_code=400, detail="El correo ya está registrado.")
    
    nuevo_usuario = UsuarioDB(
        correo=datos.correo.lower(),
        contrasena_hasheada=hashear_contrasena(datos.contrasena)
    )
    db.add(nuevo_usuario)
    db.commit()
    return {"mensaje": "Usuario registrado con éxito. Ya puedes iniciar sesión."}

@app.post("/auth/login", tags=["Autenticación"])
def login_usuario(datos: AuthInput, db: Session = Depends(get_db)):
    usuario = db.query(UsuarioDB).filter(UsuarioDB.correo == datos.correo.lower()).first()
    if not usuario or not verificar_contrasena(datos.contrasena, usuario.contrasena_hasheada):
        raise HTTPException(status_code=400, detail="Correo o contraseña incorrectos.")
    
    # Crear Llave de Acceso (Token) que dura 1 día
    expiracion = datetime.utcnow() + timedelta(days=1)
    token = jwt.encode({"sub": usuario.correo, "exp": expiracion}, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token, "correo": usuario.correo}

@app.post("/presupuestos/", tags=["Finanzas"])
def configurar_presupuesto(config: PresupuestoConfig, token: str, db: Session = Depends(get_db)):
    user = obtener_usuario_por_token(token, db)
    cat_clean = config.categoria.lower()
    
    db_presupuesto = db.query(PresupuestoDB).filter(PresupuestoDB.categoria == cat_clean, PresupuestoDB.usuario_id == user.id).first()
    if db_presupuesto:
        db_presupuesto.limite_maximo = config.limite_maximo
    else:
        db_presupuesto = PresupuestoDB(categoria=cat_clean, limite_maximo=config.limite_maximo, usuario_id=user.id)
        db.add(db_presupuesto)
    
    db.commit()
    return {"mensaje": "Presupuesto guardado."}

@app.get("/presupuestos/", tags=["Finanzas"])
def listar_presupuestos(token: str, db: Session = Depends(get_db)):
    user = obtener_usuario_por_token(token, db)
    presupuestos = db.query(PresupuestoDB).filter(PresupuestoDB.usuario_id == user.id).all()
    
    resumen = {}
    for p in presupuestos:
        gastos = db.query(TransaccionDB).filter(
            TransaccionDB.tipo == "gasto", TransaccionDB.categoria == p.categoria, TransaccionDB.usuario_id == user.id
        ).all()
        consumido = sum(g.monto for g in gastos)
        porcentaje = (consumido / p.limite_maximo) * 100 if p.limite_maximo > 0 else 0
        resumen[p.categoria] = {"consumido": consumido, "limite": p.limite_maximo, "porcentaje": porcentaje}
    return resumen

@app.post("/transacciones/", tags=["Finanzas"])
def registrar_transaccion(transaccion: TransaccionInput, token: str, db: Session = Depends(get_db)):
    user = obtener_usuario_por_token(token, db)
    cat_clean = transaccion.categoria.lower()
    alerta = None

    if transaccion.tipo == "gasto":
        p = db.query(PresupuestoDB).filter(PresupuestoDB.categoria == cat_clean, PresupuestoDB.usuario_id == user.id).first()
        if p:
            gastos = db.query(TransaccionDB).filter(
                TransaccionDB.tipo == "gasto", TransaccionDB.categoria == cat_clean, TransaccionDB.usuario_id == user.id
            ).all()
            total_gastado = sum(g.monto for g in gastos) + transaccion.monto
            pct = (total_gastado / p.limite_maximo) * 100
            if total_gastado > p.limite_maximo:
                alerta = f"🚨 ¡ALERTA DE EXCESO! Superaste el presupuesto en '{transaccion.categoria}'. Consumido: {pct:.1f}%."
            elif pct >= 80.0:
                alerta = f"⚠️ Estás llegando al límite de gasto en '{transaccion.categoria}'. Consumido: {pct:.1f}%."

    nueva_t = TransaccionDB(tipo=transaccion.tipo.lower(), categoria=cat_clean, monto=transaccion.monto, usuario_id=user.id)
    db.add(nueva_t)
    db.commit()
    return {"estatus": "Guardada", "notificacion": alerta}

@app.get("/transacciones/", tags=["Finanzas"])
def obtener_historial(token: str, db: Session = Depends(get_db)):
    user = obtener_usuario_por_token(token, db)
    return db.query(TransaccionDB).filter(TransaccionDB.usuario_id == user.id).all()

@app.post("/reiniciar/", tags=["Finanzas"])
def reiniciar_datos(token: str, db: Session = Depends(get_db)):
    user = obtener_usuario_por_token(token, db)
    db.query(TransaccionDB).filter(TransaccionDB.usuario_id == user.id).delete()
    db.query(PresupuestoDB).filter(PresupuestoDB.usuario_id == user.id).delete()
    db.commit()
    return {"mensaje": "Datos del usuario limpiados."}