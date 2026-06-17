import os
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
import jwt

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# ==========================================
# 1. CONFIGURACIÓN DE BASE DE DATOS & SEGURIDAD
# ==========================================
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://usuario:password@localhost:5432/finanzas")
SECRET_KEY = os.getenv("SECRET_KEY", "tu_clave_secreta_super_segura_para_desarrollo")
ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="API de Gestión de Finanzas Personales Premium")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 2. MODELOS DE REPOSITORIO (SQLAlchemy)
# ==========================================
class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    ciclo_inicio_dia = Column(Integer, default=1)  # Día del mes en que inicia su ciclo financiero

class TransaccionDB(Base):
    __tablename__ = "transacciones"
    id = Column(Integer, primary_key=True, index=True)
    monto = Column(Float, nullable=False)
    tipo = Column(String, nullable=False)  # "ingreso" o "gasto"
    categoria = Column(String, nullable=False)  # "alimentacion", "transporte", etc.
    fecha = Column(DateTime, default=datetime.utcnow)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))

class PresupuestoDB(Base):
    __tablename__ = "presupuestos"
    id = Column(Integer, primary_key=True, index=True)
    categoria = Column(String, nullable=False)
    limite_maximo = Column(Float, nullable=False)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. ESQUEMAS DE VALIDACIÓN (Pydantic)
# ==========================================
class UsuarioRegistro(BaseModel):
    nombre: str
    email: EmailStr
    password: str
    ciclo_inicio_dia: Optional[int] = Field(1, ge=1, le=31)

class UsuarioLogin(BaseModel):
    email: EmailStr
    password: str

class TransaccionCrear(BaseModel):
    monto: float = Field(..., gt=0)
    tipo: str  # "ingreso" o "gasto"
    categoria: str
    fecha: Optional[datetime] = None

class PresupuestoConfig(BaseModel):
    categoria: str
    limite_maximo: float = Field(..., gt=0)

# ==========================================
# 4. FUNCIONES DE AYUDA (Seguridad y Ciclos)
# ==========================================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def crear_token(usuario_id: int) -> str:
    payload = {
        "sub": str(usuario_id),
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def obtener_usuario_por_token(token: str, db: Session = Depends(get_db)) -> UsuarioDB:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        usuario_id = int(payload.get("sub"))
        usuario = db.query(UsuarioDB).filter(UsuarioDB.id == usuario_id).first()
        if not usuario:
            raise HTTPException(status_code=401, detail="Usuario no encontrado.")
        return usuario
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado.")

def obtener_rango_ciclo_actual(inicio_dia: int) -> tuple[datetime, datetime]:
    hoy = datetime.utcnow()
    # Determinar el año y mes de inicio del ciclo actual
    if hoy.day >= inicio_dia:
        fecha_inicio = datetime(hoy.year, hoy.month, inicio_dia, 0, 0, 0)
    else:
        # Si hoy es menor al día de corte, el ciclo empezó el mes pasado
        mes_anterior = hoy.month - 1 if hoy.month > 1 else 12
        anio_anterior = hoy.year if hoy.month > 1 else hoy.year - 1
        fecha_inicio = datetime(anio_anterior, mes_anterior, inicio_dia, 0, 0, 0)
    
    # El ciclo termina exactamente un mes después de la fecha de inicio
    mes_fin = fecha_inicio.month + 1 if fecha_inicio.month < 12 else 1
    anio_fin = fecha_inicio.year if fecha_inicio.month < 12 else fecha_inicio.year + 1
    fecha_fin = datetime(anio_fin, mes_fin, inicio_dia, 23, 59, 59) - timedelta(days=1)
    
    return fecha_inicio, fecha_fin

# ==========================================
# 5. ENDPOINTS DE AUTENTICACIÓN
# ==========================================
@app.post("/auth/registrar", tags=["Autenticación"])
def registrar_usuario(usuario: UsuarioRegistro, db: Session = Depends(get_db)):
    existe = db.query(UsuarioDB).filter(UsuarioDB.email == usuario.email).first()
    if existe:
        raise HTTPException(status_code=400, detail="El correo ya está registrado.")
    
    nuevo_usuario = UsuarioDB(
        nombre=usuario.nombre,
        email=usuario.email,
        password_hash=hash_password(usuario.password),
        ciclo_inicio_dia=usuario.ciclo_inicio_dia
    )
    db.add(nuevo_usuario)
    db.commit()
    return {"mensaje": "Usuario creado exitosamente."}

@app.post("/auth/login", tags=["Autenticación"])
def login_usuario(usuario: UsuarioLogin, db: Session = Depends(get_db)):
    db_usuario = db.query(UsuarioDB).filter(UsuarioDB.email == usuario.email).first()
    if not db_usuario or db_usuario.password_hash != hash_password(usuario.password):
        raise HTTPException(status_code=400, detail="Credenciales incorrectas.")
    
    token = crear_token(db_usuario.id)
    return {"access_token": token, "token_type": "bearer", "nombre": db_usuario.nombre}

# ==========================================
# 6. ENDPOINTS DE TRANSACCIONES & CORE
# ==========================================
@app.post("/transacciones/", tags=["Transacciones"])
def crear_transaccion(transaccion: TransaccionCrear, token: str, db: Session = Depends(get_db)):
    usuario = obtener_usuario_por_token(token, db)
    nueva_transaccion = TransaccionDB(
        monto=transaccion.monto,
        tipo=transaccion.tipo.lower().strip(),
        categoria=transaccion.categoria.lower().strip(),
        fecha=transaccion.fecha if transaccion.fecha else datetime.utcnow(),
        usuario_id=usuario.id
    )
    db.add(nueva_transaccion)
    db.commit()
    return {"mensaje": "Transacción registrada con éxito."}

# ==========================================
# 7. ENDPOINTS AVANZADOS (Gráficas y Ciclos)
# ==========================================
@app.get("/balance/mensual/", tags=["Métricas Financieras"])
def obtener_balance_mensual(token: str, db: Session = Depends(get_db)):
    """
    Calcula los ingresos, gastos y ahorro acumulado del ciclo de cobro personalizado del usuario.
    """
    usuario = obtener_usuario_por_token(token, db)
    fecha_inicio, fecha_fin = obtener_rango_ciclo_actual(usuario.ciclo_inicio_dia)
    
    transacciones = db.query(TransaccionDB).filter(
        TransaccionDB.usuario_id == usuario.id,
        TransaccionDB.fecha >= fecha_inicio,
        TransaccionDB.fecha <= fecha_fin
    ).all()
    
    total_ingresos = sum(t.monto for t in transacciones if t.tipo == "ingreso")
    total_gastos = sum(t.monto for t in transacciones if t.tipo == "gasto")
    ahorro_neto = total_ingresos - total_gastos
    
    return {
        "ciclo_periodo": {
            "desde": fecha_inicio.strftime("%Y-%m-%d"),
            "hasta": fecha_fin.strftime("%Y-%m-%d"),
            "dia_corte_configurado": usuario.ciclo_inicio_dia
        },
        "total_ingresos": total_ingresos,
        "total_gastos": total_gastos,
        "ahorro_neto": ahorro_neto,
        "estado_financiero": "Superávit (Ahorro)" if ahorro_neto >= 0 else "Déficit (Pérdida)"
    }

@app.get("/graficos/pastel/", tags=["Visualización de Datos"])
def obtener_datos_grafico_pastel(token: str, db: Session = Depends(get_db)):
    """
    Procesa las categorías de gastos del ciclo actual estructuradas para Chart.js.
    Las categorías con porcentajes de gasto inferiores al 5% se agrupan automáticamente en 'Otros'.
    """
    usuario = obtener_usuario_por_token(token, db)
    fecha_inicio, fecha_fin = obtener_rango_ciclo_actual(usuario.ciclo_inicio_dia)
    
    # Obtener solo gastos del ciclo actual
    gastos = db.query(TransaccionDB).filter(
        TransaccionDB.usuario_id == usuario.id,
        TransaccionDB.tipo == "gasto",
        TransaccionDB.fecha >= fecha_inicio,
        TransaccionDB.fecha <= fecha_fin
    ).all()
    
    gastos_por_categoria = {}
    suma_total_gastos = 0.0
    
    for g in gastos:
        gastos_por_categoria[g.categoria] = gastos_por_categoria.get(g.categoria, 0.0) + g.monto
        suma_total_gastos += g.monto

    labels = []
    valores = []
    monto_otros = 0.0
    
    if suma_total_gastos > 0:
        for cat, monto in gastos_por_categoria.items():
            porcentaje = (monto / suma_total_gastos) * 100
            # Regla de negocio: Si representa menos del 5%, se agrupa en 'Otros' para limpiar la interfaz
            if porcentaje < 5.0:
                monto_otros += monto
            else:
                labels.append(cat.capitalize())
                valores.append(round(monto, 2))
                
        if monto_otros > 0:
            labels.append("Otros")
            valores.append(round(monto_otros, 2))

    return {
        "labels": labels,
        "valores": valores,
        "total_gastado_ciclo": round(suma_total_gastos, 2)
    }

# ==========================================
# 8. CONFIGURACIÓN DE CONFIGS ADICIONALES
# ==========================================
@app.post("/presupuestos/", tags=["Finanzas"])
def configurar_presupuesto(config: PresupuestoConfig, token: str, db: Session = Depends(get_db)):
    usuario = obtener_usuario_por_token(token, db)
    cat_clean = config.categoria.lower().strip()
    
    db_presupuesto = db.query(PresupuestoDB).filter(
        PresupuestoDB.categoria == cat_clean, 
        PresupuestoDB.usuario_id == usuario.id
    ).first()
    
    if db_presupuesto:
        db_presupuesto.limite_maximo = config.limite_maximo
    else:
        db_presupuesto = PresupuestoDB(categoria=cat_clean, limite_maximo=config.limite_maximo, usuario_id=usuario.id)
        db_add(db_presupuesto)
        
    db.commit()
    return {"mensaje": "Presupuesto guardado."}

@app.patch("/usuarios/ciclo-cobro", tags=["Configuración de Usuario"])
def actualizar_ciclo_cobro(dia: int, token: str, db: Session = Depends(get_db)):
    if dia < 1 or dia > 31:
        raise HTTPException(status_code=400, detail="El día debe estar entre 1 y 31.")
    usuario = obtener_usuario_por_token(token, db)
    usuario.ciclo_inicio_dia = dia
    db.commit()
    return {"mensaje": "Ciclo financiero actualizado."}