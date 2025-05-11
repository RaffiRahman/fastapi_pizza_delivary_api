from fastapi import FastAPI
from auth_routes import auth_router
from order_routes import order_router
from database import engine
import models

app = FastAPI()
app.include_router(auth_router)
app.include_router(order_router)

models.Base.metadata.create_all(bind=engine)