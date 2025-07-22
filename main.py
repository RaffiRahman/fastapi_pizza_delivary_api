import inspect, re
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.openapi.utils import get_openapi
from fastapi_mail import ConnectionConfig
from auth_routes import auth_router
from order_routes import order_router
from database import engine, SessionLocal
from datetime import datetime, timedelta
import models
from fastapi_jwt_auth import AuthJWT
from schemas import Settings
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import Request
from fastapi.responses import JSONResponse

app = FastAPI()


# for Bearer JWT Auth on Swagger UI_____________________________________
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title = "Pizza Delivery API",
        version = "1.0",
        description = "An API for a Pizza Delivery Service",
        routes = app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "Bearer Auth": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Enter: **'Bearer &lt;JWT&gt;'**, where JWT is the access token"
        }
    }

    # Get all routes where jwt_optional() or jwt_required
    api_router = [route for route in app.routes if isinstance(route, APIRoute)]

    for route in api_router:
        path = getattr(route, "path")
        endpoint = getattr(route,"endpoint")
        methods = [method.lower() for method in getattr(route, "methods")]

        for method in methods:
            # access_token
            if (
                re.search("jwt_required", inspect.getsource(endpoint)) or
                re.search("fresh_jwt_required", inspect.getsource(endpoint)) or
                re.search("jwt_optional", inspect.getsource(endpoint))
            ):
                openapi_schema["paths"][path][method]["security"] = [
                    {
                        "Bearer Auth": []
                    }
                ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

#__________________________________________________________________________

@AuthJWT.load_config
def get_config():
    return Settings()

app.include_router(auth_router)
app.include_router(order_router)

models.Base.metadata.create_all(bind=engine)

#________________________________________________________________________________

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

@AuthJWT.token_in_denylist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    db = None
    try:
        db = SessionLocal()
        return db.query(models.TokenBlacklist).filter(
            models.TokenBlacklist.token == jti,
            models.TokenBlacklist.created_at >= (
                datetime.utcnow() - timedelta(days=1)
            )  # Only check recent blacklisted tokens
        ).first() is not None
    except Exception as e:
        print(f"Blacklist check error: {e}")
        return False
    finally:
        if db:
            db.close()
#_____________________________________________________________________________________

# Email configuration
conf = ConnectionConfig(
    MAIL_USERNAME="your_email@example.com",
    MAIL_PASSWORD="your_email_password",
    MAIL_FROM="your_email@example.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.example.com",
    MAIL_TLS=True,
    MAIL_SSL=False,
    USE_CREDENTIALS=True
)