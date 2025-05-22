from fastapi import APIRouter, status, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from database import SessionLocal, engine, get_db
from schemas import SignUpModel, LoginModel, UserResponseModel
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Session
from fastapi_jwt_auth import AuthJWT



auth_router = APIRouter(
    prefix= '/auth',
    tags= ['auth']
)

session = SessionLocal(bind= engine)

@auth_router.get('/')
async def hello(Authorize: AuthJWT = Depends()):
    """
        ## Sample hello route
    """
    try:
        Authorize.jwt_required()

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORABLE,
                            detail= "Invalid credentials")
    return {'message': 'Hello'}

@auth_router.post('/signup', response_model= UserResponseModel,
                  status_code=status.HTTP_201_CREATED
                  )
async def signup(user: SignUpModel, db: Session = Depends(get_db)):
    """
        ## Create a user
        This requires the following
        ```
                username:int
                email:str
                password:str
                is_staff:bool
                is_active:bool

        ```
    """
    db_email = db.query(User).filter(User.email == user.email).first()
    if db_email is not None:
        raise HTTPException(status_code= status.HTTP_400_BAD_REQUEST,
                             detail= "User with the email already exists!")

    db_username = db.query(User).filter(User.username == user.username).first()
    if db_username is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail="User with the username already exists!")

    new_user = User(
        username= user.username,
        email= user.email,
        password= generate_password_hash(user.password),
        is_active= user.is_active,
        is_staff= user.is_staff
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {
        "username": new_user.username,
        "email": new_user.email,
        "is_active": new_user.is_active,
        "is_staff": new_user.is_staff
    }

#login route

@auth_router.post('/login', status_code= 200)
async def login(user: LoginModel, Authorize: AuthJWT = Depends()):
    """
        ## Login a user
        This requires
            ```
                    username:str
                    password:str
            ```
        and returns a token pair `access` and `refresh`
    """
    db_user= session.query(User).filter(User.username == user.username).first()
    if db_user and check_password_hash(db_user.password, user.password):
        access_token = Authorize.create_access_token(subject= db_user.username)
        refresh_token = Authorize.create_refresh_token(subject= db_user.username)

        response = {
            "access": access_token,
            "refresh": refresh_token
        }

        return jsonable_encoder(response)
    raise HTTPException(status_code= status.HTTP_400_BAD_REQUEST,
                        detail= "Invalid Username or Password")


#refreshing tokens

@auth_router.get('/refresh')
async def refresh_token(Authorize: AuthJWT = Depends()):
    """
        ## create a fresh token
        This creates a fresh token. It requires a refresh token.

    """
    try:
        Authorize.jwt_refresh_token_required()

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail= "Please provide a valid refresh token")

    current_user = Authorize.get_jwt_subject()

    access_token = Authorize.create_access_token(subject= current_user)

    return jsonable_encoder({'access_token': access_token})

