from datetime import datetime, timedelta
from fastapi import APIRouter, status, Depends, Request, BackgroundTasks
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr
from database import SessionLocal, engine, get_db
from main import conf
from schemas import SignUpModel, LoginModel, UserResponseModel, ForgotPasswordModel, ResetPasswordModel
from models import User, TokenBlacklist, PasswordResetToken
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Session
from fastapi_jwt_auth import AuthJWT
import secrets
import string



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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
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


# logout
@auth_router.post('/logout')
async def logout(
        Authorize: AuthJWT = Depends(),
        db: Session = Depends(get_db),
        request: Request = None
):
    """
    ## Logout a user
    This invalidates both access and refresh tokens.
    Returns 200 on success, 401 on invalid token.
    """
    try:
        # Verify the access token first
        Authorize.jwt_required()

        # Get both tokens from the request
        access_jti = Authorize.get_raw_jwt()['jti']
        refresh_token = request.cookies.get('refresh_token_cookie') or \
                        (await request.json()).get('refresh_token', None)

        # Blacklist access token
        db.add(TokenBlacklist(token=access_jti, created_at=datetime.utcnow()))

        # If refresh token exists, blacklist it too
        if refresh_token:
            try:
                Authorize._token = refresh_token
                refresh_jti = Authorize.get_raw_jwt(refresh_token)['jti']
                db.add(TokenBlacklist(token=refresh_jti, created_at=datetime.utcnow()))
            except:
                pass  # Refresh token might be invalid/expired

        db.commit()

        return {"message": "Successfully logged out"}

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

# Password Reset
def generate_reset_token(length=32):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


async def send_reset_email(email: str, token: str, background_tasks: BackgroundTasks):
    reset_link = f"http://yourfrontend.com/reset-password?token={token}"
    message = MessageSchema(
        subject="Password Reset Request",
        recipients= [email],
        body=f"""
        You requested a password reset. 
        Please click the following link to reset your password:
        {reset_link}

        This link will expire in 1 hour.
        If you didn't request this, please ignore this email.
        """,
        subtype="plain"
    )

    fm = FastMail(conf)
    background_tasks.add_task(fm.send_message, message)


@auth_router.post('/forgot-password')
async def forgot_password(
        email_data: ForgotPasswordModel,
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    """
    ## Initiate password reset
    This sends a password reset link to the user's email if the email exists.
    """
    user = db.query(User).filter(User.email == email_data.email).first()
    if not user:
        # Don't reveal whether email exists for security
        return {"message": "If this email exists, a reset link has been sent"}

    # Delete any existing tokens for this email
    db.query(PasswordResetToken).filter(
        PasswordResetToken.email == email_data.email
    ).delete()

    # Generate new token
    token = generate_reset_token()
    expires_at = datetime.utcnow() + timedelta(hours=1)

    # Save token to database
    reset_token = PasswordResetToken(
        email=email_data.email,
        token=token,
        expires_at=expires_at
    )
    db.add(reset_token)
    db.commit()

    # Send email in background
    await send_reset_email(email_data.email, token, background_tasks)

    return {"message": "If this email exists, a reset link has been sent"}


@auth_router.post('/reset-password')
async def reset_password(
        reset_data: ResetPasswordModel,
        db: Session = Depends(get_db)
):
    """
    ## Reset user password
    This resets the user's password using a valid reset token.
    """
    # Find valid token
    token_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == reset_data.token,
        PasswordResetToken.expires_at >= datetime.utcnow(),
        PasswordResetToken.used == False
    ).first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token"
        )

    # Find user
    user = db.query(User).filter(User.email == token_record.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Update password
    user.password = generate_password_hash(reset_data.new_password)
    token_record.used = True
    db.commit()

    return {"message": "Password has been reset successfully"}