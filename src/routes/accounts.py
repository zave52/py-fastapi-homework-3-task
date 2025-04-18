from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201,
    responses={
        409: {
            "description": "Conflict",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "A user with this email "
                                  "test@example.com already exists."
                    }
                }
            }
        },
        500: {
            "description": "Server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred during user creation."
                    }
                }
            }
        }
    }
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    query_email = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(query_email)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    query_group = select(UserGroupModel).where(
        UserGroupModel.name == UserGroupEnum.USER
    )
    result = await db.execute(query_group)
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(
            status_code=500,
            detail="Default user group not found"
        )

    try:
        new_user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=group.id
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        ) from e
    else:
        return UserRegistrationResponseSchema.model_validate(new_user)


@router.post(
    "/activate/", response_model=MessageResponseSchema, responses={
        400: {
            "description": "Bad request",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid or expired activation token."
                    }
                }
            }
        }
    }
)
async def activate_account(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    query = select(ActivationTokenModel).options(
        joinedload(ActivationTokenModel.user)
    ).join(UserModel).where(
        UserModel.email == activation_data.email,
        ActivationTokenModel.token == activation_data.token
    )
    result = await db.execute(query)
    token_record = result.scalar_one_or_none()

    now_utc = datetime.now(timezone.utc)
    if not token_record or cast(datetime, token_record.expires_at).replace(
        tzinfo=timezone.utc
    ) < now_utc:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    user = token_record.user
    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def reset_password(
    password_reset_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    query_user = select(UserModel).where(
        UserModel.email == password_reset_data.email
    )
    result = await db.execute(query_user)
    user = result.scalar_one_or_none()

    if user and user.is_active:
        query_tokens = delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        await db.execute(query_tokens)

        new_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(new_token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive "
                "an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    responses={
        400: {
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid email or token."
                    }
                }
            }
        },
        500: {
            "description": "Internal Server Error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while "
                                  "resetting the password."
                    }
                }
            }
        }
    }
)
async def reset_password_complete(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    query_user = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query_user)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    query_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result = await db.execute(query_token)
    token_record = result.scalar_one_or_none()

    now_utc = datetime.now(timezone.utc)
    if not token_record or token_record.token != data.token or cast(
        datetime, token_record.expires_at
    ).replace(tzinfo=timezone.utc) < now_utc:
        if token_record:
            await db.run_sync(lambda s: s.delete(token_record))
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = data.password
        await db.run_sync(lambda s: s.delete(token_record))
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201,
    responses={
        401: {
            "detail": "Unauthorized",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid email or password."
                    }
                }
            }
        },
        403: {
            "detail": "Forbidden",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User account is not activated."
                    }
                }
            }
        },
        500: {
            "detail": "Internal Server Error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while "
                                  "processing the request."
                    }
                }
            }
        }
    }
)
async def login(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    query = select(UserModel).where(UserModel.email == login_data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token
        )
        db.add(refresh_token)
        await db.flush()
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )

    jwt_access_token = jwt_manager.create_access_token({"user_id": user.id})
    return UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token
    )


@router.post(
    "/refresh/", response_model=TokenRefreshResponseSchema, responses={
        400: {
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Token has expired."
                    }
                }
            }
        },
        401: {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Refresh token not found."
                    }
                }
            }
        },
        404: {
            "description": "Not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User not found."
                    }
                }
            }
        }
    }
)
async def token_refresh(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = decoded_token.get("user_id")
    except BaseSecurityError as e:
        raise HTTPException(status_code=400, detail=str(e))

    query_token = select(RefreshTokenModel).where(
        RefreshTokenModel.token == data.refresh_token
    )
    result = await db.execute(query_token)
    token_record = result.scalar_one_or_none()
    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    query_user = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(query_user)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
