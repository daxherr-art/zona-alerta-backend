from fastapi import FastAPI, APIRouter, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from bson import ObjectId
import bcrypt
import jwt
import paypalrestsdk
from collections import defaultdict
import time

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'zona_alerta')]

JWT_SECRET = os.environ.get('JWT_SECRET', 'zona-alerta-secret-key-2026')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 720

paypalrestsdk.configure({
    "mode": os.environ.get('PAYPAL_MODE', 'sandbox'),
    "client_id": os.environ.get('PAYPAL_CLIENT_ID', ''),
    "client_secret": os.environ.get('PAYPAL_SECRET', '')
})

app = FastAPI(title="ZONA ALERTA API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()
api_call_tracker = defaultdict(list)
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: str
    email: str
    name: str
    subscription_tier: str = "free"
    subscription_expires: Optional[datetime] = None
    role: str = "user"
    created_at: datetime = Field(default_factory=datetime.utcnow)

class DangerReport(BaseModel):
    latitude: float
    longitude: float
    danger_type: str
    description: Optional[str] = None
    photo: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: str = "medium"
    user_id: Optional[str] = None

class DangerReportResponse(BaseModel):
    id: str
    latitude: float
    longitude: float
    danger_type: str
    description: Optional[str] = None
    photo: Optional[str] = None
    timestamp: datetime
    severity: str
    is_priority: bool = False
    user_id: Optional[str] = None

class SubscriptionPlan(BaseModel):
    plan: str
    payment_id: Optional[str] = None

class AppRatingResponse(BaseModel):
    id: str
    stars: int
    comment: Optional[str] = None
    user_name: str
    timestamp: datetime

class RatingStats(BaseModel):
    average: float
    total: int
    breakdown: dict

class RatingSubmit(BaseModel):
    stars: int
    comment: Optional[str] = None

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str) -> str:
    expiration = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    return jwt.encode({"user_id": user_id, "exp": expiration}, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"_id": ObjectId(payload["user_id"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def check_subscription_active(user: dict, required_tier: str = "basic") -> bool:
    tiers = {"free": 0, "basic": 1, "standard": 2, "premium": 3}
    user_tier = user.get("subscription_tier", "free")
    if tiers.get(user_tier, 0) < tiers.get(required_tier, 0):
        return False
    expires = user.get("subscription_expires")
    if expires and expires < datetime.utcnow():
        return False
    return True
  @api_router.post("/auth/register")
async def register(user_data: UserRegister):
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    trial_expires = datetime.utcnow() + timedelta(days=7)
    user_dict = {
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "name": user_data.name,
        "subscription_tier": "premium",
        "subscription_expires": trial_expires,
        "is_trial": True,
        "role": "user",
        "created_at": datetime.utcnow()
    }
    result = await db.users.insert_one(user_dict)
    token = create_token(str(result.inserted_id))
    return {"token": token, "user": User(id=str(result.inserted_id), email=user_data.email, name=user_data.name, subscription_tier="premium", subscription_expires=trial_expires, role="user"), "trial_days_remaining": 7}

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(str(user["_id"]))
    return {"token": token, "user": User(id=str(user["_id"]), email=user["email"], name=user["name"], subscription_tier=user.get("subscription_tier", "free"), subscription_expires=user.get("subscription_expires"), role=user.get("role", "user"))}

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    subscription_expires = current_user.get("subscription_expires")
    is_trial = current_user.get("is_trial", False)
    if is_trial and subscription_expires and subscription_expires < datetime.utcnow():
        await db.users.update_one({"_id": current_user["_id"]}, {"$set": {"subscription_tier": "free", "is_trial": False}})
        current_user["subscription_tier"] = "free"
    days_remaining = 0
    if subscription_expires and subscription_expires > datetime.utcnow():
        days_remaining = (subscription_expires - datetime.utcnow()).days
    return {**User(id=str(current_user["_id"]), email=current_user["email"], name=current_user["name"], subscription_tier=current_user.get("subscription_tier", "free"), subscription_expires=current_user.get("subscription_expires"), role=current_user.get("role", "user"), created_at=current_user.get("created_at", datetime.utcnow())).dict(), "is_trial": is_trial, "trial_days_remaining": days_remaining if is_trial else 0}

@api_router.post("/reports", response_model=DangerReportResponse)
async def create_report(report: DangerReport, current_user: dict = Depends(get_current_user)):
    report_dict = report.dict()
    report_dict["user_id"] = str(current_user["_id"])
    report_dict["is_priority"] = check_subscription_active(current_user, "standard")
    result = await db.danger_reports.insert_one(report_dict)
    report_dict["id"] = str(result.inserted_id)
    return DangerReportResponse(**report_dict)

@api_router.get("/reports", response_model=List[DangerReportResponse])
async def get_all_reports():
    reports = await db.danger_reports.find().sort("timestamp", -1).to_list(1000)
    return [DangerReportResponse(id=str(r["_id"]), latitude=r["latitude"], longitude=r["longitude"], danger_type=r["danger_type"], description=r.get("description"), photo=r.get("photo"), timestamp=r["timestamp"], severity=r.get("severity", "medium"), is_priority=r.get("is_priority", False), user_id=r.get("user_id")) for r in reports]

@api_router.delete("/reports/{report_id}")
async def delete_report(report_id: str, current_user: dict = Depends(get_current_user)):
    report = await db.danger_reports.find_one({"_id": ObjectId(report_id)})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    is_owner = report.get("user_id") == str(current_user["_id"])
    is_admin = current_user.get("role") == "admin"
    if not is_owner and not is_admin:
        raise HTTPException(status_code=403, detail="No permission")
    await db.danger_reports.delete_one({"_id": ObjectId(report_id)})
    return {"message": "Report deleted"}
  @api_router.post("/subscriptions/create-payment")
async def create_subscription_payment(plan_data: SubscriptionPlan, current_user: dict = Depends(get_current_user)):
    price = "4.99"
    app_url = os.environ.get('APP_URL', 'https://zona-alerta.app')
    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {"payment_method": "paypal"},
        "redirect_urls": {"return_url": f"{app_url}/payment/success", "cancel_url": f"{app_url}/payment/cancel"},
        "transactions": [{"amount": {"total": price, "currency": "USD"}, "description": "ZONA ALERTA Premium"}]
    })
    if payment.create():
        await db.pending_subscriptions.insert_one({"user_id": str(current_user["_id"]), "plan": "premium", "payment_id": payment.id, "created_at": datetime.utcnow()})
        for link in payment.links:
            if link.rel == "approval_url":
                return {"payment_id": payment.id, "approval_url": link.href}
    raise HTTPException(status_code=500, detail="Payment creation failed")

@api_router.post("/subscriptions/execute-payment")
async def execute_subscription_payment(payment_id: str, payer_id: str, current_user: dict = Depends(get_current_user)):
    payment = paypalrestsdk.Payment.find(payment_id)
    if payment.execute({"payer_id": payer_id}):
        pending = await db.pending_subscriptions.find_one({"payment_id": payment_id})
        if not pending:
            raise HTTPException(status_code=404, detail="Subscription not found")
        expires = datetime.utcnow() + timedelta(days=30)
        await db.users.update_one({"_id": ObjectId(current_user["_id"])}, {"$set": {"subscription_tier": "premium", "subscription_expires": expires, "is_trial": False}})
        await db.pending_subscriptions.delete_one({"payment_id": payment_id})
        return {"message": "Subscription activated", "expires": expires}
    raise HTTPException(status_code=500, detail="Payment execution failed")

@api_router.post("/ratings", response_model=AppRatingResponse)
async def submit_rating(rating_data: RatingSubmit, current_user: dict = Depends(get_current_user)):
    if rating_data.stars < 1 or rating_data.stars > 5:
        raise HTTPException(status_code=400, detail="Stars must be between 1 and 5")
    existing = await db.app_ratings.find_one({"user_id": str(current_user["_id"])})
    if existing:
        await db.app_ratings.update_one({"user_id": str(current_user["_id"])}, {"$set": {"stars": rating_data.stars, "comment": rating_data.comment, "timestamp": datetime.utcnow()}})
        rating_id = str(existing["_id"])
    else:
        result = await db.app_ratings.insert_one({"user_id": str(current_user["_id"]), "stars": rating_data.stars, "comment": rating_data.comment, "timestamp": datetime.utcnow()})
        rating_id = str(result.inserted_id)
    return AppRatingResponse(id=rating_id, stars=rating_data.stars, comment=rating_data.comment, user_name=current_user["name"], timestamp=datetime.utcnow())

@api_router.get("/ratings/stats", response_model=RatingStats)
async def get_rating_stats():
    ratings = await db.app_ratings.find().to_list(1000)
    if not ratings:
        return RatingStats(average=0, total=0, breakdown={1: 0, 2: 0, 3: 0, 4: 0, 5: 0})
    total = len(ratings)
    average = round(sum(r["stars"] for r in ratings) / total, 1)
    breakdown = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for r in ratings:
        breakdown[r["stars"]] += 1
    return RatingStats(average=average, total=total, breakdown=breakdown)

@api_router.post("/proximity/check")
async def check_proximity(latitude: float, longitude: float, radius: float = 0.5, current_user: dict = Depends(get_current_user)):
    if not check_subscription_active(current_user, "basic"):
        raise HTTPException(status_code=403, detail="Premium subscription required")
    all_reports = await db.danger_reports.find().to_list(1000)
    nearby = []
    for report in all_reports:
        lat_diff = abs(report["latitude"] - latitude)
        lng_diff = abs(report["longitude"] - longitude)
        distance = ((lat_diff ** 2 + lng_diff ** 2) ** 0.5) * 111
        if distance <= radius:
            nearby.append({"id": str(report["_id"]), "danger_type": report["danger_type"], "severity": report.get("severity", "medium"), "distance": round(distance, 2)})
    return {"nearby_dangers": nearby, "count": len(nearby), "should_alert": any(d["severity"] == "high" for d in nearby)}
  @api_router.get("/ratings", response_model=List[AppRatingResponse])
async def get_ratings():
    ratings = await db.app_ratings.find().sort("timestamp", -1).to_list(50)
    result = []
    for r in ratings:
        user = await db.users.find_one({"_id": ObjectId(r["user_id"])})
        result.append(AppRatingResponse(id=str(r["_id"]), stars=r["stars"], comment=r.get("comment"), user_name=user["name"] if user else "Usuario", timestamp=r["timestamp"]))
    return result

@api_router.get("/premium/trial-status")
async def get_trial_status(current_user: dict = Depends(get_current_user)):
    is_trial = current_user.get("is_trial", False)
    subscription_expires = current_user.get("subscription_expires")
    days_remaining = 0
    if is_trial and subscription_expires and subscription_expires > datetime.utcnow():
        days_remaining = (subscription_expires - datetime.utcnow()).days
    return {"is_trial": is_trial, "days_remaining": days_remaining, "subscription_tier": current_user.get("subscription_tier", "free")}

ADMIN_SECRET = os.environ.get('ADMIN_SECRET_PASSWORD', 'ZonaAlerta2026!')

@api_router.post("/auth/make-admin")
async def make_admin(email: str, admin_password: str):
    if admin_password != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid admin password")
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"role": "admin"}})
    return {"message": f"User {email} is now admin"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

@app.get("/")
async def root():
    return {"message": "ZONA ALERTA API", "version": "1.0", "author": "Dax HERRERA"}

@app.on_event("startup")
async def startup_db_client():
    logging.info("Connected to MongoDB")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
  
