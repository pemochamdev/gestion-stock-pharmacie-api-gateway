import re
import hmac
import httpx
import hashlib
import logging
from jose import  jwt
from core import config
from api.deps import app
from fastapi import Response
from fastapi.responses import JSONResponse
from core.utils import get_db
from models.user import UserModel
from models.user import UserModel
from datetime import datetime,time
from sqlalchemy.orm import Session
from datetime import datetime,timedelta
from fastapi import  Depends, HTTPException, status,Request
from models.schemas import Token,LoginRequest,MFASetup,MFAVerify
from api.deps import oauth2_scheme,get_current_active_user,get_current_user,has_role
from api.auth import authenticate_user
from core.security import (
    log_audit,verify_mfa_code,
    verify_password,create_refresh_token,
    blacklist_token,generate_mfa_secret,
    get_mfa_uri,hash_password
)
from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError
import sqlalchemy as sa
from core.utils import create_access_token,get_db
from models.schemas import RefreshTokenRequest,LoginRequest,UserCreate,UserResponse
from models.user import RefreshTokenModel,UserModel,AuditLogModel



# ============= Routes d'authentification =============
@app.post("/auth/token", response_model=Token)
async def login_for_access_token(
    request: Request,
    form_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """Route d'authentification pour obtenir un token JWT"""
    user = authenticate_user(db, form_data.username, form_data.password.get_secret_value())
    
    if not user:
        # Journaliser la tentative échouée
        log_audit(
            db,
            None,
            "FAILED_LOGIN",
            "authentication",
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
            request_path=request.url.path,
            request_method=request.method,
            status_code=401,
            details={"username": form_data.username}
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Vérifier MFA si activé pour l'utilisateur
    if user.mfa_enabled:
        if not form_data.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Code MFA requis",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not verify_mfa_code(user.mfa_secret, form_data.mfa_code):
            # Journaliser l'échec MFA
            log_audit(
                db,
                user.id,
                "FAILED_MFA",
                "authentication",
                ip_address=request.client.host,
                user_agent=request.headers.get("User-Agent"),
                request_path=request.url.path,
                request_method=request.method,
                status_code=401
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Code MFA invalide",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    # Créer les tokens
    access_token_expires = timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token, jti, expires_at = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "roles": user.roles
        },
        expires_delta=access_token_expires
    )
    
    # Créer le refresh token
    refresh_token, refresh_expires = create_refresh_token(
        db,
        user.id,
        request.client.host,
        request.headers.get("User-Agent"),
        form_data.device_id
    )
    
    # Journaliser la connexion réussie
    # Journaliser la connexion réussie
    log_audit(
        db,
        user.id,
        "SUCCESSFUL_LOGIN",
        "authentication",
        ip_address=request.client.host,
        user_agent=request.headers.get("User-Agent"),
        request_path=request.url.path,
        request_method=request.method,
        status_code=200,
        details={"with_mfa": user.mfa_enabled}
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_at": expires_at
    }

@app.post("/auth/refresh", response_model=Token)
async def refresh_access_token(
    request: Request,
    refresh_request: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Rafraîchir un token d'accès avec un token de rafraîchissement"""
    # Rechercher le refresh token
    refresh_token = db.query(RefreshTokenModel).filter(
        RefreshTokenModel.token == refresh_request.refresh_token,
        RefreshTokenModel.revoked == False,
        RefreshTokenModel.expires_at > datetime.utcnow()
    ).first()
    
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de rafraîchissement invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Vérifier l'ID de l'appareil si fourni
    if refresh_request.device_id and refresh_token.device_id and refresh_request.device_id != refresh_token.device_id:
        # Journaliser la tentative potentiellement malveillante
        log_audit(
            db,
            refresh_token.user_id,
            "REFRESH_TOKEN_DEVICE_MISMATCH",
            "authentication",
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
            request_path=request.url.path,
            request_method=request.method,
            status_code=401,
            details={"refresh_token_id": str(refresh_token.id)}
        )
        
        # Révoquer tous les tokens de l'utilisateur par mesure de sécurité
        db.query(RefreshTokenModel).filter(
            RefreshTokenModel.user_id == refresh_token.user_id
        ).update({"revoked": True})
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Appareil non reconnu, tous les tokens ont été révoqués par mesure de sécurité",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Récupérer l'utilisateur
    user = db.query(UserModel).filter(UserModel.id == refresh_token.user_id).first()
    
    if not user or user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Utilisateur non trouvé ou désactivé",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Créer un nouveau token d'accès
    access_token_expires = timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token, jti, expires_at = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "roles": user.roles
        },
        expires_delta=access_token_expires
    )
    
    # Créer un nouveau refresh token et révoquer l'ancien
    new_refresh_token, refresh_expires = create_refresh_token(
        db,
        user.id,
        request.client.host,
        request.headers.get("User-Agent"),
        refresh_request.device_id or refresh_token.device_id
    )
    
    refresh_token.revoked = True
    db.commit()
    
    # Journaliser le rafraîchissement réussi
    log_audit(
        db,
        user.id,
        "TOKEN_REFRESHED",
        "authentication",
        ip_address=request.client.host,
        user_agent=request.headers.get("User-Agent"),
        request_path=request.url.path,
        request_method=request.method,
        status_code=200
    )
    
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_at": expires_at
    }

@app.post("/auth/logout")
async def logout(
    request: Request,
    token: str = Depends(oauth2_scheme),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Déconnexion et révocation du token"""
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        jti = payload.get("jti")
        
        if jti:
            # Ajouter le token à la liste noire
            blacklist_token(db, jti, current_user.id, datetime.fromisoformat(payload.get("exp")))
        
        # Révoquer tous les refresh tokens de la session actuelle
        device_id = request.headers.get("X-Device-ID")
        if device_id:
            db.query(RefreshTokenModel).filter(
                RefreshTokenModel.user_id == current_user.id,
                RefreshTokenModel.device_id == device_id
            ).update({"revoked": True})
        else:
            # Si pas d'ID d'appareil, révoquer tous les tokens de l'IP actuelle
            db.query(RefreshTokenModel).filter(
                RefreshTokenModel.user_id == current_user.id,
                RefreshTokenModel.ip_address == request.client.host
            ).update({"revoked": True})
            
        db.commit()
        
        # Journaliser la déconnexion
        log_audit(
            db,
            current_user.id,
            "LOGOUT",
            "authentication",
            ip_address=request.client.host,
            user_agent=request.headers.get("User-Agent"),
            request_path=request.url.path,
            request_method=request.method,
            status_code=200
        )
        
        return {"status": "success", "message": "Déconnexion réussie"}
    except Exception as e:
        logging.error(f"Erreur lors de la déconnexion: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la déconnexion"
        )

@app.post("/auth/mfa/setup", response_model=MFASetup)
async def setup_mfa(
    current_user: UserModel = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Configuration de l'authentification à deux facteurs"""
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="L'authentification à deux facteurs est déjà activée"
        )
    
    # Générer un nouveau secret
    secret = generate_mfa_secret()
    uri = get_mfa_uri(current_user.username, secret)
    
    # Stocker temporairement le secret (à confirmer)
    current_user.mfa_secret = secret
    db.commit()
    
    return {"secret": secret, "uri": uri}

@app.post("/auth/mfa/activate")
async def activate_mfa(
    mfa_verify: MFAVerify,
    current_user: UserModel = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Activer l'authentification à deux facteurs après vérification"""
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="L'authentification à deux facteurs est déjà activée"
        )
    
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Veuillez d'abord configurer l'authentification à deux facteurs"
        )
    
    # Vérifier le code
    if not verify_mfa_code(current_user.mfa_secret, mfa_verify.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code invalide"
        )
    
    # Activer MFA
    current_user.mfa_enabled = True
    db.commit()
    
    # Journaliser l'activation
    log_audit(
        db,
        current_user.id,
        "MFA_ACTIVATED",
        "user_settings"
    )
    
    return {"status": "success", "message": "Authentification à deux facteurs activée avec succès"}

@app.post("/auth/mfa/deactivate")
async def deactivate_mfa(
    mfa_verify: MFAVerify,
    current_user: UserModel = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Désactiver l'authentification à deux facteurs"""
    if not current_user.mfa_enabled or not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="L'authentification à deux facteurs n'est pas activée"
        )
    
    # Vérifier le code
    if not verify_mfa_code(current_user.mfa_secret, mfa_verify.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code invalide"
        )
    
    # Désactiver MFA
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()
    
    # Journaliser la désactivation
    log_audit(
        db,
        current_user.id,
        "MFA_DEACTIVATED",
        "user_settings"
    )
    
    return {"status": "success", "message": "Authentification à deux facteurs désactivée avec succès"}

@app.post("/auth/change-password")
async def change_password(
    current_password: SecretStr,
    new_password: SecretStr,
    current_user: UserModel = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Changer le mot de passe de l'utilisateur"""
    # Valider le nouveau mot de passe
    password = new_password.get_secret_value()
    if len(password) < config.PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Le mot de passe doit contenir au moins {config.PASSWORD_MIN_LENGTH} caractères"
        )
    if config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins une lettre majuscule"
        )
    if config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins une lettre minuscule"
        )
    if config.PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins un chiffre"
        )
    if config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins un caractère spécial"
        )
    
    # Vérifier le mot de passe actuel
    if not verify_password(current_password.get_secret_value(), current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mot de passe actuel incorrect"
        )
    
    # Mettre à jour le mot de passe
    current_user.hashed_password = hash_password(password)
    current_user.password_last_changed = datetime.utcnow()
    current_user.require_password_change = False
    db.commit()
    
    # Révoquer tous les tokens actifs pour forcer une nouvelle connexion
    db.query(RefreshTokenModel).filter(
        RefreshTokenModel.user_id == current_user.id,
        RefreshTokenModel.revoked == False
    ).update({"revoked": True})
    db.commit()
    
    # Journaliser le changement de mot de passe
    log_audit(
        db,
        current_user.id,
        "PASSWORD_CHANGED",
        "user_settings"
    )
    
    return {"status": "success", "message": "Mot de passe modifié avec succès"}

# ============= Routes de gestion des utilisateurs =============
@app.post("/users", response_model=UserResponse)
async def create_user(
    user_create: UserCreate,
    current_user: UserModel = Depends(has_role(["admin"])),
    db: Session = Depends(get_db)
):
    """Créer un nouvel utilisateur (admin uniquement)"""
    # Vérifier si l'utilisateur existe déjà
    existing_user = db.query(UserModel).filter(
        (UserModel.username == user_create.username) | 
        (UserModel.email == user_create.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nom d'utilisateur ou email déjà utilisé"
        )
    
    # Créer l'utilisateur
    hashed_password = hash_password(user_create.password.get_secret_value())
    new_user = UserModel(
        username=user_create.username,
        email=user_create.email,
        hashed_password=hashed_password,
        full_name=user_create.full_name,
        require_password_change=True  # Forcer le changement au premier login
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Journaliser la création
    log_audit(
        db,
        current_user.id,
        "USER_CREATED",
        "user_management",
        details={"created_user_id": str(new_user.id)}
    )
    
    return new_user

@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: UserModel = Depends(get_current_active_user)
):
    """Obtenir les informations de l'utilisateur actuel"""
    return current_user

# ============= Routes de proxy vers les microservices =============
@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_endpoint(
    service: str, 
    path: str, 
    request: Request,
    current_user: UserModel = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Proxy intelligent vers les microservices"""
    if service not in config.SERVICE_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service}' non trouvé"
        )
    
    # Obtenir l'URL cible
    target_url = f"{config.SERVICE_REGISTRY[service]}/{path}"
    
    # Obtenir le corps de la requête
    body = None
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.json()
        except:
            # Si ce n'est pas du JSON, essayer de récupérer les données du formulaire
            try:
                form_data = await request.form()
                body = dict(form_data)
            except:
                # Si ce n'est pas un formulaire, utiliser les données brutes
                body = await request.body()
    
    # Obtenir les headers
    headers = dict(request.headers)
    
    # Supprimer les headers qui ne doivent pas être transmis
    for header in ["host", "connection", "content-length"]:
        if header in headers:
            del headers[header]
    
    # Ajouter les en-têtes d'authentification et d'audit pour les services backend
    headers["X-User-ID"] = str(current_user.id)
    headers["X-Username"] = current_user.username
    headers["X-User-Roles"] = ",".join(current_user.roles)
    headers["X-Request-ID"] = request.state.request_id
    
    # Ajouter une signature pour authentifier que la requête provient du gateway
    timestamp = str(int(time.time()))
    signature_data = f"{request.method}:{target_url}:{timestamp}:{current_user.id}"
    signature = hmac.new(
        config.SECRET_KEY.encode(),
        signature_data.encode(),
        hashlib.sha256
    ).hexdigest()
    
    headers["X-Gateway-Timestamp"] = timestamp
    headers["X-Gateway-Signature"] = signature
    
    # Envoyer la requête au service cible avec un client HTTPS sécurisé
    async with httpx.AsyncClient(timeout=30.0, verify=True) as client:
        try:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                params=request.query_params,
                content=body if isinstance(body, bytes) else None,
                json=body if not isinstance(body, bytes) else None
            )
            
            # Journaliser la requête au microservice
            log_audit(
                db,
                current_user.id,
                f"SERVICE_REQUEST_{service.upper()}",
                service,
                ip_address=request.client.host,
                user_agent=request.headers.get("User-Agent"),
                request_path=request.url.path,
                request_method=request.method,
                status_code=response.status_code
            )
            
            # Renvoyer la réponse du service
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        except httpx.RequestError as exc:
            logging.error(f"Erreur lors de la requête au service {service}: {exc}")
            
            # Journaliser l'erreur
            log_audit(
                db,
                current_user.id,
                f"SERVICE_ERROR_{service.upper()}",
                service,
                ip_address=request.client.host,
                user_agent=request.headers.get("User-Agent"),
                request_path=request.url.path,
                request_method=request.method,
                status_code=503,
                details={"error": str(exc)}
            )
            
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Service {service} indisponible"
            )




# ============= Routes de surveillance et de santé =============
@app.get("/health")
async def health_check():
    """Endpoint de vérification de santé"""
    # Vérifier la base de données
    db_status = True
    try:
        db = config.SessionLocal()
        db.execute("SELECT 1")
        db.close()
    except SQLAlchemyError:
        db_status = False
    
    # Vérifier Redis
    redis_status = True
    try:
        config.redis_client.ping()
    except:
        redis_status = False
    
    # Vérifier tous les services
    service_status = {}
    async with httpx.AsyncClient(timeout=2.0) as client:
        for service_name, service_url in config.SERVICE_REGISTRY.items():
            try:
                response = await client.get(f"{service_url}/health")
                service_status[service_name] = response.status_code == 200
            except:
                service_status[service_name] = False
    
    # Statut global
    all_ok = db_status and redis_status and all(service_status.values())
    
    status_data = {
        "status": "healthy" if all_ok else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": service_status,
        "dependencies": {
            "database": db_status,
            "redis": redis_status
        }
    }
    
    status_code = status.HTTP_200_OK if all_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(content=status_data, status_code=status_code)

@app.get("/metrics")
async def metrics(
    current_user: UserModel = Depends(has_role(["admin"])),
    db: Session = Depends(get_db)
):
    """Endpoint de métriques pour la surveillance (admin uniquement)"""
    # Nombre d'utilisateurs actifs
    active_users_count = db.query(sa.func.count(UserModel.id)).filter(UserModel.disabled == False).scalar()
    
    # Nombre de tokens actifs
    active_tokens_count = db.query(sa.func.count(RefreshTokenModel.id)).filter(
        RefreshTokenModel.revoked == False,
        RefreshTokenModel.expires_at > datetime.utcnow()
    ).scalar()
    
    # Top 5 des services les plus utilisés (dernières 24h)
    one_day_ago = datetime.utcnow() - timedelta(days=1)
    service_usage = db.query(
        AuditLogModel.resource,
        sa.func.count(AuditLogModel.id).label("count")
    ).filter(
        AuditLogModel.timestamp > one_day_ago,
        AuditLogModel.resource.in_(config.SERVICE_REGISTRY.keys())
    ).group_by(
        AuditLogModel.resource
    ).order_by(
        sa.desc("count")
    ).limit(5).all()
    
    # Nombre d'authentifications réussies (dernières 24h)
    successful_logins = db.query(sa.func.count(AuditLogModel.id)).filter(
        AuditLogModel.action == "SUCCESSFUL_LOGIN",
        AuditLogModel.timestamp > one_day_ago
    ).scalar()
    
    # Nombre d'authentifications échouées (dernières 24h)
    failed_logins = db.query(sa.func.count(AuditLogModel.id)).filter(
        AuditLogModel.action == "FAILED_LOGIN",
        AuditLogModel.timestamp > one_day_ago
    ).scalar()
    
    # Construire l'objet de métriques
    metrics_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "system": {
            "active_users": active_users_count,
            "active_tokens": active_tokens_count
        },
        "authentication": {
            "successful_logins_24h": successful_logins,
            "failed_logins_24h": failed_logins
        },
        "service_usage_24h": [
            {"service": item.resource, "count": item.count}
            for item in service_usage
        ]
    }
    
    return metrics_data

@app.get("/")
async def root():
    """Page d'accueil de l'API Gateway"""
    return {
        "message": "API Gateway sécurisée opérationnelle",
        "version": "1.0.0",
        "documentation": "/documentation"
    }
