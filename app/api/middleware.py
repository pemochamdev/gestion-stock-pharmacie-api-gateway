from api.deps import app
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request, status
from fastapi.responses import JSONResponse
import os
import uuid
import logging
import time
from core import config


# ============= Middleware de sécurité =============
# CORS strictement contrôlé
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("ALLOWED_ORIGINS", "").split(",")],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Device-ID"],
    expose_headers=["X-Request-ID"],
    max_age=86400,  # 24 heures
)

# Middleware pour la journalisation et le suivi
@app.middleware("http")
async def logging_and_tracking_middleware(request: Request, call_next):
    # Générer un ID de requête unique
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Ajouter l'ID de requête aux headers
    request.state.request_id = request_id
    
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Ajouter l'ID de requête à la réponse
        response.headers["X-Request-ID"] = request_id
        
        # Journaliser les informations de la requête
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("User-Agent", "unknown")
        
        logging.info(
            f"RequestID: {request_id} | Method: {request.method} | "
            f"Path: {request.url.path} | IP: {client_ip} | "
            f"Status: {response.status_code} | Time: {process_time:.4f}s"
        )
        
        return response
    except Exception as e:
        # Journaliser l'erreur
        logging.error(
            f"RequestID: {request_id} | Error: {str(e)}"
        )
        raise

# Middleware pour le rate limiting
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Obtenir l'adresse IP du client et le chemin
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    
    # Ignorer les health checks pour le rate limiting
    if path == "/health":
        return await call_next(request)
    
    # Clés Redis pour le tracking des limites
    minute_key = f"ratelimit:{client_ip}:{path}:minute"
    hour_key = f"ratelimit:{client_ip}:global:hour"
    
    # Vérifier et incrémenter les compteurs
    minute_count = config.redis_client.incr(minute_key)
    if minute_count == 1:
        config.redis_client.expire(minute_key, 60)  # Expire après 60 secondes
    
    hour_count = config.redis_client.incr(hour_key)
    if hour_count == 1:
        config.redis_client.expire(hour_key, 3600)  # Expire après 1 heure
    
    # Vérifier les limites
    if minute_count > config.RATE_LIMIT_PER_MINUTE:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded. Try again in a minute."}
        )
    
    if hour_count > config.RATE_LIMIT_PER_HOUR:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Hourly rate limit exceeded. Try again later."}
        )
    
    return await call_next(request)

# Middleware de sécurité HTTP
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    
    # Ajouter des en-têtes de sécurité
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    
    return response
