import os
import secrets
import uvicorn
from app.core.config import AUTH_HOST, AUTH_PORT, SSL_ENABLED, SSL_CERT, SSL_KEY, LOG_LEVEL
from app.main import app

# This file is now just a shim to run the app
if __name__ == "__main__":
    
    # Check if SSL files exist
    if SSL_ENABLED and (not os.path.exists(SSL_CERT) or not os.path.exists(SSL_KEY)):
        print(f"WARNING: SSL cert/key not found at {SSL_CERT}/{SSL_KEY}")
    
    # Run server
    uvicorn.run(
        "app.main:app",
        host=AUTH_HOST,
        port=AUTH_PORT,
        ssl_keyfile=SSL_KEY if (SSL_ENABLED and os.path.exists(SSL_KEY)) else None,
        ssl_certfile=SSL_CERT if (SSL_ENABLED and os.path.exists(SSL_CERT)) else None,
        log_level=LOG_LEVEL.lower(),
        reload=False
    )
