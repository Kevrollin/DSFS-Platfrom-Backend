from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from app.core.database import Database
# Import all necessary routers
from app.routes import student_transactions # Assuming this is your new router file
from app.routes import user_routes # Assuming you have a user router
from app.routes import project_routes # Assuming you have a project router
from app.routes import donation_routes # Assuming you have a donation router
from app.routes import auth # Assuming this is your auth router

from typing import Dict, Any, List, Optional
from pydantic import BaseModel # Import BaseModel for defining schemas in OpenAPI manually

# Initialize FastAPI app without default OpenAPI docs
app = FastAPI(
    title="Decentralized Funding API",
    description="API for decentralized crowdfunding platform",
    version="1.0.0",
    docs_url="/docs",         # Enable Swagger UI at /docs
    redoc_url="/redoc",       # Enable ReDoc at /redoc
    openapi_url="/openapi.json"  # Enable OpenAPI schema
)

# Add CORS middleware
# Consider restricting allow_origins in production for better security
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://dsfs-platform.vercel.app",  # Your Vercel frontend
        "http://localhost:5173"              # For local development, if needed
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Database connection events
@app.on_event("startup")
async def startup_db_client():
    """Connects to the MongoDB database on application startup."""
    await Database.connect_to_mongo()
    print("Connected to MongoDB.") # Optional: Add logging

@app.on_event("shutdown")
async def shutdown_db_client():
    """Closes the MongoDB connection on application shutdown."""
    await Database.close_mongo_connection()
    print("Closed MongoDB connection.") # Optional: Add logging

# Include routers
# Ensure the router variables match your imported router files
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(user_routes.router, prefix="/api/users", tags=["users"]) # Assuming user_router is a module with a 'router' instance
app.include_router(project_routes.router, prefix="/api/projects", tags=["projects"]) # Assuming project_router is a module with a 'router' instance
app.include_router(donation_routes.router, prefix="/api/donations", tags=["donations"]) # Assuming donation_router is a module with a 'router' instance
app.include_router(student_transactions.router, prefix="/api/stellar", tags=["stellar"]) # Include the new stellar transactions router

# Health check endpoint
@app.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy"}

# You can add more endpoints here or in separate router files
