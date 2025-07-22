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
    allow_origins=["http://localhost:5173"],  # Add your frontend's local URL here
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

# Custom docs endpoints
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Serves the custom Swagger UI documentation."""
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="API Docs",
        # Using specific versions of Swagger UI assets
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css",
    )

@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_json():
    """Generates and serves the OpenAPI schema (Swagger JSON)."""
    # Manually define the schema structure.
    # This should ideally match the Pydantic models used in your application.
    # We are adding the new /api/stellar/student/send_xlm endpoint and its schema.

    schema: Dict[str, Any] = {
        "openapi": "3.0.2",
        "info": {
            "title": "Decentralized Funding API",
            "version": "1.0.0",
            "description": "API for decentralized crowdfunding platform"
        },
        "paths": {
            # --- Existing Paths (Examples - adjust based on your actual router definitions) ---
            "/api/auth/register": {
                "post": {
                    "summary": "Sign Up",
                    "operationId": "signup",
                    "tags": ["auth"],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UserBase"} # Assuming UserBase is the signup request model
                            }
                        },
                        "required": True
                    },
                    "responses": {
                        "200": { # Changed from 201 to 200 based on common API patterns, adjust if needed
                            "description": "User created successfully. Stellar account generated.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "email": {"type": "string", "format": "email"},
                                            "username": {"type": "string"},
                                            "stellar_public_key": {"type": "string"},
                                            "message": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Bad Request - Email already registered or failed key generation/funding"
                        },
                         "500": {
                            "description": "Internal Server Error - Failed to generate Stellar account or save user"
                        }
                    }
                }
            },
            "/api/auth/login": {
                 "post": {
                    "summary": "Login",
                    "operationId": "login",
                    "tags": ["auth"],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LoginRequest"}
                            }
                        },
                        "required": True
                    },
                    "responses": {
                        "200": {
                            "description": "Successfully logged in",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/TokenResponse"}
                                }
                            }
                        },
                        "401": {
                            "description": "Invalid credentials"
                        }
                    }
                }
            },
             "/api/auth/me": {
                "get": {
                    "summary": "Get Current User Details",
                    "operationId": "read_users_me",
                    "tags": ["auth"],
                    "security": [{"bearerAuth": []}], # Indicate this endpoint requires authentication
                    "responses": {
                        "200": {
                            "description": "Current User Details",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorized"
                        }
                    }
                }
            },
            # Add other existing paths from user_router, project_router, donation_router here following the same structure
            # Example for a GET /api/users endpoint:
            "/api/users/me": { # Assuming user_router has a /me endpoint for user details
                 "get": {
                    "summary": "Get Authenticated User Details",
                    "operationId": "get_authenticated_user",
                    "tags": ["users"],
                    "security": [{"bearerAuth": []}], # Requires authentication
                    "responses": {
                        "200": {
                            "description": "Authenticated User Details",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorized"
                        }
                    }
                }
            },
             "/api/projects": {
                "get": {
                    "summary": "List Projects",
                    "operationId": "list_projects",
                    "tags": ["projects"],
                    "responses": {
                        "200": {
                            "description": "Successful Response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/Project"}
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create Project",
                    "operationId": "create_project",
                    "tags": ["projects"],
                    "security": [{"bearerAuth": []}], # Requires authentication (likely student role)
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ProjectBase"}
                            }
                        },
                        "required": True
                    },
                    "responses": {
                        "200": {
                            "description": "Successful Response",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Project"}
                                }
                            }
                        },
                         "401": {"description": "Unauthorized"},
                         "403": {"description": "Forbidden (e.g., not a student)"}
                    }
                }
            },
            # Add paths for GET, PUT, DELETE /api/projects/{project_id} similarly...
            # Add paths for /api/donations similarly...


            # --- New Stellar Transaction Path ---
"/student/send_xlm": {
  "post": {
    "summary": "Send XLM from student account",
    "operationId": "studentSendXlm",
    "tags": ["student"],
    "requestBody": {
      "required": True,
      "content": {
        "application/json": {
          "schema": {
            "type": "object",
            "properties": {
              "destination_public_key": {
                "type": "string",
                "description": "Stellar public key of the recipient"
              },
              "amount": {
                "type": "number",
                "format": "float",
                "description": "Amount of XLM to send"
              },
            "memo_text": {
              "type": "string",
              "nullable": True,
              "description": "Optional memo for the transaction"
              }
            },
            "required": ["destination_public_key", "amount"]
          }
        }
      }
    },
    "responses": {
      "200": {
        "description": "Transaction submitted successfully",
        "content": {
          "application/json": {
            "schema": {
              "type": "object",
              "properties": {
                "message": { "type": "string" },
                "transaction_hash": { "type": "string" }
              }
            }
          }
        }
      },
      "400": {
        "description": "Bad Request - Missing or invalid Stellar secret key or transaction failed"
      },
      "403": {
        "description": "Forbidden - Only students can access this route"
      },
      "500": {
        "description": "Internal Server Error - Could not decrypt key or send transaction"
      }
    }
  }
},

            "/student/balance": {
  "get": {
    "summary": "Get Student Stellar Balance",
    "operationId": "getStudentBalance",
    "tags": ["student"],
    "security": [
      {
        "bearerAuth": []
      }
    ],
    "responses": {
      "200": {
        "description": "Successfully retrieved the student's Stellar account balances.",
        "content": {
          "application/json": {
            "schema": {
              "type": "object",
              "properties": {
                "public_key": {
                  "type": "string",
                  "description": "Stellar public key associated with the student"
                },
                "balances": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "asset_type": { "type": "string" },
                      "asset_code": { "type": "string" },
                      "balance": { "type": "string" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "400": {
        "description": "Bad Request - No Stellar public key associated with the student account."
      },
      "403": {
        "description": "Forbidden - Only students are allowed to access this route."
      },
    }
            # --- End New Stellar Transaction Path ---
        },
        "components": {
            "schemas": {
                # --- Existing Schemas (Refined) ---
                "UserRole": {
                    "type": "string",
                    "enum": ["admin", "donor", "student"]
                },
                 "StudentProfile": {
                    "type": "object",
                    "properties": {
                         "institution": {"type": "string"},
                         "student_id": {"type": "string"},
                         "field_of_study": {"type": "string"},
                         "year_of_study": {"type": "integer"},
                         "is_verified": {"type": "boolean"}
                    },
                    "required": ["institution", "student_id", "field_of_study", "year_of_study"]
                 },
                "DonorProfile": {
                    "type": "object",
                    "properties": {
                         "organization": {"type": "string", "nullable": True},
                         "preferred_categories": {"type": "array", "items": {"type": "string"}},
                         "donation_history": {"type": "array", "items": {"type": "string"}}, # Assuming ObjectIds stored as strings
                         "total_donated": {"type": "number"}
                    }
                },
                "UserBase": { # Used for signup request
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "password": {"type": "string", "format": "password"},
                        "username": {"type": "string"},
                        "full_name": {"type": "string", "nullable": True},
                        # wallet_address and role are not provided by user at signup in the new flow
                        # "wallet_address": {"type": "string", "nullable": True},
                        # "role": {"$ref": "#/components/schemas/UserRole"}
                    },
                    "required": ["email", "password", "username"]
                },
                "User": { # Represents the User model stored in DB and returned in responses (excluding password_hash and encrypted key)
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "MongoDB ObjectId"},
                        "email": {"type": "string", "format": "email"},
                        "username": {"type": "string"},
                        "full_name": {"type": "string", "nullable": True},
                        "stellar_public_key": {"type": "string", "nullable": True, "description": "Stellar Public Key (Wallet Address)"}, # Added public key
                        # stellar_secret_key_encrypted is NOT included in the response schema for security
                        "role": {"$ref": "#/components/schemas/UserRole"},
                        "projects_created": {"type": "array", "items": {"type": "string"}, "description": "List of Project ObjectIds created by the user (if student)"},
                        "donations_made": {"type": "array", "items": {"type": "string"}, "description": "List of Transaction ObjectIds made by the user (if donor)"},
                        "student_profile": {"$ref": "#/components/schemas/StudentProfile", "nullable": True},
                        "donor_profile": {"$ref": "#/components/schemas/DonorProfile", "nullable": True},
                        "created_at": {"type": "string", "format": "date-time"},
                        "updated_at": {"type": "string", "format": "date-time"}
                    },
                    "required": ["email", "username", "role"]
                },
                 # Add UserCreate and UserUpdate schemas if your user_router uses them
                 # Example UserCreate (similar to UserBase but might include role if admin creates users)
                "UserCreate": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "username": {"type": "string"},
                        "password": {"type": "string", "format": "password"},
                        "full_name": {"type": "string", "nullable": True},
                        "role": {"$ref": "#/components/schemas/UserRole"}
                    },
                    "required": ["email", "username", "password", "role"]
                },
                "UserUpdate": { # Schema for updating user details
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "username": {"type": "string"},
                        "full_name": {"type": "string", "nullable": True},
                         # Allow updating public key? Or is it set once at signup?
                         # "stellar_public_key": {"type": "string", "nullable": True}
                    }
                     # No required fields for update, as all are optional
                },
                "ProjectStatus": {
                    "type": "string",
                    "enum": ["pending", "active", "completed", "cancelled"]
                },
                "ProjectBase": { # Used for project creation request
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "objectives": {"type": "string"},
                        "deliverables": {"type": "string"},
                        "category": {"type": "string"},
                        "target_amount": {"type": "number"},
                        # wallet_address is now on the User model, not Project
                        # "wallet_address": {"type": "string"},
                        "deadline": {"type": "string", "format": "date-time"}
                    },
                    "required": ["title", "description", "objectives", "deliverables", "category", "target_amount", "deadline"]
                },
                "Project": { # Represents the Project model stored in DB and returned in responses
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "MongoDB ObjectId"},
                        "creator_id": {"type": "string", "description": "ObjectId of the User (student) who created the project"}, # Link to User
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "objectives": {"type": "string"},
                        "deliverables": {"type": "string"},
                        "category": {"type": "string"},
                        "target_amount": {"type": "number"},
                        "current_amount": {"type": "number"},
                        "status": {"$ref": "#/components/schemas/ProjectStatus"},
                        "media_urls": {"type": "array", "items": {"type": "string"}},
                        "donors": {"type": "array", "items": {"type": "string"}, "description": "List of User ObjectIds who donated directly"}, # Link to Users
                        "created_at": {"type": "string", "format": "date-time"},
                        "updated_at": {"type": "string", "format": "date-time"}
                    },
                    "required": ["creator_id", "title", "description", "objectives", "deliverables", "category", "target_amount", "deadline"]
                },
                 # Add ProjectUpdate schema if your project_router uses it
                 "ProjectUpdate": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "objectives": {"type": "string"},
                        "deliverables": {"type": "string"},
                        "category": {"type": "string"},
                        "target_amount": {"type": "number"},
                        "status": {"$ref": "#/components/schemas/ProjectStatus"},
                        "media_urls": {"type": "array", "items": {"type": "string"}}
                    }
                 },
                "TransactionBase": { # Used for transaction creation request (if any)
                    "type": "object",
                    "properties": {
                        "amount": {"type": "number"},
                        "transaction_hash": {"type": "string"},
                        "message": {"type": "string", "nullable": True},
                        "asset_type": {"type": "string"},
                         # "asset_issuer": {"type": "string", "nullable": True} # Add if using non-XLM
                    },
                     "required": ["amount", "transaction_hash", "asset_type"]
                },
                "Transaction": { # Represents the Transaction model stored in DB and returned in responses
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "MongoDB ObjectId"},
                        "amount": {"type": "number"},
                        "transaction_hash": {"type": "string", "description": "Stellar transaction hash"},
                        "message": {"type": "string", "nullable": True, "description": "Stellar transaction memo"},
                        "asset_type": {"type": "string"},
                        # "asset_issuer": {"type": "string", "nullable": True}, # Add if using non-XLM
                        "donor_id": {"type": "string", "nullable": True, "description": "ObjectId of the Donor User (if direct donation)"}, # Link to User
                        "project_id": {"type": "string", "nullable": True, "description": "ObjectId of the Project being funded"}, # Link to Project
                        "source_account_id": {"type": "string", "description": "Stellar public key of the sender"},
                        "destination_account_id": {"type": "string", "description": "Stellar public key of the receiver"},
                        "status": {"type": "string", "description": "Transaction status (e.g., successful, failed)"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "block_height": {"type": "integer", "nullable": True},
                        "confirmed_at": {"type": "string", "format": "date-time", "nullable": True}
                    },
                    "required": ["amount", "transaction_hash", "asset_type", "source_account_id", "destination_account_id", "status"]
                },
                 # Add TransactionUpdate schema if your donation_router uses it
                 "TransactionUpdate": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "block_height": {"type": "integer", "nullable": True},
                        "confirmed_at": {"type": "string", "format": "date-time", "nullable": True}
                    }
                 },
                 "LoginRequest": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "password": {"type": "string", "format": "password"}
                    },
                    "required": ["email", "password"]
                },
                "TokenResponse": { # Response after successful login
                    "type": "object",
                    "properties": {
                        "access_token": {"type": "string"},
                        "token_type": {"type": "string"},
                         "stellar_public_key": {"type": "string", "nullable": True, "description": "Stellar Public Key of the logged-in user"} # Include public key in login response
                    },
                    "required": ["access_token", "token_type"]
                },
                # --- New Schemas for Stellar Endpoint ---
                "SendXlmRequest": {
                    "type": "object",
                    "properties": {
                        "destination_public_key": {"type": "string", "description": "Stellar public key of the recipient account."},
                        "amount": {"type": "number", "description": "Amount of XLM to send."},
                        "memo_text": {"type": "string", "nullable": True, "description": "Optional memo for the transaction (max 28 bytes for text memo)."}
                    },
                    "required": ["destination_public_key", "amount"]
                },
                "SendXlmResponse": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string"},
                        "transaction_hash": {"type": "string", "description": "Hash of the submitted Stellar transaction."}
                    },
                    "required": ["message", "transaction_hash"]
                },
                 "ErrorResponse": { # Generic schema for error details
                     "type": "object",
                     "properties": {
                         "detail": {"type": "string"},
                         # Add other potential error fields like Stellar result codes if exposed
                         "headers": { # Example for WWW-Authenticate header in 401
                             "type": "object",
                             "additionalProperties": {"type": "string"}
                         }
                     }
                 }
                # --- End New Schemas ---
            },
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "Enter your JWT token in the format 'Bearer YOUR_TOKEN'"
                }
            }
        }
    }
        }
    }

    # Manually add schemas from your Pydantic models if you want OpenAPI to generate them
    # You would typically use app.openapi() to get the base schema and then modify it.
    # Since we disabled default OpenAPI, we build it manually here.
    # For a large app, you'd let FastAPI generate most of this.

    # Example of how you *would* add schemas if you had Pydantic models defined directly in this file
    # from pydantic import BaseModel
    # class MyModel(BaseModel): pass
    # from fastapi.utils import generate_operation_id_for_path
    # app.add_api_route("/my_path", my_endpoint, methods=["GET"], response_model=MyModel)
    # This manual schema generation is complex for a full app.
    # The current manual schema is based on the expected structure from your models.

    return JSONResponse(content=schema)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy"}

# You can add more endpoints here or in separate router files
