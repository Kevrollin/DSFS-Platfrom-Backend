from fastapi import APIRouter, HTTPException
from ..models.models import Project
from ..schemas.schemas import ProjectCreate
from ..core.database import Database

router = APIRouter()

@router.post("/", response_model=Project)
async def create_project(project: ProjectCreate):
    db = Database.get_db()
    project_dict = project.dict()
    result = await db.projects.insert_one(project_dict)
    created_project = await db.projects.find_one({"_id": result.inserted_id})
    return created_project

@router.get("/{project_id}")
async def get_project(project_id: str):
    db = Database.get_db()
    if (project := await db.projects.find_one({"_id": project_id})) is not None:
        return project
    raise HTTPException(status_code=404, detail="Project not found")