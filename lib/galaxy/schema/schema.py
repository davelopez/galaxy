from datetime import datetime

from pydantic import (
    BaseModel,
    Field,
)


class UserModel(BaseModel):
    """User in a transaction context."""
    id: int = Field(title='ID', description='User ID')
    username: str = Field(title='Username', description='User username')
    email: str = Field(title='Email', description='User email')
    active: bool = Field(title='Active', description='User is active')
    deleted: bool = Field(title='Deleted', description='User is deleted')
    last_password_change: datetime = Field(title='Last password change', description='')
    model_class: str = Field(title='Model class', description='Database model class (User)')
