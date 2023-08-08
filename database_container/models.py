from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin
from dotenv import load_dotenv
import os
import hashlib

load_dotenv()

Base = declarative_base()

class Users(Base, UserMixin):
    __tablename__ = "users"

    id = Column("id", Integer, primary_key=True, autoincrement=True)
    username = Column("firstName", String, unique=True)
    password = Column("password", String)
    role = Column("role", String)  # Admin, CompanyOwner, CompanyUser, Banned
    email = Column("email", String, unique=True)
    company = Column("company", String)

    def __init__(self, username, password, role, email, company):
        self.username = username
        self.password = password
        self.role = role
        self.email = email
        self.company = company

    def __repr__(self):
        return f"{self.id} | {self.username} | {self.password} | {self.role} | {self.email} | {self.company}"