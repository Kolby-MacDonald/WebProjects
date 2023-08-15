from sqlalchemy import create_engine, Column, String, Integer, LargeBinary
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin
from dotenv import load_dotenv
import os
load_dotenv()

Base = declarative_base()

# Website Users
class Users(Base, UserMixin):
    __tablename__ = "users"

    id = Column("id", Integer, primary_key=True, autoincrement=True)            # User ID
    username = Column("firstName", String, unique=True)                         # Unique Usernames
    password = Column("password", String)                                       # Password (SHA3_512) - Will be salted
    role = Column("role", String)                                               # User Role: Admin, User, Banned
    email = Column("email", String, unique=True)                                # Unique Email - Two Faq Eventually

    def __init__(self, username, password, role, email, company):
        self.username = username
        self.password = password
        self.role = role
        self.email = email

    def __repr__(self):
        return f"{self.id} | {self.username} | {self.password} | {self.role} | {self.email}"

# Blog Post's 
class BlogPosts(Base):
    __tablename__ = "blog_posts"
    
    id = Column("id", Integer, primary_key=True, autoincrement=True)            # Post ID
    title = Column("title", String)                                             # Post Title
    content = Column("content", String)                                         # Post Body Content
    header_image = Column("header_image", String)                               # Post Header Image

    def __init__(self, title, content, header_image):
        self.title = title
        self.content = content
        self.header_image = header_image

# Remote Access Database Controller [ AVAILDATA ] - Contact developer for more information.
class AvailAccess(Base):
    __tablename__ = "a000_users_table"                                          # Standard Access Table Name

    id = Column(Integer, primary_key=True, autoincrement=True)                  # Test Account ID
    username = Column(String, unique=True)                                      # Unique Username
    password = Column(String)                                                   # SHA256 Password
    role = Column(String, default="signed_up")                                  # User Role: Admin, User
    write_access = Column(String)                                               # What tables can you write to.
    read_access = Column(String)                                                # What tables can you read.
    create_tables = Column(String, default="no")                                # Can you create tables.
    employee_name = Column(String)                                              # Required Column - Don't use.
    job_title = Column(String)                                                  # Required Column - Don't use.
    email = Column(String, unique=True)                                         # Unique Email