from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Boolean, ForeignKey, Float, DateTime, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import CreateSchema
from sqlalchemy.orm import relationship, sessionmaker
from flask_login import UserMixin
from sqlalchemy.engine import URL
from datetime import datetime as dt
import pyotp, bcrypt

#Database Connection things
url_object = URL.create(
    "mysql+pymysql",
    username="root",
    password="awsPassword123fk",
    host="ispj-db.cxruucec3o8o.us-east-1.rds.amazonaws.com",
    database="ISPJ_DB",
)

#engine creation
engine = create_engine(url_object)
metadata = MetaData(schema="ISPJ_DB")
with engine.connect() as conn:
    if not conn.dialect.has_schema(conn, "ISPJ_DB"): 
        conn.execute(CreateSchema("ISPJ_DB"))


Base = declarative_base(metadata=metadata)


Session = sessionmaker(bind=engine)
dbSession = Session()
