from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, URL, Insert, Result, Boolean, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import CreateSchema
from sqlalchemy.sql import select
from DBcreateTables import Customer, roles_users, Role
import pymysql, shelve


url_object = URL.create(
    "mysql+pymysql",
    username="root",
    password="mysqlpassword",
    host="localhost",
    database="customer",
)

engine = create_engine(url_object)
metadata = MetaData(schema="ASPJ_DB")
with engine.connect() as conn:
    if not conn.dialect.has_schema(conn, "ASPJ_DB"): 
        conn.execute(CreateSchema("ASPJ_DB"))
Base = declarative_base(metadata=metadata)
conn = engine.connect()
Session = sessionmaker(bind=engine)
dbSession = Session()
database = "aspj_db.Customer"

def populateData():
    new_user = Customer()

def deleteData(id):

    delete_user = dbSession.query(Customer).filter(Customer.phoneNumber == id).first()
    dbSession.delete(delete_user)
    dbSession.commit()
    dbSession.close()

def checkData():
    for role in dbSession.query(Role).all():
        print("Role:")
        print(role.roleName)
    
    for customer in dbSession.query(Customer).all():
        print("\nCustomer PhoneNum:")
        print(customer.phoneNumber)

    for user in dbSession.execute(select(roles_users)).fetchall():
        print("\nRole Users:")
        print(user.role_id)

    dbSession.close()


def main():
    checkData()
    

main()