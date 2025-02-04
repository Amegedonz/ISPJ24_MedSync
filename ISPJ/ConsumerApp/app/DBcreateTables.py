from sqlalchemy import Table, Column, Integer, String, Boolean, ForeignKey, Float, DateTime, text
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func
from database import engine, Base
import datetime


Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = 'users'

    uid = Column(String(9), primary_key=True, unique=True)
    username = Column(String(50), nullable=False)
    password = Column(String(255), nullable=False)
    email = Column(String(100), unique=True)
    phoneNumber = Column(Integer(), unique=True)
    role = Column(String(50), nullable=False, default="Patient")

    doctor_profile = relationship("Doctor", back_populates="user", uselist=False)

    def __repr__(self):
        return f"<User(uid = {self.uid}, username = {self.username})"
    
class Doctor(Base):
    __tablename__ = 'doctors'

    uid = Column(String(9), ForeignKey('users.uid'), unique= True, nullable=False )
    license_number = Column(String(7), unique=True, nullable=False, primary_key=True)
    specialisation = Column(String(50), nullable=False)
    facility = Column(String(50))

    user = relationship("User", back_populates="doctor_profile")

class PatientAssignment(Base):
    __tablename__ = 'doctor_patient_assignment'

    doctor_id = Column(String(7), ForeignKey('doctors.license_number'), primary_key=True)
    patient_id = Column(String(9), ForeignKey('users.uid'), primary_key=True)
    assignmentDateTime = Column(DateTime(timezone=True), onupdate=func.now())
    assignedBy = Column(String(50), nullable=False)

class PatientRecords(Base):
    __tablename__ = 'patient_records'

    record_id = Column(Integer, primary_key=True)
    patient_id = Column(String(9), ForeignKey('users.uid'))
    record_data = Column(String(255))
    record_time = Column(DateTime(timezone=True), onupdate=func.now())
    attending = Column(String(7), ForeignKey('doctors.license_number'))

def addValues():
    newUser = User(uid = 'T0110907Z', username = 'LucianHo', password = 'P@ssw0rd')
    session.add(newUser)
    session.commit()

def createTables():
    try:
        Base.metadata.create_all(engine)
        print("Tables created successfully!")


    except exec.SQLAlchemyError as e:
        print(f"Database connection failed: {e}")

    session.close()

def testConn():
    try:
        users = session.query(User).all()
        for user in users:
            print(user)

    except exec.SQLalchemy as e:
        print(f"SQLalchemy error: {e}")
    

def main():
    createTables()
    



main()