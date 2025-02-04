from sqlalchemy import Table, Column, Integer, String, Boolean, ForeignKey, Float, DateTime, text
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func
from database import engine, Base, dbSession
from flask_login import UserMixin

class User(Base, UserMixin):
    __tablename__ = 'users'

    id = Column(String(9), primary_key=True, unique=True)
    username = Column(String(50), nullable=False)
    password = Column(String(255), nullable=False)
    email = Column(String(100), unique=True)
    phoneNumber = Column(Integer(), unique=True)
    role = Column(String(50), nullable=False, default="Patient")

    doctor_profile = relationship("Doctor", back_populates="user", uselist=False)
    doctors = relationship("PatientAssignment", back_populates="patient")

    def __repr__(self):
        return f"<User(id = {self.id}, username = {self.username})>"

    def add_doctor(self, license_number, specialisation, facility):
        # Create the associated doctor profile
        doctor = Doctor(
            id=self.id,  # Link the doctor to this user
            license_number=license_number,
            specialisation=specialisation,
            facility=facility
        )
        self.doctor_profile = doctor  # Establish the relationship
        self.role = "Doctor"  
        return doctor
    
class Doctor(Base):
    __tablename__ = 'doctors'

    license_number = Column(String(7), primary_key=True, unique=True)
    id = Column(String(9), ForeignKey('users.id'), nullable=False) 
    specialisation = Column(String(50), nullable=False)
    facility = Column(String(50))

    user = relationship("User", back_populates="doctor_profile")
    patients = relationship("PatientAssignment", back_populates="doctor")

    def __repr__(self):
        return f"<Doctor(license_number={self.license_number}, specialisation={self.specialisation})>"

class PatientAssignment(Base):
    __tablename__ = 'doctor_patient_assignment'

    doctor_id = Column(String(7), ForeignKey('doctors.license_number'), primary_key=True)
    patient_id = Column(String(9), ForeignKey('users.id'), primary_key=True)
    doctor = relationship("Doctor", back_populates="patients")
    patient = relationship("User", back_populates="doctors")

class PatientRecords(Base):
    __tablename__ = 'patient_records'

    record_id = Column(Integer, primary_key=True)
    patient_id = Column(String(9), ForeignKey('users.id'))
    record_data = Column(String(255))
    record_time = Column(DateTime(timezone=True), onupdate=func.now())
    attending = Column(String(7), ForeignKey('doctors.license_number'))

def addValues():
    newUser = User(id = 'T0110907Z', username = 'LucianHo', password = 'P@ssw0rd')
    dbSession.add(newUser)
    dbSession.commit()

def createTables():
    try:
        Base.metadata.create_all(engine)
        dbSession.commit()
        print("Tables created successfully!")


    except exec.SQLAlchemyError as e:
        print(f"Database connection failed: {e}")

    finally:
        dbSession.close()

def deleteTables():
    Base.metadata.drop_all(engine)
    dbSession.commit()
    dbSession.close()

def clearTableData():
    dbSession.query(User).delete()
    print("Contents deleted!")
    dbSession.commit()
    dbSession.close()

def testConn():
    try:
        users = dbSession.query(User).all()
        for user in users:
            print(user)

    except exec.SQLalchemy as e:
        print(f"SQLalchemy error: {e}")
    

def main():
    ...
    
main()