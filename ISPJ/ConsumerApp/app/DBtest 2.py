from DBcreateTables import User
from database import dbSession
from config import Config


def checkData():
    userID = "T0110907Z"
    user = dbSession.query(User).filter(User.uid == userID).first()
    if user:
        print("Hello")    
    
    
    dbSession.close()


def main():
    print(Config.SECRET_KEY)
    

main()