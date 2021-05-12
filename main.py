import re
import hashlib
import uuid #Moving to replace with bcrypt
import bcrypt

def passwordChecker(password):
    #check the password length
    if len(password) < 8:
        return False

    #checks for lower
    lowerCheck = re.compile(r'[a-z]')
    if not(lowerCheck.search(password)):
        return False

    #checks for upper
    upperCheck = re.compile(r'[A-Z]')
    if not(upperCheck.search(password)):
        return False

    #checks for number
    numCheck = re.compile(r'\d')
    if not(numCheck.search(password)):
        return False

    #checks for special character
    spCheck = re.compile(r'\W')
    if not(spCheck.search(password)):
        return False

    else:
        return True

def generateSalt():
    salt = bcrypt.gensalt()
    return salt

def saltByteToString(salt):
    stringSalt = salt.decode("utf-8")
    return stringSalt

def passHash(password):
    hashed_password = hashlib.sha512(password.encode())
    return hashed_password

def previousPasswordExists(hashed_password):
    list = open("previous_password.txt").readlines()

    if hashed_password in list:
        return True
    else:
        return False

def addPasswordToLog(hashed_password):
    with open("previous_password.txt", "a") as prev:
        #prevLen = len(prev)
        if prevLen < 8 or (prevLen == ""):
            prev.write(user + ":" + hashed_password + "::0:90:7:::" + saltByteToString(salt) + "\n")

if __name__ == '__main__':
    user = input("Enter you user name: ")
    password = input("Enter your password: ")
    if passwordChecker(password) is True:
        print("That is a strong password.")
        passHash(password)
    else:
        print("That is a weak password.")

    #salt = uuid.uuid4().hex #Suggested to not use, while unique, they aren't random
    #salt = "^AN:~fGRGX?t,/4s" #Static debug Salt
    salt = generateSalt()

    hashed_password = hashlib.sha512(password.encode() + salt).hexdigest()

    with open("shadow.txt", "a") as shadow:
    #shadow.write(user + ":" + passHash(password).hexdigest() + "::0:90:7:::")
        shadow.write(user + ":" + hashed_password + "::0:90:7:::" + saltByteToString(salt) + "\n")

    if (previousPasswordExists(hashed_password)):
        print("Could not add to password log.")
    else:
        addPasswordToLog(hashed_password)
        print("Added to file")
        

