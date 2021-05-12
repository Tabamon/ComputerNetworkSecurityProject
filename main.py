import re
import hashlib
import uuid

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

def passHash(password):
    hashed_password = hashlib.sha512(password.encode())
    return hashed_password

if __name__ == '__main__':
    user = input("Enter you user name: ")
    password = input("Enter your password: ")
    if passwordChecker(password) is True:
        print("That is a strong password.")
        passHash(password)
    else:
        print("That is a weak password.")

    #salt = uuid.uuid4().hex
    salt = "^AN:~fGRGX?t,/4s"
    hashed_password = hashlib.sha512(password.encode() + salt.encode()).hexdigest()

    with open("shadow.txt", "a") as shadow:
    #shadow.write(user + ":" + passHash(password).hexdigest() + "::0:90:7:::")
        shadow.write(user + ":" + hashed_password + "::0:90:7:::"+salt + "\n")

