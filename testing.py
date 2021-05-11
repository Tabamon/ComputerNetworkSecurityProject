import hashlib

def checkIfSame(hashedPassword, attempt):
    hashedAttempt = hashlib.sha512(attempt.encode())
    if hashedAttempt == hashedPassword:
        return True
    else:
        return False