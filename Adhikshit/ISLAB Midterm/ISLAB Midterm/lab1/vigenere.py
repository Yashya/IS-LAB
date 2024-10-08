import math

def encrypt(pt,k):
    i=0
    n=len(k)
    pt=pt.replace(" ","").lower()
    ct=""
    for char in pt:
        c=((ord(char)-ord('a'))+(ord(k[i])-ord('a')))%26
        ct+=chr(c+ord('a'))
        i=(i+1)%n
    return ct

def decrypt(ct,k):
    i = 0
    n = len(k)
    pt = ""
    for char in ct:
        c = ((ord(char) - ord('a')) - (ord(k[i])-ord('a'))) % 26
        pt += chr(c + ord('a'))
        i =(i+1) % n
    return pt

msg=input("Enter the Message\n")
k=input("enter key\n")

ct=encrypt(msg,k)
print(f"The Ciphertext is : {ct}\n")

pt=decrypt(ct,k)
print(f"The Plaintext is: {pt}\n")