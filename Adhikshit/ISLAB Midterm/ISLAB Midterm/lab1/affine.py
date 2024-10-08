import math

def encrypt(pt,k1,k2):
    pt=pt.replace(" ","").lower()
    if k1==13 or k1%2==0:
        print("Invalid choice for K1 try again\n")
        exit()
    ct=""
    for char in pt:
        c=(((ord(char)-ord('a'))*k1)+k2)%26
        ct+=chr(c+ord('a'))
    return ct

def decrypt(ct,k1,k2):
    kin=pow(k1,-1,26)
    pt=""
    for char in ct:
        p=(((ord(char)-ord('a'))-k2)*kin)%26
        pt+=chr(p+ord('a'))

    return pt

msg=input("Enter the Message\n")
k1=int(input("enter k1\n"))
k2=int(input("enter k2\n"))

ct=encrypt(msg,k1,k2)
print(f"The Ciphertext is : {ct}\n")

pt=decrypt(ct,k1,k2)
print(f"The Plaintext is: {pt}\n")
