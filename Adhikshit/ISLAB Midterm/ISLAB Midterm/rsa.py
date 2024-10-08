def isprime(n):
    for i in range(2,int(n**0.5)+1):
        if n%i==0:
            return 0
    return 1

def encrypt(pt,e,n):
    ct=pow(pt,e,n)
    return ct

def decrypt(ct,e,n,tot):
    d=-1
    for i in range(2,tot):
        if e*i % tot == 1:
            d=i
            break

    pt=pow(ct,d,n)
    return pt


def main():
    p=int(input("Enter the value of p: "))
    q=int(input("Enter the value of q: "))
    n=p*q
    tot=-1
    if isprime(p) == 1 and isprime(q) == 1 :
        tot=(p-1)*(q-1)
    else :
        tot=n-1

    e=-1

    for i in range(2,tot):
        if isprime(i)==1:
            if tot%i!=0:
                e=i
                break

    pt=(input("Enter the Plaintext: "))
    ct=[]
    print("Encryption\n")
    for i in pt:
        ct.append(encrypt(ord(i),e,n))
    print(f"The ciphertext is: {ct}\n")

    print("Decryption\n")
    pt2=[]
    for i in ct:
        pt2.append(decrypt(i,e,n,tot))
    print(f"The plaintext is {pt2}\n")


if __name__=="__main__":
    main()





