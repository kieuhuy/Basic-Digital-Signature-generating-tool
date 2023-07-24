import base64
from hashlib import sha256
from Crypto import PublicKey
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tkinter import *
from Crypto.Signature import pkcs1_15
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256

def GenerateKey():

    private_key = RSA.generate(2048)
    public_key = private_key.publickey().export_key()

    print("\ n Generate public keys:"+public_key.decode('utf8'))
    print("\ n Generate private keys:"+private_key.export_key().decode('utf8'))

    publicKeyText.delete(0.0, END)
    publicKeyText.insert(END, public_key.decode('utf8'))
    
    privateKeyText.delete(0.0, END)
    privateKeyText.insert(END, private_key.export_key().decode('utf8'))


def EncryptionByPublickey():

    public_key_str = publicKeyText.get("0.0","end").encode(encoding="utf-8")
    public_key = RSA.import_key(public_key_str)
    msg = entryText.get("0.0", "end")           
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(msg.encode())
    
    print("The text after public key is encrypted is: " + base64.encodebytes(encrypted).decode('utf8'))
    outputText.delete(0.0, END)
    outputText.insert(END, base64.encodebytes(encrypted).decode('utf8'))
    
def DecryptionByPrivatekey():   

    private_key_str = privateKeyText.get("0.0","end").encode(encoding="utf-8")
    private_key = RSA.import_key(private_key_str)
    msg = entryText.get("0.0", "end").encode(encoding="utf-8")
    decryptor = PKCS1_OAEP.new(private_key)
    encrypt_msg = base64.decodebytes(msg)
    outputText.delete(0.0, END)
    
    try:

        decrypted= decryptor.decrypt(encrypt_msg)
        print("The text after private key decryption is: "+decrypted.decode('utf8'))
        outputText.insert(END,decrypted.decode('utf8'))
    except:

        a1 = "Private key decryption failed"
        print(a1)
        outputText.insert(END,a1)

def sign_msg():

    global signature
    private_key_str = privateKeyText.get("0.0","end").encode(encoding="utf-8")
    private_key = RSA.import_key(private_key_str)
    msg = (entryText.get("0.0","end")).encode(encoding= "utf-8")
    hash = SHA256.new(msg)
    signer = PKCS115_SigScheme(private_key)
    signature = signer.sign(hash)
    a = signature.hex()
    outputText.delete(0.0,END)
    outputText.insert(0.0,a)

def verify_msg():

    public_key_str = publicKeyText.get("0.0","end").encode(encoding="utf-8")
    public_key = RSA.import_key(public_key_str)
    msg = (entryText.get("0.0","end")).encode(encoding="utf-8")
    hash_msg = SHA256.new(msg)
    signatur = (entrySig.get("0.0"))
    verifier = PKCS115_SigScheme(public_key)
    try:
        verifier.verify(hash_msg,signature)
        b = "Verify successful, signature is valid"
        outputCheck.delete("0.0",END)
        outputCheck.insert(END,b)
    except:
        a = "Can not verify, signature is not valid."
        print(a)
        outputCheck.delete("0.0",END)
        outputCheck.insert(END,a)

window = Tk()    
window.title("RSA Encryption Decryption Software")

frame = Frame(window)
frame.pack()

label = Label(frame, text = "Public key:")
label.grid(row = 1, column = 1,columnspan= 4)

publicKeyText = Text(frame,width=50,height=8)
publicKeyText.grid(row = 2, column = 1,columnspan = 4)

label = Label(frame, text = "Private key:")
label.grid(row = 3, column = 1,columnspan= 4)

privateKeyText = Text(frame,width=50,height=8)
privateKeyText.grid(row = 4, column = 1,columnspan = 4)

btGenerateKey = Button(frame, text = "Generate public key / private key",command=GenerateKey)
btGenerateKey.grid(row = 5, column = 1,columnspan = 4)

label = Label(frame, text = "Please enter the text:")
label.grid(row = 6, column = 1,columnspan = 4)

entryText = Text(frame,width=50,height=5)
entryText.grid(row = 7, column = 1,columnspan = 4)

label = Label(frame, text = "Please enter the signature:")
label.grid(row = 10, column = 1,columnspan = 4)

entrySig = Text(frame,width=50,height=5)
entrySig.grid(row = 11, column = 1,columnspan = 4)

btEncryptionByPublickey = Button(frame, text = "Encryption",command=EncryptionByPublickey)
btEncryptionByPublickey.grid(row = 8, column = 1,pady = 10)

btsignmsg = Button(frame, text = "Create signature",command=sign_msg)
btsignmsg.grid(row = 8, column = 2)

btDecryptionByPrivatekey = Button(frame, text = "Decryption",command=DecryptionByPrivatekey)
btDecryptionByPrivatekey.grid(row = 8, column = 3)

btcheckSig = Button(frame, text = "Verify signature", command=verify_msg)
btcheckSig.grid(row = 12, column = 2,pady = 10)

outputText = Text(frame,width=50,height=5)
outputText.grid(row = 9, column = 1,columnspan = 4)

outputCheck = Text(frame,width=50,height=5)
outputCheck.grid(row = 13, column = 1,columnspan = 4)

GenerateKey();
mainloop()