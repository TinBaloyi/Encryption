import tkinter as tk
from tkinter import *
from cryptography.fernet import Fernet
from tkinter import messagebox
from tkinter import filedialog
import tkinter.simpledialog
import os

root = tk.Tk()

rdoBtn = tk.IntVar()
myFrame = Frame(root)
myFrame.pack()

Password = tkinter.simpledialog.askstring("User choice of password", "Enter password to use for encrypting and decrypting your files", show="*")  # Ask for the password
myEntry = tk.Entry(myFrame, show="*")
myEntry.grid(row=2, column=1, padx=10, pady=20)

# Generates key
key = Fernet.generate_key()

# Initialize the Fernet cipher with the key
cipher = Fernet(key)

Label(root, text="Choose an algorithm ", font="Arial 10").pack()
tk.Radiobutton(root, text="General Algorithm", variable=rdoBtn, value=1).pack()
tk.Radiobutton(root, text="Own Algorithm", variable=rdoBtn, value=2).pack()

def OwnEncryption(file_path, key):
    if myEntry.get() == Password:
        with open(file_path, "rb") as file:
            data = bytearray(file.read())

        if isinstance(key, str):
            key = key.encode('utf-8')

        for index, value in enumerate(data):
            data[index] = value ^ key[index % len(key)]  # allows both strings and integers to be used as a password

        new_file_path = file_path + ".enc"  # Create a new file path with ".enc" extension

        with open(new_file_path, "wb") as file:
            file.write(data)

        os.remove(file_path)  # Remove the original file after encryption
    else:
        messagebox.showinfo("Error", "Wrong password, Will not encrypt")

def OwnDecryption(file_path, key):
    if myEntry.get() == Password:
        with open(file_path, "rb") as file:
            data = bytearray(file.read())

        if isinstance(key, str):
            key = key.encode('utf-8')

        for index, value in enumerate(data):
            data[index] = value ^ key[index % len(key)]  # allows both strings and integers to be used as a password

        with open(file_path, "wb") as file:
            file.write(data)

        new_file_path = os.path.splitext(file_path)[0]  # Remove the file extension
        os.rename(file_path, new_file_path)  # Rename the decrypted file to the original file name
    else:
        messagebox.showinfo("Error", "Wrong password, Will not decrypt")

def generalEncrypt_file(file_path):
    if myEntry.get() == Password:
        # Read the file contents
        with open(file_path, 'rb') as f:
            file_contents = f.read()

        # Encrypt the file contents
        encrypted_contents = cipher.encrypt(file_contents)
        messagebox.showinfo("Message", "Done encrypting")

        # Write the encrypted contents back to the file
        with open(file_path, 'wb') as f:
            f.write(encrypted_contents)
    else:
        messagebox.showinfo("Message", "No password entered/Wrong password")

def generalDecrypt_file(file_path):
    if myEntry.get() == Password:
        # Read the encrypted file contents
        with open(file_path, 'rb') as f:
            encrypted_contents = f.read()

        # Decrypt the file contents
        decrypted_contents = cipher.decrypt(encrypted_contents)
        messagebox.showinfo("Message", "Done decrypting")

        # Write the decrypted contents back to the file
        with open(file_path, 'wb') as f:
            f.write(decrypted_contents)
    else:
        messagebox.showinfo("Message", "No password entered/Wrong password")

def encrypt():
    # Encrypt in terms of choice of algorithm
    if rdoBtn.get() == 1:
        # Get the path of the file to encrypt
        file_path = filedialog.askopenfilename()
        # Encrypt the file with the general algorithm
        generalEncrypt_file(file_path)
    elif rdoBtn.get() == 2:
        # Encrypt the file with own algorithm
        file_path = filedialog.askopenfilename()
        OwnEncryption(file_path, Password)
        messagebox.showinfo("Message", "Done Encrypting")
    else:
        messagebox.showinfo("Error", "Select a radio button!")

def decrypt():
    # Decrypt in terms of choice of algorithm
    if rdoBtn.get() == 1:
        # Get the path of the file to decrypt
        file_path = filedialog.askopenfilename()
        # Decrypt the file with the general algorithm
        generalDecrypt_file(file_path)
    elif rdoBtn.get() == 2:
        # Decrypt the file with own algorithm
        file_path = filedialog.askopenfilename()
        OwnDecryption(file_path, Password)
        messagebox.showinfo("Message", "Done Decrypting")
    else:
        messagebox.showinfo("Error", "Select a radio button!")

root.geometry("500x500")
root.title("Encryption and Decryption GUI")

labelEnter = tk.Label(myFrame, text="Enter the password:", font=('Arial', 10))
labelEnter.grid(row=2, column=0, padx=10, pady=20)

EncryptButton = tk.Button(myFrame, text="Encrypt", command=encrypt)
EncryptButton.grid(row=3, column=0, pady=20)

DecryptButton = tk.Button(myFrame, text="Decrypt", command=decrypt)
DecryptButton.grid(row=3, column=1, padx=10, pady=20)

root.mainloop()
