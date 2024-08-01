# Encryption

Overview
This project is a simple GUI application for encrypting and decrypting files using Python. It provides two encryption algorithms: a general algorithm (using the Fernet module from the cryptography library) and a custom XOR-based algorithm. The GUI is built using the Tkinter library.

Features
Password Protection: The application prompts the user for a password to use for encryption and decryption.
Multiple Algorithms: Users can choose between a general encryption algorithm and a custom XOR-based algorithm.
User-Friendly Interface: A simple and intuitive interface for selecting files and encrypting/decrypting them.
Getting Started
Prerequisites
Python 3.x
Required libraries: tkinter, cryptography, Crypto
You can install the required libraries using pip:
pip install cryptography pycryptodome


Usage
When you start the application, you will be prompted to enter a password.
Choose an encryption algorithm by selecting one of the radio buttons:
General Algorithm: Uses the Fernet encryption algorithm.
Own Algorithm: Uses a custom XOR-based encryption algorithm.
Click the "Encrypt" button to select a file and encrypt it.
Click the "Decrypt" button to select an encrypted file and decrypt it.
Encryption Algorithms
General Algorithm (Fernet)
Fernet is an implementation of symmetric (also known as “secret key”) authenticated cryptography. Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key.

Own Algorithm (XOR-based)
The custom algorithm uses the XOR bitwise operation with the password to encrypt and decrypt files. It is a simple method but less secure compared to modern encryption algorithms.

Acknowledgments
The cryptography library for providing easy-to-use cryptographic functions.
The Tkinter library for GUI creation.
