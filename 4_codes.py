import tkinter as tk
# from tkinter import Tk, Label, Entry, Button, Text
from tkinter import ttk,  messagebox, END
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
# from cryptography.hazmat.primitives import hashes 
import hashlib
import os


def des_encrypt(message, key):
    # Pad the message if needed
    if len(message) % 8 != 0:
        message += b"\0" * (8 - len(message) % 8)
    
    # Create a DES cipher object
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Encrypt the message
    ciphertext = cipher.encrypt(message)
    
    return ciphertext

def des_decrypt(ciphertext, key):
    # Create a DES cipher object
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Decrypt the ciphertext
    decrypted_message = cipher.decrypt(ciphertext)
    
    return decrypted_message.rstrip(b"\0")

def generate_des_key():
    key = get_random_bytes(8)
    des_key_entry.delete(0, END)
    des_key_entry.insert(tk.END, key.hex())

def des_encrypt_message():
    key = bytes.fromhex(des_key_entry.get())
    message = des_message_entry.get().encode()

    # Check if the key length is 8 bytes
    if len(key) != 8:
        messagebox.showerror("Error", "Key must be 8 bytes long.")
        return

    # Encryption
    ciphertext = des_encrypt(message, key)
    des_ciphertext_entry.delete(1.0, END)
    des_ciphertext_entry.insert(tk.END, ciphertext.hex())

def des_decrypt_message():
    key = bytes.fromhex(des_key_entry.get())
    ciphertext = bytes.fromhex(des_ciphertext_entry.get("1.0", "end-1c"))

    # Check if the key length is 8 bytes
    if len(key) != 8:
        messagebox.showerror("Error", "Key must be 8 bytes long.")
        return

    # Decryption
    decrypted_message = des_decrypt(ciphertext, key)
    des_decrypted_text.delete(1.0, END)
    des_decrypted_text.insert(tk.END, decrypted_message.decode())

def aes_encrypt(message, key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to ensure its length is a multiple of the block size
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    
    # Encrypt the padded message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    return iv, ciphertext

def aes_decrypt(iv, ciphertext, key):
    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the decrypted message
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_message)
    
    return unpadded_message + unpadder.finalize()

def generate_aes_key():
    # Generate a random 256-bit AES key
    key = os.urandom(32)
    aes_key_entry.delete(0, END)
    aes_key_entry.insert(tk.END, key.hex())

def aes_encrypt_message():
    key = bytes.fromhex(aes_key_entry.get())
    message = aes_message_entry.get().encode()

    # Check if the key length is 32 bytes (256 bits)
    if len(key) != 32:
        messagebox.showerror("Error", "Key must be 32 bytes (256 bits) long.")
        return

    # Encryption
    iv, ciphertext = aes_encrypt(message, key)
    aes_iv_entry.delete(1.0, END)
    aes_iv_entry.insert(tk.END, iv.hex())
    aes_ciphertext_entry.delete(1.0, END)
    aes_ciphertext_entry.insert(tk.END, ciphertext.hex())

def aes_decrypt_message():
    key = bytes.fromhex(aes_key_entry.get())
    iv = bytes.fromhex(aes_iv_entry.get("1.0", "end-1c"))
    ciphertext = bytes.fromhex(aes_ciphertext_entry.get("1.0", "end-1c"))

    # Check if the key length is 32 bytes (256 bits)
    if len(key) != 32:
        messagebox.showerror("Error", "Key must be 32 bytes (256 bits) long.")
        return

    # Decryption
    decrypted_message = aes_decrypt(iv, ciphertext, key)
    aes_decrypted_text.delete(1.0, END)
    aes_decrypted_text.insert(tk.END, decrypted_message.decode())

def generate_md5_key():
    # Generate a random encryption key
    key = Fernet.generate_key()
    md5_key_entry.delete(0, "end")
    md5_key_entry.insert(0, key.decode())

def md5_encrypt():
    key = md5_key_entry.get().encode()
    message = md5_message_entry.get()
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    md5_encrypted_message_entry.delete(0, "end")
    md5_encrypted_message_entry.insert(0, encrypted_message.decode())

def md5_decrypt():
    key = md5_key_entry.get().encode()
    encrypted_message = md5_encrypted_message_entry.get().encode()
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    md5_decrypted_message_entry.delete(1.0, "end")
    md5_decrypted_message_entry.insert("end", decrypted_message)


# RSA Encryption/Decryption Functions
def generate_rsa_keypair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize private key and public key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem.decode(), public_key_pem.decode()


def rsa_encrypt(message, public_key_pem):
    # Deserialize public key from PEM format
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())

    # Encrypt the message
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashlib.SHA256()),
            algorithm=hashlib.SHA256(),
            label=None
        )
    )

    return ciphertext.hex()


def rsa_decrypt(ciphertext, private_key_pem):
    # Deserialize private key from PEM format
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None,
                                                     backend=default_backend())

    # Decrypt the ciphertext
    plaintext = private_key.decrypt(
        bytes.fromhex(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashlib.SHA256()),
            algorithm=hashlib.SHA256(),
            label=None
        )
    )

    return plaintext.decode()


def generate_key_rsa():
    private_key, public_key = generate_rsa_keypair()
    private_key_text.delete(1.0, END)
    public_key_text.delete(1.0, END)
    private_key_text.insert(tk.END, private_key)
    public_key_text.insert(tk.END, public_key)


def encrypt_rsa():
    public_key = public_key_text.get(1.0, tk.END)
    message = message_entry_rsa.get()
    ciphertext = rsa_encrypt(message, public_key)
    ciphertext_entry_rsa.delete(1.0, END)
    ciphertext_entry_rsa.insert(tk.END, ciphertext)


def decrypt_rsa():
    private_key = private_key_text.get(1.0, tk.END)
    ciphertext = ciphertext_entry_rsa.get("1.0", tk.END).strip()
    try:
        decrypted_message = rsa_decrypt(ciphertext, private_key)
        output_text_rsa.delete(1.0, END)
        output_text_rsa.insert(tk.END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")



# Diffie-Hellman Key Exchange Functions
def generate_dh_parameters():
    # Generate Diffie-Hellman parameters
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters


def generate_dh_key_pair(parameters):
    # Generate a Diffie-Hellman key pair
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_secret(private_key, peer_public_key):
    # Derive shared secret
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def perform_key_exchange():
    # Generate parameters
    dh_parameters = generate_dh_parameters()

    # Alice's key pair
    alice_private_key, alice_public_key = generate_dh_key_pair(dh_parameters)

    # Bob's key pair
    bob_private_key, bob_public_key = generate_dh_key_pair(dh_parameters)

    # Exchange public keys
    alice_shared_secret = derive_shared_secret(alice_private_key, bob_public_key)
    bob_shared_secret = derive_shared_secret(bob_private_key, alice_public_key)

    # Verify shared secrets are the same
    if alice_shared_secret == bob_shared_secret:
        shared_secret_text.delete(1.0, END)
        shared_secret_text.insert(tk.END, "Shared secret:\n" + alice_shared_secret.hex())
    else:
        messagebox.showerror("Error", "Shared secrets do not match.")

# GUI Setup
root = tk.Tk()
root.title("Encryption/Decryption App")

# tabs
tab_control = ttk.Notebook(root)
tab1 = tk.Frame(tab_control)
tab2 = tk.Frame(tab_control)
tab3 = tk.Frame(tab_control)
tab_rsa = ttk.Frame(tab_control)
tab_dh = ttk.Frame(tab_control)

# DES Tab
des_key_label = tk.Label(tab1, text="DES Key (Hex):")
des_key_label.grid(row=0, column=0, padx=5, pady=5)
des_key_entry = tk.Entry(tab1, width=50)
des_key_entry.grid(row=0, column=1, padx=5, pady=5)

des_generate_key_button = tk.Button(tab1, text="Generate Key", command=generate_des_key)
des_generate_key_button.grid(row=0, column=2, padx=5, pady=5)

des_message_label = tk.Label(tab1, text="Message:")
des_message_label.grid(row=1, column=0, padx=5, pady=5)
des_message_entry = tk.Entry(tab1, width=50)
des_message_entry.grid(row=1, column=1, padx=5, pady=5)

des_encrypt_button = tk.Button(tab1, text="Encrypt", command=des_encrypt_message)
des_encrypt_button.grid(row=2, column=1, padx=5, pady=5)

des_ciphertext_label = tk.Label(tab1, text="Ciphertext (Hex):")
des_ciphertext_label.grid(row=3, column=0, padx=5, pady=5)
des_ciphertext_entry = tk.Text(tab1, height=5, width=50)
des_ciphertext_entry.grid(row=3, column=1, padx=5, pady=5)

des_decrypt_button = tk.Button(tab1, text="Decrypt", command=des_decrypt_message)
des_decrypt_button.grid(row=4, column=1, padx=5, pady=5)

des_decrypted_text_label = tk.Label(tab1, text="Decrypted Message:")
des_decrypted_text_label.grid(row=5, column=0, padx=5, pady=5)
des_decrypted_text = tk.Text(tab1, height=5, width=50)
des_decrypted_text.grid(row=5, column=1, padx=5, pady=5)

tab_control.add(tab1, text="DES")

# AES Tab
aes_key_label = tk.Label(tab2, text="AES Key (Hex):")
aes_key_label.grid(row=0, column=0, padx=5, pady=5)
aes_key_entry = tk.Entry(tab2, width=50)
aes_key_entry.grid(row=0, column=1, padx=5, pady=5)

aes_generate_key_button = tk.Button(tab2, text="Generate Key", command=generate_aes_key)
aes_generate_key_button.grid(row=0, column=2, padx=5, pady=5)

aes_message_label = tk.Label(tab2, text="Message:")
aes_message_label.grid(row=1, column=0, padx=5, pady=5)
aes_message_entry = tk.Entry(tab2, width=50)
aes_message_entry.grid(row=1, column=1, padx=5, pady=5)

aes_encrypt_button = tk.Button(tab2, text="Encrypt", command=aes_encrypt_message)
aes_encrypt_button.grid(row=2, column=1, padx=5, pady=5)

aes_iv_label = tk.Label(tab2, text="IV (Hex):")
aes_iv_label.grid(row=3, column=0, padx=5, pady=5)
aes_iv_entry = tk.Text(tab2, height=2, width=50)
aes_iv_entry.grid(row=3, column=1, padx=5, pady=5)

aes_ciphertext_label = tk.Label(tab2, text="Ciphertext (Hex):")
aes_ciphertext_label.grid(row=4, column=0, padx=5, pady=5)
aes_ciphertext_entry = tk.Text(tab2, height=4, width=50)
aes_ciphertext_entry.grid(row=4, column=1, padx=5, pady=5)

aes_decrypt_button = tk.Button(tab2, text="Decrypt", command=aes_decrypt_message)
aes_decrypt_button.grid(row=5, column=1, padx=5, pady=5)

aes_decrypted_text_label = tk.Label(tab2, text="Decrypted Message:")
aes_decrypted_text_label.grid(row=6, column=0, padx=5, pady=5)
aes_decrypted_text = tk.Text(tab2, height=5, width=50)
aes_decrypted_text.grid(row=6, column=1, padx=5, pady=5)

tab_control.add(tab2, text="AES")

# MD5 Tab
md5_key_label = tk.Label(tab3, text="MD5 Key:")
md5_key_label.grid(row=0, column=0, padx=5, pady=5)
md5_key_entry = tk.Entry(tab3, width=50)
md5_key_entry.grid(row=0, column=1, padx=5, pady=5)

md5_generate_key_button = tk.Button(tab3, text="Generate Key", command=generate_md5_key)
md5_generate_key_button.grid(row=0, column=2, padx=5, pady=5)

md5_message_label = tk.Label(tab3, text="Message:")
md5_message_label.grid(row=1, column=0, padx=5, pady=5)
md5_message_entry = tk.Entry(tab3, width=50)
md5_message_entry.grid(row=1, column=1, padx=5, pady=5)

md5_encrypt_button = tk.Button(tab3, text="Encrypt", command=md5_encrypt)
md5_encrypt_button.grid(row=2, column=1, padx=5, pady=5)

md5_encrypted_message_label = tk.Label(tab3, text="Encrypted Message:")
md5_encrypted_message_label.grid(row=3, column=0, padx=5, pady=5)
md5_encrypted_message_entry = tk.Entry(tab3, width=50)
md5_encrypted_message_entry.grid(row=3, column=1, padx=5, pady=5)

md5_decrypt_button = tk.Button(tab3, text="Decrypt", command=md5_decrypt)
md5_decrypt_button.grid(row=4, column=1, padx=5, pady=5)

md5_decrypted_message_label = tk.Label(tab3, text="Decrypted Message:")
md5_decrypted_message_label.grid(row=5, column=0, padx=5, pady=5)
md5_decrypted_message_entry = tk.Text(tab3, height=5, width=50)
md5_decrypted_message_entry.grid(row=5, column=1, padx=5, pady=5)

tab_control.add(tab3, text="MD5")

# RSA tab elements
generate_button_rsa = tk.Button(tab_rsa, text="Generate Key", command=generate_key_rsa)
generate_button_rsa.pack(pady=10)

private_key_label_rsa = tk.Label(tab_rsa, text="Private Key:")
private_key_label_rsa.pack(pady=5)

private_key_text = tk.Text(tab_rsa, height=10, width=50)
private_key_text.pack(pady=5)

public_key_label_rsa = tk.Label(tab_rsa, text="Public Key:")
public_key_label_rsa.pack(pady=5)

public_key_text = tk.Text(tab_rsa, height=10, width=50)
public_key_text.pack(pady=5)

message_label_rsa = tk.Label(tab_rsa, text="Message:")
message_label_rsa.pack(pady=5)

message_entry_rsa = tk.Entry(tab_rsa, width=50)
message_entry_rsa.pack(pady=5)

encrypt_button_rsa = tk.Button(tab_rsa, text="Encrypt", command=encrypt_rsa)
encrypt_button_rsa.pack(pady=5)

ciphertext_label_rsa = tk.Label(tab_rsa, text="Ciphertext:")
ciphertext_label_rsa.pack(pady=5)

ciphertext_entry_rsa = tk.Text(tab_rsa, height=5, width=50)
ciphertext_entry_rsa.pack(pady=5)

decrypt_button_rsa = tk.Button(tab_rsa, text="Decrypt", command=decrypt_rsa)
decrypt_button_rsa.pack(pady=5)

output_text_rsa = tk.Text(tab_rsa, height=10, width=50)
output_text_rsa.pack(pady=5)

# tab_control.add(tab_rsa, text='RSA')

# Diffie-Hellman tab elements
exchange_button_dh = tk.Button(tab_dh, text="Perform Key Exchange", command=perform_key_exchange)
exchange_button_dh.pack(pady=10)

shared_secret_text = tk.Text(tab_dh, height=10, width=50)
shared_secret_text.pack(padx=10, pady=5)

tab_control.add(tab_dh, text='Diffie-Hellman')

tab_control.pack(expand=1, fill="both")

root.mainloop()
