# rsa
import tkinter as tk
from tkinter import messagebox, END
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


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
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return ciphertext.hex()

def rsa_decrypt(ciphertext, private_key_pem):
    # Deserialize private key from PEM format
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    
    # Decrypt the ciphertext
    plaintext = private_key.decrypt(
        bytes.fromhex(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return plaintext.decode()

def generate_key():
    private_key, public_key = generate_rsa_keypair()
    private_key_text.delete(1.0, END)
    public_key_text.delete(1.0, END)
    private_key_text.insert(tk.END, private_key)
    public_key_text.insert(tk.END, public_key)

def encrypt():
    public_key = public_key_text.get(1.0, tk.END)
    message = message_entry.get()
    ciphertext = rsa_encrypt(message, public_key)
    ciphertext_entry.delete(1.0, END)
    ciphertext_entry.insert(tk.END, ciphertext)

def decrypt():
    private_key = private_key_text.get(1.0, tk.END)
    ciphertext = ciphertext_entry.get("1.0", tk.END).strip()
    try:
        decrypted_message = rsa_decrypt(ciphertext, private_key)
        output_text.delete(1.0, END)
        output_text.insert(tk.END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# GUI Setup
root = tk.Tk()
root.title("RSA Encryption/Decryption")

generate_button = tk.Button(root, text="Generate Key", command=generate_key)
generate_button.grid(row=0, column=0, padx=5, pady=5)

private_key_label = tk.Label(root, text="Private Key:")
private_key_label.grid(row=1, column=0, padx=5, pady=5)
private_key_text = tk.Text(root, height=10, width=50)
private_key_text.grid(row=1, column=1, padx=5, pady=5)

public_key_label = tk.Label(root, text="Public Key:")
public_key_label.grid(row=2, column=0, padx=5, pady=5)
public_key_text = tk.Text(root, height=10, width=50)
public_key_text.grid(row=2, column=1, padx=5, pady=5)

message_label = tk.Label(root, text="Message:")
message_label.grid(row=3, column=0, padx=5, pady=5)
message_entry = tk.Entry(root, width=50)
message_entry.grid(row=3, column=1, padx=5, pady=5)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=4, column=1, padx=5, pady=5)

ciphertext_label = tk.Label(root, text="Ciphertext:")
ciphertext_label.grid(row=5, column=0, padx=5, pady=5)
ciphertext_entry = tk.Text(root, height=5, width=50)
ciphertext_entry.grid(row=5, column=1, padx=5, pady=5)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=6, column=1, padx=5, pady=5)

output_text = tk.Text(root, height=10, width=50)
output_text.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()
