import tkinter
from tkinter import *
import customtkinter
from PIL import Image, ImageTk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

secren = Tk()
secren.minsize(width=400, height=600)

def encrypt():
    title = ent1.get()
    secret = txt.get("1.0", "end-1c")
    master_key = ent2.get()

    if not title or not secret or not master_key:
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    # Generate a key for encryption
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    # Encrypt the secret message
    encrypted_secret = cipher_suite.encrypt(secret.encode())

    # Save the encrypted secret and key to a file
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path:
        with open(file_path, "wb") as file:
            file.write(encrypted_secret + b'\n' + key)

        messagebox.showinfo("Encryption", "Encryption completed and file saved!")

def decrypt():
    master_key = ent2.get()

    if not master_key:
        messagebox.showerror("Error", "Please enter the master key.")
        return

    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "rb") as file:
            contents = file.read()

        try:
            # Split the contents into encrypted secret and key
            encrypted_secret, stored_key = contents.split(b'\n')

            # Create a new Fernet cipher suite using the stored key
            cipher_suite = Fernet(stored_key)

            # Decrypt the secret message
            decrypted_secret = cipher_suite.decrypt(encrypted_secret).decode()
            messagebox.showinfo("Decryption", "Decryption completed!\n\nDecrypted Secret:\n" + decrypted_secret)
        except:
            messagebox.showerror("Decryption Error", "Failed to decrypt the file!")

img = ImageTk.PhotoImage(Image.open(r"C:\Users\ardab\OneDrive\Resimler\istockphoto-504757234-612x612111.jpg"))
panel = tkinter.Label(secren, image=img)
panel.pack(side="top", fill="y", expand="false")

lab1 = tkinter.Label(text="Enter your title")
lab1.pack(pady=20)

ent1 = tkinter.Entry(width=30)
ent1.pack()

lab2 = tkinter.Label(text="Enter your secret", pady=10)
lab2.pack()

txt = tkinter.Text(width=30, height=13)
txt.pack()

lab3 = tkinter.Label(text="Enter master key", pady=10)
lab3.pack()

ent2 = tkinter.Entry(width=30)
ent2.pack()

button1 = customtkinter.CTkButton(master=secren, fg_color=("dodger blue", "dodger blue"), text="Save & encrypt",
                                 command=encrypt)
button1.pack(pady=10)

button2 = customtkinter.CTkButton(master=secren, fg_color=("dodger blue", "dodger blue"), text="Decrypt",
                                 command=decrypt)
button2.pack(pady=5)

secren.mainloop()
