import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import hmac


def generate_hmac():
    message = message_entry.get()
    key = key_entry.get()
    algorithm = algorithm_combobox.get()

    if not message or not key:
        messagebox.showerror("Błąd", "Wprowadź zarówno wiadomość, jak i klucz!")
        return

    try:
        key_bytes = key.encode('utf-8')
        message_bytes = message.encode('utf-8')

        if algorithm == "SHA-256":
            digest = hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()
        elif algorithm == "SHA-1":
            digest = hmac.new(key_bytes, message_bytes, hashlib.sha1).hexdigest()
        elif algorithm == "MD5":
            digest = hmac.new(key_bytes, message_bytes, hashlib.md5).hexdigest()
        else:
            messagebox.showerror("Błąd", "Nieobsługiwany algorytm!")
            return

        result_label.config(text=f"HMAC: {digest}")
    except Exception as e:
        messagebox.showerror("Błąd", f"Wystąpił błąd: {str(e)}")


root = tk.Tk()
root.title("Generator HMAC")
root.geometry("400x300")

tk.Label(root, text="Wiadomość:").pack(pady=5)
message_entry = tk.Entry(root, width=50)
message_entry.pack(pady=5)

tk.Label(root, text="Klucz:").pack(pady=5)
key_entry = tk.Entry(root, width=50, show="*")
key_entry.pack(pady=5)

tk.Label(root, text="Algorytm:").pack(pady=5)
algorithm_combobox = ttk.Combobox(root, values=["SHA-256", "SHA-1", "MD5"], state="readonly")
algorithm_combobox.set("SHA-256")
algorithm_combobox.pack(pady=5)

generate_button = tk.Button(root, text="Generuj HMAC", command=generate_hmac)
generate_button.pack(pady=10)

result_label = tk.Label(root, text="HMAC: ", wraplength=380, justify="center")
result_label.pack(pady=10)

root.mainloop()
