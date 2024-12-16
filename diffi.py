import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os


class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Diffie-Hellman i RSA")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)

        self.create_diffie_hellman_tab()
        self.create_rsa_tab()

    def create_diffie_hellman_tab(self):
        self.diffie_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.diffie_tab, text="Diffie-Hellman")

        tk.Label(self.diffie_tab, text="Podaj liczbę pierwszą p:").grid(row=0, column=0, padx=5, pady=5)
        self.p_entry = tk.Entry(self.diffie_tab)
        self.p_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.diffie_tab, text="Podaj generator g:").grid(row=1, column=0, padx=5, pady=5)
        self.g_entry = tk.Entry(self.diffie_tab)
        self.g_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Button(self.diffie_tab, text="Oblicz klucz wspólny", command=self.calculate_diffie_hellman).grid(row=2,
                                                                                                            columnspan=2,
                                                                                                            pady=10)

        self.result_label = tk.Label(self.diffie_tab, text="")
        self.result_label.grid(row=3, columnspan=2, pady=10)

    def calculate_diffie_hellman(self):
        try:
            p = int(self.p_entry.get())
            g = int(self.g_entry.get())

            private_a = int.from_bytes(get_random_bytes(4), 'big')
            private_b = int.from_bytes(get_random_bytes(4), 'big')

            public_a = pow(g, private_a, p)
            public_b = pow(g, private_b, p)

            shared_key_a = pow(public_b, private_a, p)
            shared_key_b = pow(public_a, private_b, p)

            if shared_key_a == shared_key_b:
                self.result_label.config(text=f"Klucz wspólny: {shared_key_a}")
            else:
                self.result_label.config(text="Błąd: Klucze nie są zgodne!")
        except ValueError:
            messagebox.showerror("Błąd", "Nieprawidłowe dane wejściowe!")

    def create_rsa_tab(self):
        self.rsa_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.rsa_tab, text="RSA")

        tk.Button(self.rsa_tab, text="Generuj klucze RSA", command=self.generate_rsa_keys).grid(row=0, columnspan=2,
                                                                                                pady=10)

        tk.Label(self.rsa_tab, text="Wybierz plik do zaszyfrowania:").grid(row=1, column=0, padx=5, pady=5)
        tk.Button(self.rsa_tab, text="Wybierz plik", command=self.select_file).grid(row=1, column=1, padx=5, pady=5)

        tk.Button(self.rsa_tab, text="Szyfruj plik", command=self.encrypt_file).grid(row=2, column=0, padx=5, pady=5)
        tk.Button(self.rsa_tab, text="Deszyfruj plik", command=self.decrypt_file).grid(row=2, column=1, padx=5, pady=5)

        self.file_label = tk.Label(self.rsa_tab, text="Nie wybrano pliku")
        self.file_label.grid(row=3, columnspan=2, pady=10)

    def generate_rsa_keys(self):
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            with open("private.pem", "wb") as priv_file:
                priv_file.write(private_key)

            with open("public.pem", "wb") as pub_file:
                pub_file.write(public_key)

            messagebox.showinfo("Sukces",
                                "Klucze RSA zostały wygenerowane i zapisane jako private.pem oraz public.pem.")
        except Exception as e:
            messagebox.showerror("Błąd", f"Wystąpił problem: {e}")

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path = file_path
            self.file_label.config(text=os.path.basename(file_path))
        else:
            self.file_label.config(text="Nie wybrano pliku")

    def encrypt_file(self):
        try:
            with open("public.pem", "rb") as pub_file:
                public_key = RSA.import_key(pub_file.read())
            cipher_rsa = PKCS1_OAEP.new(public_key)

            with open(self.file_path, "rb") as f:
                data = f.read()

            chunk_size = 190
            chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

            encrypted_chunks = []
            for chunk in chunks:
                encrypted_chunks.append(cipher_rsa.encrypt(chunk))

            encrypted_file_path = os.path.splitext(self.file_path)[0] + ".enc"
            with open(encrypted_file_path, "wb") as enc_file:
                for encrypted_chunk in encrypted_chunks:
                    enc_file.write(len(encrypted_chunk).to_bytes(4, byteorder="big"))
                    enc_file.write(encrypted_chunk)

            messagebox.showinfo("Sukces", f"Plik został zaszyfrowany: {encrypted_file_path}")
        except Exception as e:
            messagebox.showerror("Błąd", f"Wystąpił problem: {e}")

    def decrypt_file(self):
        try:
            with open("private.pem", "rb") as priv_file:
                private_key = RSA.import_key(priv_file.read())
            cipher_rsa = PKCS1_OAEP.new(private_key)

            with open(self.file_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = b""
            offset = 0
            while offset < len(encrypted_data):
                chunk_size = int.from_bytes(encrypted_data[offset:offset + 4], byteorder="big")
                offset += 4
                encrypted_chunk = encrypted_data[offset:offset + chunk_size]
                offset += chunk_size
                decrypted_data += cipher_rsa.decrypt(encrypted_chunk)

            decrypted_file_path = os.path.splitext(self.file_path)[0] + "_decrypted"
            with open(decrypted_file_path, "wb") as dec_file:
                dec_file.write(decrypted_data)

            messagebox.showinfo("Sukces", f"Plik został odszyfrowany: {decrypted_file_path}")
        except Exception as e:
            messagebox.showerror("Błąd", f"Wystąpił problem: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
