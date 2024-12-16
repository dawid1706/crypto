import os
from tkinter import Tk, filedialog, Label, Button, Text, StringVar, Entry, Frame, Radiobutton, messagebox, OptionMenu
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class AplikacjaSzyfrowania:
    def __init__(self, root):
        self.root = root
        self.root.title("Szyfrowanie plików i tekstu")
        self.algorytm = StringVar(value="AES")
        self.tryb = StringVar(value="Blokowy")
        self.typ_operacji = StringVar(value="Tekst")
        self.iv = None
        self.utworz_interfejs()

    def utworz_interfejs(self):
        ramka_algorytm = Frame(self.root)
        ramka_algorytm.pack(pady=10)

        Label(ramka_algorytm, text="Wybierz algorytm:").grid(row=0, column=0, padx=10)
        Radiobutton(ramka_algorytm, text="AES", variable=self.algorytm, value="AES").grid(row=0, column=1)
        Radiobutton(ramka_algorytm, text="DES", variable=self.algorytm, value="DES").grid(row=0, column=2)

        ramka_tryb = Frame(self.root)
        ramka_tryb.pack(pady=10)

        Label(ramka_tryb, text="Wybierz tryb:").grid(row=0, column=0, padx=10)
        Radiobutton(ramka_tryb, text="Blokowy", variable=self.tryb, value="Blokowy").grid(row=0, column=1)
        Radiobutton(ramka_tryb, text="Strumieniowy", variable=self.tryb, value="Strumieniowy").grid(row=0, column=2)

        ramka_operacja = Frame(self.root)
        ramka_operacja.pack(pady=10)

        Label(ramka_operacja, text="Operacja:").grid(row=0, column=0, padx=10)
        OptionMenu(ramka_operacja, self.typ_operacji, "Tekst", "Plik", command=self.przelacz_wejscie).grid(row=0, column=1)

        ramka_klucz = Frame(self.root)
        ramka_klucz.pack(pady=10)

        Label(ramka_klucz, text="Klucz:").grid(row=0, column=0, padx=10)
        self.pole_klucz = Entry(ramka_klucz, width=30)
        self.pole_klucz.grid(row=0, column=1)

        self.przycisk_plik = Button(self.root, text="Wybierz plik", command=self.wybierz_plik)
        self.etykieta_plik = Label(self.root, text="Nie wybrano pliku")

        self.etykieta_tekst = Label(self.root, text="Tekst do zaszyfrowania/odszyfrowania:")
        self.pole_tekst = Text(self.root, height=10, width=50)

        Button(self.root, text="Szyfruj", command=self.szyfruj).pack(side="left", padx=20, pady=10)
        Button(self.root, text="Deszyfruj", command=self.deszyfruj).pack(side="right", padx=20, pady=10)

        self.przelacz_wejscie(self.typ_operacji.get())

    def przelacz_wejscie(self, operacja):
        if operacja == "Plik":
            self.etykieta_tekst.pack_forget()
            self.pole_tekst.pack_forget()
            self.przycisk_plik.pack(pady=10)
            self.etykieta_plik.pack(pady=5)
        else:
            self.przycisk_plik.pack_forget()
            self.etykieta_plik.pack_forget()
            self.etykieta_tekst.pack(pady=10)
            self.pole_tekst.pack(pady=10)

    def wybierz_plik(self):
        self.sciezka_pliku = filedialog.askopenfilename()
        if self.sciezka_pliku:
            self.etykieta_plik.config(text=f"Wybrano: {os.path.basename(self.sciezka_pliku)}")
        else:
            self.etykieta_plik.config(text="Nie wybrano pliku")

    def sprawdz_klucz(self, klucz):
        if self.algorytm.get() == "AES" and len(klucz) > 16:
            messagebox.showerror("Błąd", "Klucz AES musi mieć 16 znaków lub mniej.")
            return False
        if self.algorytm.get() == "DES" and len(klucz) > 8:
            messagebox.showerror("Błąd", "Klucz DES musi mieć 8 znaków lub mniej.")
            return False
        if not klucz:
            messagebox.showerror("Błąd", "Klucz nie może być pusty.")
            return False
        return True

    def pobierz_szyfr(self, dla_szyfrowania=True):
        klucz = self.pole_klucz.get().encode('utf-8')
        if not self.sprawdz_klucz(klucz.decode('utf-8')):
            return None

        if self.algorytm.get() == "AES":
            klucz = pad(klucz, AES.block_size)[:16]
            if self.tryb.get() == "Blokowy":
                if dla_szyfrowania:
                    self.iv = get_random_bytes(16)
                elif not self.iv or len(self.iv) != 16:
                    raise ValueError("Niepoprawna długość wektora IV (musi mieć 16 bajtów dla AES).")
                return AES.new(klucz, AES.MODE_CBC, iv=self.iv)
            else:
                if dla_szyfrowania:
                    self.iv = get_random_bytes(16)
                elif not self.iv or len(self.iv) != 16:
                    raise ValueError("Niepoprawna długość wektora IV (musi mieć 16 bajtów dla AES).")
                return AES.new(klucz, AES.MODE_CFB, iv=self.iv)
        else:
            klucz = pad(klucz, DES.block_size)[:8]
            if self.tryb.get() == "Blokowy":
                if dla_szyfrowania:
                    self.iv = get_random_bytes(8)
                elif not self.iv or len(self.iv) != 8:
                    raise ValueError("Niepoprawna długość wektora IV (musi mieć 8 bajtów dla DES).")
                return DES.new(klucz, DES.MODE_CBC, iv=self.iv)
            else:
                if dla_szyfrowania:
                    self.iv = get_random_bytes(8)
                elif not self.iv or len(self.iv) != 8:
                    raise ValueError("Niepoprawna długość wektora IV (musi mieć 8 bajtów dla DES).")
                return DES.new(klucz, DES.MODE_CFB, iv=self.iv)

    def szyfruj(self):
        szyfr = self.pobierz_szyfr(dla_szyfrowania=True)
        if not szyfr:
            return

        if self.typ_operacji.get() == "Tekst":
            tekst = self.pole_tekst.get("1.0", "end").strip()
            if tekst:
                try:
                    zaszyfrowany_tekst = szyfr.encrypt(pad(tekst.encode('utf-8'), szyfr.block_size))
                    self.pole_tekst.delete("1.0", "end")
                    self.pole_tekst.insert("1.0", f"{self.iv.hex()}:{zaszyfrowany_tekst.hex()}")
                except Exception as e:
                    messagebox.showerror("Błąd", f"Szyfrowanie nie powiodło się: {e}")
        elif self.typ_operacji.get() == "Plik":
            if hasattr(self, 'sciezka_pliku') and os.path.isfile(self.sciezka_pliku):
                try:
                    with open(self.sciezka_pliku, 'rb') as f:
                        dane = f.read()
                    zaszyfrowane_dane = szyfr.encrypt(pad(dane, szyfr.block_size))
                    nazwa_pliku, rozszerzenie = os.path.splitext(os.path.basename(self.sciezka_pliku))
                    metadane = f"{rozszerzenie}|".encode('utf-8')
                    ukryta_sciezka = os.path.join(os.getcwd(), nazwa_pliku)
                    with open(ukryta_sciezka, 'wb') as f:
                        f.write(self.iv + metadane + zaszyfrowane_dane)
                    messagebox.showinfo("Sukces", f"Zaszyfrowano plik: {ukryta_sciezka}")
                except Exception as e:
                    messagebox.showerror("Błąd", f"Szyfrowanie pliku nie powiodło się: {e}")

    def deszyfruj(self):
        if self.typ_operacji.get() == "Tekst":
            tekst = self.pole_tekst.get("1.0", "end").strip()
            if tekst:
                try:
                    iv_hex, zaszyfrowany_tekst = tekst.split(":")
                    self.iv = bytes.fromhex(iv_hex)
                    szyfr = self.pobierz_szyfr(dla_szyfrowania=False)
                    odszyfrowany_tekst = unpad(szyfr.decrypt(bytes.fromhex(zaszyfrowany_tekst)), szyfr.block_size).decode('utf-8')
                    self.pole_tekst.delete("1.0", "end")
                    self.pole_tekst.insert("1.0", odszyfrowany_tekst)
                except Exception as e:
                    messagebox.showerror("Błąd", f"Deszyfrowanie nie powiodło się: {e}")
        elif self.typ_operacji.get() == "Plik":
            if hasattr(self, 'sciezka_pliku') and os.path.isfile(self.sciezka_pliku):
                try:
                    with open(self.sciezka_pliku, 'rb') as f:
                        dane = f.read()
                    if self.algorytm.get() == "AES":
                        self.iv = dane[:16]
                        koniec_metadanych = dane.find(b"|")
                    else:
                        self.iv = dane[:8]
                        koniec_metadanych = dane.find(b"|")

                    metadane = dane[len(self.iv):koniec_metadanych].decode('utf-8')
                    zaszyfrowane_dane = dane[koniec_metadanych + 1:]

                    szyfr = self.pobierz_szyfr(dla_szyfrowania=False)
                    odszyfrowane_dane = unpad(szyfr.decrypt(zaszyfrowane_dane), szyfr.block_size)
                    sciezka_wyjscia = f"{self.sciezka_pliku}{metadane}"
                    with open(sciezka_wyjscia, 'wb') as f:
                        f.write(odszyfrowane_dane)
                    messagebox.showinfo("Sukces", f"Odszyfrowano plik: {sciezka_wyjscia}")
                except Exception as e:
                    messagebox.showerror("Błąd", f"Deszyfracja pliku nie powiodła się: {e}")

if __name__ == "__main__":
    root = Tk()
    app = AplikacjaSzyfrowania(root)
    root.mainloop()
