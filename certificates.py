import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_pem_x509_certificate
from PyPDF2 import PdfReader

class Application(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("Podpis cyfrowy i analiza certyfikatów")

        self.keygen_button = QPushButton("Generuj klucze RSA", self)
        self.sign_button = QPushButton("Podpisz dokument PDF", self)
        self.verify_button = QPushButton("Zweryfikuj podpis PDF", self)
        self.cert_button = QPushButton("Sprawdź certyfikat", self)

        layout = QVBoxLayout()

        button_layout_top = QHBoxLayout()
        button_layout_top.addWidget(self.keygen_button)
        button_layout_top.addWidget(self.cert_button)

        button_layout_bottom = QHBoxLayout()
        button_layout_bottom.addWidget(self.sign_button)
        button_layout_bottom.addWidget(self.verify_button)

        layout.addLayout(button_layout_top)
        layout.addLayout(button_layout_bottom)

        self.setLayout(layout)

        self.keygen_button.clicked.connect(self._generate_rsa_keys)
        self.sign_button.clicked.connect(self._sign_pdf_document)
        self.verify_button.clicked.connect(self._verify_pdf_signature)
        self.cert_button.clicked.connect(self._load_certificate)

    def _generate_rsa_keys(self):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()

            self._save_to_file("klucz_prywatny.pem", private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

            self._save_to_file("klucz_publiczny.pem", public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ))

            QMessageBox.information(self, "Sukces", "Klucze RSA zostały wygenerowane i zapisane.")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd podczas generowania kluczy RSA: {e}")

    def _sign_pdf_document(self):
        try:
            file_path = self._select_file("Wybierz plik PDF do podpisania", "Pliki PDF (*.pdf)")
            if not file_path:
                return

            pdf_hash = self._calculate_pdf_hash(file_path)

            private_key = self._load_private_key("klucz_prywatny.pem")
            signature = private_key.sign(
                pdf_hash,
                padding.PSS(
                    mgf=padding.MGF1(SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                SHA256()
            )

            self._save_to_file(file_path + ".sig", signature)
            QMessageBox.information(self, "Sukces", f"Dokument PDF został podpisany. Podpis zapisano jako {file_path}.sig")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd podczas podpisywania PDF: {e}")

    def _verify_pdf_signature(self):
        try:
            file_path = self._select_file("Wybierz plik PDF do weryfikacji", "Pliki PDF (*.pdf)")
            signature_path = self._select_file("Wybierz plik z podpisem", "Pliki z podpisem (*.sig)")

            if not file_path or not signature_path:
                return

            pdf_hash = self._calculate_pdf_hash(file_path)

            public_key = self._load_public_key("klucz_publiczny.pem")
            signature = self._read_file(signature_path)

            public_key.verify(
                signature,
                pdf_hash,
                padding.PSS(
                    mgf=padding.MGF1(SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                SHA256()
            )

            QMessageBox.information(self, "Sukces", "Podpis jest prawidłowy.")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd podczas weryfikacji podpisu: {e}")

    def _load_certificate(self):
        try:
            cert_path = self._select_file("Wybierz certyfikat X.509", "Pliki certyfikatów (*.pem *.crt)")
            if not cert_path:
                return

            cert = load_pem_x509_certificate(self._read_file(cert_path))

            details = f"""
Wystawca: {cert.issuer.rfc4514_string()}
Podmiot: {cert.subject.rfc4514_string()}
Ważny od: {cert.not_valid_before.isoformat()} UTC
Ważny do: {cert.not_valid_after.isoformat()} UTC
Algorytm podpisu: {cert.signature_algorithm_oid._name}
"""
            QMessageBox.information(self, "Wynik", details)
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd podczas ładowania certyfikatu: {e}")

    def _select_file(self, dialog_title, file_filter):
        file_path, _ = QFileDialog.getOpenFileName(self, dialog_title, "", file_filter)
        return file_path

    def _calculate_pdf_hash(self, file_path):
        reader = PdfReader(file_path)
        pdf_text = ''.join(page.extract_text() for page in reader.pages if page.extract_text())
        digest = hashes.Hash(SHA256())
        digest.update(pdf_text.encode())
        return digest.finalize()

    def _load_private_key(self, path):
        return load_pem_private_key(self._read_file(path), password=None)

    def _load_public_key(self, path):
        return load_pem_public_key(self._read_file(path))

    def _read_file(self, path):
        with open(path, "rb") as file:
            return file.read()

    def _save_to_file(self, path, data):
        with open(path, "wb") as file:
            file.write(data)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Application()
    window.show()
    sys.exit(app.exec_())
