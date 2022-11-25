import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QPushButton, QLabel, QMessageBox, QWidget, QGridLayout, QFileDialog, QHBoxLayout, QVBoxLayout, QTabWidget

from envelope import Envelope, open_envelope, VerificationException
from rsa import rsa_gen_keys, RSAKey

class MainWidget(QWidget):
    def __init__(self, parent=None):
        super(MainWidget, self).__init__(parent)
        tabWidget = QTabWidget()

        tabWidget.addTab(KeysTab(self), "Key management")
        self.pubKey = None
        self.secKey = None

        tabWidget.addTab(EncryptTab(self), "Encrypt")
        self.otherPubKey = None
        self.toEncryptFilepath = None

        tabWidget.addTab(DecryptTab(self), "Decrypt")
        self.outFilePath = None

        layout = QVBoxLayout()
        layout.addWidget(tabWidget)
        self.setLayout(layout)
        self.setWindowTitle("Digital Envelope")


class KeysTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        grid = QGridLayout(self)

        leftBox = QVBoxLayout()
        centerBox = QVBoxLayout()
        rightBox = QVBoxLayout()
        grid.addLayout(leftBox, 0, 0)
        grid.addLayout(centerBox, 0, 1)
        grid.addLayout(rightBox, 0, 2)

        # button to generate RSA keys
        rsa_genkeys_btn = QPushButton("Generate RSA key pair")
        rsa_genkeys_btn.clicked.connect(self.on_rsa_genkeys_btn_clicked)
        centerBox.addWidget(rsa_genkeys_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        # label with status of user's keys
        self.userKeyStatusLbl = QLabel("Your key pair is missing")
        centerBox.addWidget(self.userKeyStatusLbl, alignment=Qt.AlignmentFlag.AlignCenter)
        # buttons to select user's keys
        selUserPubKeyBtn = QPushButton("Select your public key")
        selUserPubKeyBtn.clicked.connect(self.on_selUserPubKeyBtn_clicked)
        centerBox.addWidget(selUserPubKeyBtn, alignment=Qt.AlignmentFlag.AlignCenter)
        selUserSecKeyBtn = QPushButton("Select your secret key")
        selUserSecKeyBtn.clicked.connect(self.on_selUserSecKeyBtn_clicked)
        centerBox.addWidget(selUserSecKeyBtn, alignment=Qt.AlignmentFlag.AlignCenter)

    def on_rsa_genkeys_btn_clicked(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.Directory)
        dialog.setViewMode(QFileDialog.Detail)

        fileNames = None
        if dialog.exec():
            fileNames = dialog.selectedFiles()

        if fileNames is not None:
            path = fileNames[0]
            self.parent.pubKey, self.parent.secKey = rsa_gen_keys(1024)
            self.parent.pubKey.save(os.path.join(path, "pub.key"))
            self.parent.secKey.save(os.path.join(path, "sec.key"))
            self.userKeyStatusLbl.setText("Your keys are ready to be used")
        else:
            showMsg("You must select a destination to save the generated keys")
            return

    def on_selUserPubKeyBtn_clicked(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)

        fileNames = None
        if dialog.exec():
            fileNames = dialog.selectedFiles()

        if fileNames is not None:
            path = fileNames[0]
            self.parent.pubKey = RSAKey.from_file(path)
            if self.parent.secKey is not None:
                self.userKeyStatusLbl.setText("Your keys are ready to be used")

    def on_selUserSecKeyBtn_clicked(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)

        fileNames = None
        if dialog.exec():
            fileNames = dialog.selectedFiles()

        if fileNames is not None:
            path = fileNames[0]
            self.parent.secKey = RSAKey.from_file(path)
            if self.parent.pubKey is not None:
                self.userKeyStatusLbl.setText("Your keys are ready to be used")

class EncryptTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        grid = QGridLayout(self)

        leftBox = QVBoxLayout()
        rightBox = QVBoxLayout()
        grid.addLayout(leftBox, 0, 0)
        grid.addLayout(rightBox, 0, 1)

        # ---------- LEFT ----------
        # button to select recipient's RSA keys
        selRecipPubKeyBtn = QPushButton("Select recipient's public key")
        selRecipPubKeyBtn.clicked.connect(self.on_selRecipPubKeyBtn_clicked)
        leftBox.addWidget(selRecipPubKeyBtn, alignment=Qt.AlignmentFlag.AlignCenter)
        self.otherPubKey = None
        # label with status of recipient's key
        self.recipKeyStatusLbl = QLabel("Missing recipient's public key")
        leftBox.addWidget(self.recipKeyStatusLbl, alignment=Qt.AlignmentFlag.AlignCenter)

        # ---------- RIGHt ----------
        # button to choose a file for encryption
        choose_file_btn = QPushButton("Select input file")
        choose_file_btn.clicked.connect(self.on_choose_file_btn_clicked)
        rightBox.addWidget(choose_file_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        # label with chosen filepath
        self.text_filepath = QLabel("No file selected")
        rightBox.addWidget(self.text_filepath, alignment=Qt.AlignmentFlag.AlignCenter)
        # create envelope button
        createEnvelopeBtn = QPushButton("Create envelope")
        createEnvelopeBtn.clicked.connect(self.on_createEnvelopeBtn_clicked)
        rightBox.addWidget(createEnvelopeBtn, alignment=Qt.AlignmentFlag.AlignCenter)

    def on_selRecipPubKeyBtn_clicked(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)

        fileNames = None
        if dialog.exec():
            fileNames = dialog.selectedFiles()

        if fileNames is not None:
            path = fileNames[0]
            self.parent.otherPubKey = RSAKey.from_file(path)
            self.recipKeyStatusLbl.setText("Recipient's public key is selected")

    def on_choose_file_btn_clicked(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)

        fileNames = None
        if dialog.exec():
            fileNames = dialog.selectedFiles()

        if fileNames is not None:
            self.parent.toEncryptFilepath = fileNames[0]
            self.text_filepath.setText(fileNames[0])
            print(self.parent.toEncryptFilepath)

    def on_createEnvelopeBtn_clicked(self):
        if self.parent.otherPubKey is None:
            showMsg("You must select recipient's public key first")
            return
        if self.parent.secKey is None:
            showMsg("You must select your secret key first")
            return
        if self.parent.toEncryptFilepath is None:
            showMsg("You must select input file first")
            return

        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)

        fileNames = None
        if dialog.exec():
            fileNames = dialog.selectedFiles()

        if fileNames is not None:
            path = fileNames[0]
            with open(self.parent.toEncryptFilepath, 'rb') as f:
                data = f.read()
            envlp = Envelope.create(data, self.parent.otherPubKey, self.parent.secKey)
            envlp.save(path)

            showMsg(f"Envelope was saved to {path}")


class DecryptTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        grid = QGridLayout(self)

        leftBox = QVBoxLayout()
        rightBox = QVBoxLayout()
        grid.addLayout(leftBox, 0, 0)
        grid.addLayout(rightBox, 0, 1)

        # ---------- LEFT ----------
        # button to select senders's pub key
        selSendPubKeyBtn = QPushButton("Select sender's public key")
        selSendPubKeyBtn.clicked.connect(self.on_selSendPubKeyBtn_clicked)
        leftBox.addWidget(selSendPubKeyBtn, alignment=Qt.AlignmentFlag.AlignCenter)
        self.otherPubKey = None
        # label with status of senders's key
        self.sendKeyStatusLbl = QLabel("Missing sender's public key")
        leftBox.addWidget(self.sendKeyStatusLbl, alignment=Qt.AlignmentFlag.AlignCenter)

        # ---------- RIGHT ----------
        # path to save data from envelope
        selOutFile = QPushButton("Select output file")
        selOutFile.clicked.connect(self.on_selOutFile_clicked)
        rightBox.addWidget(selOutFile, alignment=Qt.AlignmentFlag.AlignCenter)

        # open envelope button
        openEnvelopeBtn = QPushButton("Open (verify) envelope")
        openEnvelopeBtn.clicked.connect(self.on_openEnvelopeBtn_clicked)
        rightBox.addWidget(openEnvelopeBtn, alignment=Qt.AlignmentFlag.AlignCenter)

    def on_selSendPubKeyBtn_clicked(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)

        fileNames = None
        if dialog.exec():
            fileNames = dialog.selectedFiles()

        if fileNames is not None:
            path = fileNames[0]
            self.parent.otherPubKey = RSAKey.from_file(path)
            self.sendKeyStatusLbl.setText("Sender's public key is selected")

    def on_selOutFile_clicked(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)

        fileNames = None
        if dialog.exec():
            fileNames = dialog.selectedFiles()

        if fileNames is not None:
            self.parent.outFilePath = fileNames[0]

    def on_openEnvelopeBtn_clicked(self):
        if self.parent.otherPubKey is None:
            showMsg("You must select sender's public key first")
            return
        if self.parent.secKey is None:
            showMsg("You must select your secret key first")
            return
        if self.parent.outFilePath is None:
            showMsg("You must select output file first")
            return
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)

        fileNames = None
        if dialog.exec():
            fileNames = dialog.selectedFiles()

        if fileNames is not None:
            envlp = Envelope.from_file(fileNames[0])
            try:
                data = open_envelope(envlp, self.parent.otherPubKey, self.parent.secKey)
            except (VerificationException, AssertionError):
                showMsg("Envelope signature could not be verified")
                return

            with open(self.parent.outFilePath, 'wb') as f:
                f.write(data)
            showMsg(f"Envelope was verified and data was written to {self.parent.outFilePath}")

def showMsg(msg: str):
    msgBox = QMessageBox()
    msgBox.setText(msg)
    msgBox.exec()

if __name__ == "__main__":
    app = QApplication([])

    w = MainWidget()
    w.resize(800, 500)
    w.show()

    app.exec()

