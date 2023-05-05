import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
from tkinter import messagebox
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.geometry("300x300")
        self.root.title("파일 암호화/복호화")

        # 파일 선택 버튼
        self.file_select_button = tk.Button(
            self.root,
            text="파일 선택",
            command=self.select_file
        )
        self.file_select_button.pack(pady=10)

        # Run 버튼 생성
        self.run_btn = tk.Button(self.root, text="Run", command=self.run)
        self.run_btn.pack()

        # 암호화/복호화 선택 콤보박스 생성
        self.mode_var = tk.StringVar(value="기법선택")
        self.mode_var1 = tk.StringVar(value="기법선택")
        self.mode_enc = ttk.Combobox(self.root, values=["DES암호화", "AES암호화"], textvariable=self.mode_var)
        self.mode_dec = ttk.Combobox(self.root, values=["DES복호화", "AES복호화"], textvariable=self.mode_var1)

        self.enc_var=tk.IntVar()
        self.enc=tk.Checkbutton(self.root, text="암호화",command=self.show_hide_combobox, variable=self.enc_var)
        self.enc.pack()
        
        self.dec_var=tk.IntVar()
        self.dec=tk.Checkbutton(self.root, text="복호화",command=self.show_hide_combobox, variable=self.dec_var)
        self.dec.pack()

    def show_hide_combobox(self):
        if self.enc_var.get()==1:
            self.mode_enc.pack()
        else:
            self.mode_enc.pack_forget()
        if self.dec_var.get()==1:
            self.mode_dec.pack()
        else:
            self.mode_dec.pack_forget()

    def run(self):
        # 파일이 선택되지 않은 경우 경고 메시지 출력
        if not hasattr(self, "filename"):
            messagebox.showwarning("오류!", "파일이 선택되지 않았습니다.")
            return
        
        # 선택된 작업에 따라 암호화/복호화 함수 호출
        if self.mode_var.get() == "DES암호화":
            self.encrypt_file_DES(DES)
            self.mode_var = tk.StringVar(value="기법선택")
        elif self.mode_var1.get() == "DES복호화":
            self.decrypt_file_DES(DES)
            self.mode_var1 = tk.StringVar(value="기법선택")
        elif self.mode_var.get() == "AES암호화":
            self.mode_var = tk.StringVar(value="기법선택")
            self.encrypt_file_AES(AES)
        elif self.mode_var1.get() == "AES복호화":
            self.decrypt_file_AES(AES)
            self.mode_var1 = tk.StringVar(value="기법선택")
        # 기법이 선택되었지 않은 경우 경고 메세지 출력
        elif self.mode_var.get() == "기법선택":
            messagebox.showwarning("오류!","기법을 선택해주세요!")
        elif self.mode_var1.get() == "기법선택":
            messagebox.showwarning("오류!","기법을 선택해주세요!") 

    def select_file(self):
        self.filename = filedialog.askopenfilenames(
            initialdir="/",
            title="파일을 선택해 주세요!",
            filetypes=(("Text files", "*.txt*"), ("all files", "*.*"))
        )

    def encrypt_file_DES(self, cipher_algo):
        for filename in self.filename:
            with open(filename, "rb") as f:
                plaintext = f.read()

            key = b"thiskey!"
            iv = b"thisivv!"

            cipher = cipher_algo.new(key, cipher_algo.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext, cipher_algo.block_size))

            with open(filename + ".DESenc", "wb") as f:
                f.write(ciphertext)
        messagebox.showinfo('알림!!','DES로 암호화가 완료되었습니다!')


    def decrypt_file_DES(self, cipher_algo):
        for filename in self.filename:
            with open(filename, "rb") as f:
                ciphertext = f.read()

            key = b"thiskey!"
            iv = b"thisivv!"

            cipher = cipher_algo.new(key, cipher_algo.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), cipher_algo.block_size)

            with open(filename[:-6], "wb") as f:
                f.write(decrypted)
        messagebox.showinfo('알림!!','DES로 복호화가 완료되었습니다!')

    def encrypt_file_AES(self, cipher_algo):
        for filename in self.filename:
            with open(filename, "rb") as f:
                plaintext = f.read()
        
            key = b'0123456789abcdef'
            iv = b'abcdef0123456789'

            cipher = cipher_algo.new(key, cipher_algo.MODE_CBC, iv)
            padded_plaintext = pad(plaintext, cipher_algo.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)

            with open(filename + ".AESenc", "wb") as f:
                f.write(ciphertext)
        messagebox.showinfo('알림!!','AES로 암호화가 완료되었습니다!')

    def decrypt_file_AES(self, cipher_algo):
        for filename in self.filename:
            with open(filename, "rb") as f:
                ciphertext = f.read()

            key = b'0123456789abcdef'
            iv = b'abcdef0123456789'

            cipher = cipher_algo.new(key, cipher_algo.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted_padded, cipher_algo.block_size)

            with open(filename[:-6], "wb") as f:
                f.write(decrypted)

        messagebox.showinfo('알림!!','AES로 복호화가 완료되었습니다!')

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()