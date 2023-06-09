from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import datetime
import threading


class FileSelector:
    def __init__(self, root):
        self.root = root
        self.filename = []

        self.select_btn = tk.Button(
            self.root,
            text="파일 선택",
            command=self.select_files
        )
        self.select_btn.pack(pady=10)

    def select_files(self):
        self.filename = filedialog.askopenfilenames()


class CryptoProcessor:
    def __init__(self, root):
        self.root = root

        self.mode_var = tk.StringVar(value="기법선택")
        self.mode_var.trace("w", self.mode_changed)
        self.mode_var1 = tk.StringVar(value="기법선택")
        self.mode_var1.trace("w", self.mode_changed)

        self.mode_label = tk.Label(self.root, text="암호화/복호화 기법 선택")
        self.mode_label.pack()

        self.mode_menu = tk.OptionMenu(self.root, self.mode_var, "기법선택", "DES암호화", "AES암호화", "3DES암호화")
        self.mode_menu.pack()

        self.mode_menu1 = tk.OptionMenu(self.root, self.mode_var1, "기법선택", "DES복호화", "AES복호화", "3DES복호화")
        self.mode_menu1.pack()

    def mode_changed(self, *args):
        mode = self.mode_var.get()
        mode1 = self.mode_var1.get()
        if mode != "기법선택" and mode1 != "기법선택":
            self.mode_var.set("기법선택")
            self.mode_var1.set("기법선택")
            messagebox.showwarning("오류!", "암호화와 복호화 중 한 가지를 선택해주세요.")


class PasswordInput:
    def __init__(self, root):
        self.root = root

        self.password_label = tk.Label(self.root, text="비밀번호 입력")
        self.password_label.pack()

        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=10)
    def get_password(self):
            password = self.password_entry.get()
            if not password:
                # 기본 암호 설정 (예: "default_password")
                password = "abcdef0123456789"
            return password


class ScheduleTask:
    def __init__(self, root, callback):
        self.root = root
        self.callback = callback

        self.schedule_label = tk.Label(self.root, text="일정 시간 후 실행")
        self.schedule_label.pack()

        self.time_entry = tk.Entry(self.root)
        self.time_entry.pack()

        self.schedule_btn = tk.Button(
            self.root,
            text="일정 시간 후 실행",
            command=self.schedule_execution
        )
        self.schedule_btn.pack(pady=10)

    def schedule_execution(self):
        time_str = self.time_entry.get()
        if not time_str:
            self.callback()
            return

        try:
            scheduled_time = datetime.datetime.strptime(time_str, "%H:%M:%S").time()
        except ValueError:
            messagebox.showwarning("오류!", "올바른 시간 형식을 입력해주세요. (HH:MM:SS)")
            return

        current_time = datetime.datetime.now().time()
        time_diff = datetime.datetime.combine(datetime.date.today(), scheduled_time) - datetime.datetime.combine(
            datetime.date.today(), current_time
        )
        time_diff_seconds = time_diff.total_seconds()

        if time_diff_seconds <= 0:
            messagebox.showwarning("오류!", "과거의 시간을 입력했습니다. 미래의 시간을 입력해주세요.")
            return

        self.root.after(int(time_diff_seconds * 1000), self.callback)


class CryptoApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("파일 암호화/복호화")

        self.file_selector = FileSelector(self.root)
        self.crypto_processor = CryptoProcessor(self.root)
        self.password_input = PasswordInput(self.root)
        self.schedule_task = ScheduleTask(self.root, self.execute_crypto)

        self.execute_btn = tk.Button(
            self.root,
            text="암호화/복호화 실행",
            command=self.execute_crypto
        )
        self.execute_btn.pack(pady=20)

        self.delete_checkbox = tk.Checkbutton(
            self.root,
            text="원본 파일 삭제",
            onvalue=1,
            offvalue=0
        )
        self.delete_checkbox.pack()

        self.root.mainloop()

    def execute_crypto(self):
        mode = self.crypto_processor.mode_var.get()
        password = self.password_input.get_password()

        if not password:
            # Use a default password if none is entered
            password = "default_password"

        try:
            password_bytes = password.encode()
            if len(password_bytes) != 8 and mode.startswith("DES"):
                messagebox.showwarning("오류!", "비밀번호는 8바이트여야 합니다.")
                return

            if len(password_bytes) != 16 and mode.startswith("AES"):
                messagebox.showwarning("오류!", "비밀번호는 16바이트여야 합니다.")
                return
        except UnicodeEncodeError:
            messagebox.showwarning("오류!", "올바른 문자열을 입력해주세요.")
            return

        if mode == "DES암호화":
            self.encrypt_file_DES(DES, password_bytes)
        elif mode == "AES암호화":
            self.encrypt_file_AES(AES, password_bytes)
        elif mode == "3DES암호화":
            self.encrypt_file_DES(DES3, password_bytes)
        elif mode == "DES복호화":
            self.decrypt_file_DES(DES, password_bytes)
        elif mode == "AES복호화":
            self.decrypt_file_AES(AES, password_bytes)
        elif mode == "3DES복호화":
            self.decrypt_file_DES(DES3, password_bytes)

    def encrypt_file_DES(self, cipher_algo, password_bytes):
        for filename in self.file_selector.filename:
            with open(filename, "rb") as f:
                plaintext = f.read()

            key = password_bytes
            iv = b"thisivv!"

            cipher = cipher_algo.new(key, cipher_algo.MODE_CBC, iv)
            padded_plaintext = pad(plaintext, cipher_algo.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)

            with open(filename + ".DESenc", "wb") as f:
                f.write(ciphertext)

            if self.delete_checkbox.get() == 1:
                # 원본 파일 삭제
                os.remove(filename)

            print(f"암호화된 파일: {filename + '.DESenc'}")
            print(f"암호화된 데이터 예시: {ciphertext[:16]}...")

        messagebox.showinfo('알림!!', 'DES로 암호화가 완료되었습니다!')

    def encrypt_file_AES(self, cipher_algo, password_bytes):
        for filename in self.file_selector.filename:
            with open(filename, "rb") as f:
                plaintext = f.read()

            key = password_bytes
            iv = b"thisisiv!123456"

            cipher = cipher_algo.new(key, cipher_algo.MODE_CBC, iv)
            padded_plaintext = pad(plaintext, cipher_algo.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)

            with open(filename + ".AESenc", "wb") as f:
                f.write(ciphertext)

            if self.delete_checkbox["variable"].get() == 1:
                # 원본 파일 삭제
                os.remove(filename)

            print(f"암호화된 파일: {filename + '.AESenc'}")
            print(f"암호화된 데이터 예시: {ciphertext[:16]}...")

        messagebox.showinfo('알림!!', 'AES로 암호화가 완료되었습니다!')

    def decrypt_file_DES(self, cipher_algo, password_bytes):
        for filename in self.file_selector.filename:
            if not filename.endswith(".DESenc"):
                continue

            with open(filename, "rb") as f:
                ciphertext = f.read()

            key = password_bytes
            iv = b"thisivv!"

            cipher = cipher_algo.new(key, cipher_algo.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, cipher_algo.block_size)

            decrypted_filename = filename[:-7]  # Remove ".DESenc" extension

            with open(decrypted_filename, "wb") as f:
                f.write(plaintext)

            if self.delete_checkbox["variable"].get() == 1:
                # 원본 파일 삭제
                os.remove(filename)

            print(f"복호화된 파일: {decrypted_filename}")
            print(f"복호화된 데이터 예시: {plaintext[:16]}...")

        messagebox.showinfo('알림!!', 'DES로 복호화가 완료되었습니다!')

    def decrypt_file_AES(self, cipher_algo, password_bytes):
        for filename in self.file_selector.filename:
            if not filename.endswith(".AESenc"):
                continue

            with open(filename, "rb") as f:
                ciphertext = f.read()

            key = password_bytes
            iv = b"thisisiv!123456"

            cipher = cipher_algo.new(key, cipher_algo.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, cipher_algo.block_size)

            decrypted_filename = filename[:-7]  # Remove ".AESenc" extension

            with open(decrypted_filename, "wb") as f:
                f.write(plaintext)

            if self.delete_checkbox["variable"].get() == 1:
                # 원본 파일 삭제
                os.remove(filename)

            print(f"복호화된 파일: {decrypted_filename}")
            print(f"복호화된 데이터 예시: {plaintext[:16]}...")

        messagebox.showinfo('알림!!', 'AES로 복호화가 완료되었습니다!')


if __name__ == "__main__":
    CryptoApp()
