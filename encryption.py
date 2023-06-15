import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
import os
import datetime


class CryptoApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.geometry("600x400")
        self.root.title("파일 암호화/복호화 프로그램")
        self.file_selector = FileSelector(self.root)
        self.file_selector.pack()

        self.crypto_processor = CryptoProcessor(self.root)
        self.crypto_processor.pack()

        self.password_input = PasswordInput(self.root)
        self.password_input.pack()

        self.schedule_time = ScheduleTime(self.root)
        self.schedule_time.pack()

        self.execute_button = tk.Button(self.root, text="실행", command=self.execute_crypto)
        self.execute_button.pack()

        self.root.mainloop()

    def encrypt_file_DES(self, filename, password):
        key = password.encode("utf-8").ljust(8, b"\x00")[:8]
        cipher = DES.new(key, DES.MODE_ECB)

        with open(filename, "rb") as file:
            plaintext = file.read()

        encrypted_ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

        encrypted_filename = filename + ".cas"
        with open(encrypted_filename, "wb") as file:
            file.write(encrypted_ciphertext)

        return encrypted_filename
    
    def encrypt_file_AES(self, filename, password):
        key = password.encode("utf-8").ljust(16, b"\x00")[:16]
        cipher = AES.new(key, AES.MODE_ECB)

        with open(filename, "rb") as file:
            plaintext = file.read()

        encrypted_ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        encrypted_filename = filename + ".cas"
        with open(encrypted_filename, "wb") as file:
            file.write(encrypted_ciphertext)

        return encrypted_filename

    def encrypt_file_3DES(self, filename, password):
        key = password.encode("utf-8").ljust(24, b"\x00")[:24]
        cipher = DES3.new(key, DES3.MODE_ECB)

        with open(filename, "rb") as file:
            plaintext = file.read()

        encrypted_ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))

        encrypted_filename = filename + ".cas"
        with open(encrypted_filename, "wb") as file:
            file.write(encrypted_ciphertext)

        return encrypted_filename

    def decrypt_file_DES(self, filename, password):
        key = password.encode("utf-8").ljust(8, b"\x00")[:8]
        cipher = DES.new(key, DES.MODE_ECB)

        with open(filename, "rb") as file:
            ciphertext = file.read()

        decrypted_plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

        decrypted_filename = filename[:-4]
        with open(decrypted_filename, "wb") as file:
            file.write(decrypted_plaintext)

        return decrypted_filename

    def decrypt_file_AES(self, filename, password):
        key = password.encode("utf-8").ljust(16, b"\x00")[:16]
        cipher = AES.new(key, AES.MODE_ECB)

        with open(filename, "rb") as file:
            ciphertext = file.read()

        decrypted_plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        decrypted_filename = filename[:-4]
        with open(decrypted_filename, "wb") as file:
            file.write(decrypted_plaintext)

        return decrypted_filename

    def decrypt_file_3DES(self, filename, password):
        key = password.encode("utf-8").ljust(24, b"\x00")[:24]
        cipher = DES3.new(key, DES3.MODE_ECB)

        with open(filename, "rb") as file:
            ciphertext = file.read()

        decrypted_plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)

        decrypted_filename = filename[:-4]
        with open(decrypted_filename, "wb") as file:
            file.write(decrypted_plaintext)

        return decrypted_filename

    def get_original_extension(self, filename):
        _, ext = os.path.splitext(filename)
        return ext

    def execute_crypto(self):
        selected_files = self.file_selector.get_selected_files()
        selected_mode = self.crypto_processor.get_selected_mode()
        scheduled_time = self.schedule_time.get_scheduled_time()

        if not selected_files:
            messagebox.showerror("Error", "파일을 선택해주세요.")
            return

        if selected_mode == "기법선택":
            messagebox.showerror("Error", "암호화 또는 복호화 기법을 선택해주세요.")
            return
        

        current_time = datetime.datetime.now()

        if scheduled_time and current_time < scheduled_time:
            time_diff = scheduled_time - current_time
            self.root.after(int(time_diff.total_seconds() * 1000), self.execute_crypto_now)
        else:
            self.execute_crypto_now()

    def execute_crypto_now(self):
        selected_files = self.file_selector.get_selected_files()
        selected_mode = self.crypto_processor.get_selected_mode()
        password, delete_original = self.password_input.get_password(selected_mode)

        if not selected_files:
            messagebox.showerror("Error", "파일을 선택해주세요.")
            return

        if selected_mode == "기법선택":
            messagebox.showerror("Error", "암호화 또는 복호화 기법을 선택해주세요.")
            return

        for file in selected_files:
            try:
                if selected_mode == "DES암호화":
                    encrypted_filename = self.encrypt_file_DES(file, password)
                    messagebox.showinfo("암호화 완료", f"{file}이(가) 암호화되었습니다. 암호화된 파일: {encrypted_filename}")

                elif selected_mode == "AES암호화":
                    encrypted_filename = self.encrypt_file_AES(file, password)
                    messagebox.showinfo("암호화 완료", f"{file}이(가) 암호화되었습니다. 암호화된 파일: {encrypted_filename}")

                elif selected_mode == "3DES암호화":
                    encrypted_filename = self.encrypt_file_3DES(file, password)
                    messagebox.showinfo("암호화 완료", f"{file}이(가) 암호화되었습니다. 암호화된 파일: {encrypted_filename}")

                elif selected_mode == "DES복호화":
                    decrypted_filename = self.decrypt_file_DES(file, password)
                    messagebox.showinfo("복호화 완료", f"{file}이(가) 복호화되었습니다. 복호화된 파일: {decrypted_filename}")

                elif selected_mode == "AES복호화":
                    decrypted_filename = self.decrypt_file_AES(file, password)
                    messagebox.showinfo("복호화 완료", f"{file}이(가) 복호화되었습니다. 복호화된 파일: {decrypted_filename}")

                elif selected_mode == "3DES복호화":
                    decrypted_filename = self.decrypt_file_3DES(file, password)
                    messagebox.showinfo("복호화 완료", f"{file}이(가) 복호화되었습니다. 복호화된 파일: {decrypted_filename}")

                if delete_original:
                    os.remove(file)

            except Exception as e:
                messagebox.showerror("Error", f"처리 중 오류가 발생했습니다: {str(e)}")


class FileSelector(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.selected_files = []

        self.select_button = tk.Button(self, text="파일 선택", command=self.select_files)
        self.select_button.pack()

        self.selected_files_label = tk.Label(self, text="선택한 파일: ")
        self.selected_files_label.pack()

    def select_files(self):
        self.selected_files = filedialog.askopenfilenames()
        self.update_selected_files_label()

    def update_selected_files_label(self):
        file_names = ", ".join(self.selected_files) if self.selected_files else "없음"
        self.selected_files_label.configure(text="선택한 파일: " + file_names)

    def get_selected_files(self):
        return self.selected_files


class CryptoProcessor(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.mode_var1 = tk.StringVar()
        self.mode_var1.set("기법선택")

        self.mode_label = tk.Label(self, text="암호화/복호화 기법 선택")
        self.mode_label.pack()

        self.mode_menu = tk.OptionMenu(self, self.mode_var1, "기법선택", "DES암호화", "AES암호화", "3DES암호화", "DES복호화", "AES복호화", "3DES복호화")
        self.mode_menu.pack()

    def get_selected_mode(self):
        return self.mode_var1.get()


class PasswordInput(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.password_var = tk.StringVar()
        self.password_var.set("")

        self.password_label = tk.Label(self, text="암호 입력")
        self.password_label.pack()

        self.password_entry = tk.Entry(self, textvariable=self.password_var, show="*")
        self.password_entry.pack()

        self.delete_original_var = tk.BooleanVar()
        self.delete_original_var.set(False)

        self.delete_original_checkbutton = tk.Checkbutton(
            self, text="원본 파일 삭제", variable=self.delete_original_var
        )
        self.delete_original_checkbutton.pack()

    def get_password(self, selected_mode):
        password = self.password_var.get()
        delete_original = self.delete_original_var.get()

        if selected_mode == "기법선택":
            password = ""
            delete_original = False

        return password, delete_original


class ScheduleTime(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        self.schedule_label = tk.Label(self, text="예약 시간 (YYYY-MM-DD HH:MM:SS):")
        self.schedule_label.pack()

        self.schedule_entry = tk.Entry(self)
        self.schedule_entry.pack()

    def get_scheduled_time(self):
        scheduled_time_str = self.schedule_entry.get()
        if scheduled_time_str:
            try:
                scheduled_time = datetime.datetime.strptime(scheduled_time_str, "%Y-%m-%d %H:%M:%S")
                return scheduled_time
            except ValueError:
                messagebox.showerror("Error", "올바른 날짜 및 시간 형식을 입력해주세요.")
        return None


if __name__ == "__main__":
    app = CryptoApp()
