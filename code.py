"""
Code for all the classes in Kivy
"""

import base64
import functools
import os
import pathlib
import sqlite3

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from kivy.app import App
from kivy.factory import Factory
from kivy.logger import Logger
from kivy.properties import ObjectProperty
from kivy.uix.screenmanager import ScreenManager, Screen


class CyberVault(App):

    def __init__(self, **kw):
        """Function which is run on initialization of the app"""

        super().__init__(**kw)
        Logger.info("CyberVault: Initializing the application")
        self.kv_file = str(pathlib.Path(self.directory) / "design.kv")
        self.db_con = sqlite3.connect(pathlib.Path(os.getenv("KIVY_HOME")) / "CyberVault.db")
        self.db_cur = self.db_con.cursor()
        self.db_cur.executescript("""
            CREATE TABLE IF NOT EXISTS masterpwd(test_bytes BLOB, salt BLOB);
            CREATE TABLE IF NOT EXISTS passwords(site_name TEXT, username TEXT, password TEXT);
        """)
        self.db_cur.execute("DELETE FROM masterpwd WHERE ROWID != 1")
        self.sm = ObjectProperty()
        self.setup = self.db_cur.execute("SELECT * FROM masterpwd").fetchone() is None
        self.fernet_key = None

    def build(self):
        self.sm = ScreenManager()
        if self.setup:
            Logger.debug("CyberVault: Loading SetupScreen")
            self.sm.add_widget(SetupScreen())
        else:
            Logger.debug("CyberVault: Loading VaultScreen")
            self.sm.add_widget(Factory.LockScreen())
        return self.sm

    def open_settings(self, *largs) -> None:
        """Overriding the open_settings() function to prevent opening settings on F1"""
        Logger.debug("CyberVault: Ignoring F1 to open_settings()")


class SetupScreen(Screen):

    def setup_tasks(self, pwd1, pwd2):
        password = pwd1.text.encode()
        pwd1.text = pwd2.text = ""
        app = App.get_running_app()
        Logger.debug("CyberVault: Dropping the tables if they exist and creating new tables")
        app.db_cur.executescript("""
            DROP TABLE IF EXISTS masterpwd;
            DROP TABLE IF EXISTS passwords;
            CREATE TABLE IF NOT EXISTS masterpwd(test_bytes BLOB, salt BLOB);
            CREATE TABLE IF NOT EXISTS passwords(site_name TEXT, username TEXT, password TEXT);
        """)

        Logger.debug("CyberVault: Generating bytes to salt the password in key-deriving function")
        salt = os.urandom(32)

        Logger.debug("CyberVault: Generating a PBKDF2HMAC instance(key-deriving function)")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=150000)

        Logger.debug("CyberVault: Deriving a key from the key-deriving function")
        app.fernet_key = Fernet(base64.urlsafe_b64encode(kdf.derive(password)))
        del password
        Logger.debug("CyberVault: Creating a test token using the Fernet key which can be generated from the pwd")
        fernet_token = app.fernet_key.encrypt(b'test_password')

        Logger.debug("CyberVault: Storing the test token and the salt in database")
        app.db_cur.execute("INSERT INTO masterpwd VALUES(?, ?)", (fernet_token, salt))
        app.db_con.commit()

        popup = Factory.FinishedSetupPopup()
        popup.bind(on_dismiss=self.dismiss_popup)
        popup.open()

    def dismiss_popup(self, _):
        self.manager.switch_to(VaultScreen())
        return False


class VaultScreen(Screen):

    def fetch_passwords(self):
        app = App.get_running_app()
        data = []
        Logger.debug("CyberVault: Fetching passwords and adding to RecycleView data")
        for password in app.db_cur.execute("SELECT ROWID, * FROM passwords"):
            data.append({
                "text": f"{password[1]}: {password[2]}",
                "on_press": functools.partial(self.view_password, password[0])
            })
        return data

    def view_password(self, rowid):
        app = App.get_running_app()
        data = list(app.db_cur.execute("SELECT * FROM passwords WHERE ROWID = (?)", (rowid,)).fetchone())
        view = Factory.ViewPwdScreen()
        view.title_text.text += str(rowid)
        view.pwd.text = base64.urlsafe_b64decode(app.fernet_key.decrypt(data.pop().encode('utf-8'))).decode()
        view.site_name.text, view.username.text = map(str, data)
        self.manager.transition.direction = "left"
        self.manager.switch_to(view)


class AddPwdScreen(Screen):

    def save_password(self, pwd1, pwd2, reqd_data):
        pwd1.text = pwd2.text = ""
        app = App.get_running_app()
        site_name, username, pwd1, pwd2 = reqd_data
        Logger.debug("CyberVault: Both the passwords matched")
        Logger.debug("CyberVault: Adding values to db")
        b64_safe_pwd = base64.urlsafe_b64encode(pwd1.encode())
        encrypted_pwd = App.get_running_app().fernet_key.encrypt(b64_safe_pwd).decode()
        del pwd1, pwd2, reqd_data
        app.db_cur.execute("INSERT INTO passwords VALUES (?, ?, ?)", (
            site_name,
            username,
            encrypted_pwd
        ))
        app.db_con.commit()
        self.manager.transition.direction = "left"
        self.manager.switch_to(VaultScreen())


class ViewPwdScreen(Screen):

    def delete_pwd(self, _):
        app = App.get_running_app()
        rowid = int(self.title_text.text.split("#").pop())
        app.db_cur.execute("DELETE FROM passwords WHERE rowid == (?)", (rowid,))
        app.db_con.commit()
        self.manager.switch_to(VaultScreen())

    def edit_pwd(self):
        data = (self.site_name.text, self.username.text, self.pwd.text, self.pwd.text)
        edit_pass = EditPwdScreen()
        edit_pass.site_name.text, edit_pass.username.text, edit_pass.pwd1.text, edit_pass.pwd2.text = data
        edit_pass.title_text.text += self.title_text.text.split("#").pop()
        self.manager.switch_to(edit_pass)


class LockScreen(Screen):

    def authenticate_user(self, button, pwd):
        password = pwd.text
        pwd.text = ""
        app = App.get_running_app()
        fernet_token, salt = app.db_cur.execute("SELECT * FROM masterpwd").fetchone()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=150000)
        app.fernet_key = Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))
        del password

        try:
            app.fernet_key.decrypt(fernet_token)
            Logger.debug("CyberVault: Decrypted the encrypted token")
            button.disabled = True
            self.manager.switch_to(Factory.VaultScreen())
        except InvalidToken:
            Logger.debug("CyberVault: Invalid input")
            self.ids.pwd.parent.add_widget(Factory.InvalidPwdLabel())


class EditPwdScreen(Screen):
    
    def save_password(self, pwd1, pwd2, reqd_data):
        pwd1.text = pwd2.text = ""
        app = App.get_running_app()
        site_name, username, pwd1, pwd2 = reqd_data
        Logger.debug("CyberVault: Both the passwords matched")
        Logger.debug("CyberVault: Updating values in the db")
        b64_safe_pwd = base64.urlsafe_b64encode(pwd1.encode())
        encrypted_pwd = App.get_running_app().fernet_key.encrypt(b64_safe_pwd).decode()
        del pwd1, pwd2, reqd_data
        app.db_cur.execute("UPDATE passwords SET site_name = (?), username = (?), password = (?) WHERE ROWID == (?)", (
            site_name,
            username,
            encrypted_pwd,
            self.title_text.text.split("#").pop()
        ))
        app.db_con.commit()
        self.manager.transition.direction = "left"
        self.manager.switch_to(VaultScreen())
