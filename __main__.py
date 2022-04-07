#!/usr/bin/env python3

"""Main script which initializes the program"""


def main():
    """Function to initialize the app while also setting some kivy related settings"""

    import os
    import pathlib

    os.environ['KIVY_HOME'] = str(pathlib.Path(__file__).parent / "assets")
    """Location for kivy to save files and the core config file"""

    os.environ['KIVY_NO_ENV_CONFIG'] = '1'
    """Disables modifying kivy settings through env variables"""

    from kivy import Config
    Config.setall("kivy", {
        "default_font": [
            "NotoSans",
            "assets/fonts/NotoSans-Regular.ttf",
            "assets/fonts/NotoSans-Italic.ttf",
            "assets/fonts/NotoSans-Bold.ttf",
            "assets/fonts/NotoSans-BoldItalic.ttf"
        ],
        "window_icon": "assets/icon/ic_app_icon.png",
        "desktop": 1,
        "exit_on_escape": 0,
        "log_enable": 1,
        "log_level": "info",
        "log_maxfiles": 0
    })
    Config.setall("graphics", {
        "height": 600,
        "width": 800
    })
    Config.write()

    from code import CyberVault
    CyberVault().run()


if __name__ == "__main__":
    main()
else:
    raise ImportError("This script is not supposed to be imported into another program.")
