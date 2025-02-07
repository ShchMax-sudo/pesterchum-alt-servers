# Windows-only cx_freeze setup file
from cx_Freeze import *
import sys

from version import buildVersion

if sys.version_info < (3, 0, 0):
    sys.exit("Python versions lower than 3 are not supported.")

def is_64bit() -> bool:
    return sys.maxsize > 2**32

base = None
if sys.platform == "win32":
    base = "Win32GUI"

    path = sys.path
    if is_64bit() == True:
        path.append(r"C:\Program Files (x86)\Windows Kits\10\Redist\10.0.22000.0\ucrt\DLLs\x64")
    elif is_64bit() == False:
        path.append(r"C:\Program Files (x86)\Windows Kits\10\Redist\10.0.22000.0\ucrt\DLLs\x86")
        
    print("Path = " + str(path))
    
includefiles = ["quirks",
                "smilies",
                "themes",
                "docs",
                "README.md",
                "LICENSE",
                "CHANGELOG.md",
                "PCskins.png",
                "Pesterchum.png",
                "logging.ini.example"]
build_exe_options = {
##    "includes": ["PyQt5.QtCore",
##                 "PyQt5.QtGui",
##                 "PyQt5.QtWidgets",
##                 "pygame",
##                 "feedparser",
##                 "magic",
##                 "ostools",
##                 "requests",
##                 "urllib",
##                 "pytwmn",
##                 "re",
##                 "oyoyo",
##                 "ssl"],
    "excludes": ['collections.sys',
        'collections._sre',
        'collections._json',
        'collections._locale',
        'collections._struct',
        'collections.array',
        'collections._weakref',
        'PyQt5.QtMultimedia',
        'PyQt5.QtDBus',
        'PyQt5.QtDeclarative',
        'PyQt5.QtHelp',
        'PyQt5.QtNetwork',
        'PyQt5.QtSql',
        'PyQt5.QtSvg',
        'PyQt5.QtTest',
        'PyQt5.QtWebKit',
#        'PyQt5.QtXml',
#        'PyQt5.QtXmlPatterns',
        'PyQt5.phonon',
        'PyQt5.QtAssistant',
        'PyQt5.QtDesigner',
        'PyQt5.QAxContainer',],
    "include_files": includefiles,
    "include_msvcr": True,  # cx_freeze copies 64-bit binaries always?
    "path": path            # Improved in 6.6, path to be safe
                            # VCRUNTIME140.dll <3
}

bdist_mac_options = {
    'iconfile': 'trayicon32.icns',
    'bundle_name': "Pesterchum"
}

description = "Pesterchum"
icon = "pesterchum.ico"

# See https://stackoverflow.com/questions/15734703/use-cx-freeze-to-create-an-msi-that-adds-a-shortcut-to-the-desktop
shortcut_table = [
    ("DesktopShortcut",        # Shortcut
     "DesktopFolder",          # Directory_
     "Pesterchum",             # Name
     "TARGETDIR",              # Component_
     "[TARGETDIR]pesterchum.exe",# Target
     None,                     # Arguments
     description,              # Description
     None,                     # Hotkey
     None,                     # Icon (Is inherited from pesterchum.exe)
     None,                     # IconIndex
     None,                     # ShowCmd
     'TARGETDIR'               # WkDir
     ),
    ("StartMenuShortcut",        # Shortcut
     "StartMenuFolder",          # Directory_
     "Pesterchum",             # Name
     "TARGETDIR",              # Component_
     "[TARGETDIR]pesterchum.exe",# Target
     None,                     # Arguments
     description,              # Description
     None,                     # Hotkey
     None,                     # Icon
     None,                     # IconIndex
     None,                     # ShowCmd
     'TARGETDIR'               # WkDir
     )
    ]

msi_data = {"Shortcut": shortcut_table}
bdist_msi_options = {'data': msi_data,
                     'summary_data': {
                         'comments': "FL1P",
                         'keywords': "Pesterchum"},
                     'upgrade_code': "{86740d75-f1f2-48e8-8266-f36395a2d77f}",
                     'add_to_path': False, # !!!
                     'all_users': False,
                     'install_icon': "pesterchum.ico"}

setup(
            name = "Pesterchum",
            version = buildVersion,
            url = "https://github.com/Dpeta/pesterchum-alt-servers",
            description = description,#"P3ST3RCHUM",
            options = {"build_exe": build_exe_options,
                       "bdist_msi": bdist_msi_options,
                       "bdist_mac": bdist_mac_options},
            executables = [Executable("pesterchum.py",
                                      base=base,
                                      icon=icon
                                      )])
