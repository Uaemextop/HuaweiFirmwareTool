"""
Build script for creating Windows executable using PyInstaller
"""

import PyInstaller.__main__
import os
import shutil

def build_exe():
    """Build standalone Windows executable"""

    # Clean previous builds
    if os.path.exists('build'):
        shutil.rmtree('build')
    if os.path.exists('dist'):
        shutil.rmtree('dist')

    # PyInstaller arguments
    args = [
        'src/main.py',
        '--name=ONT-Flasher-GUI',
        '--onefile',
        '--windowed',
        '--icon=resources/icon.ico' if os.path.exists('resources/icon.ico') else '',
        '--add-data=resources:resources',
        '--noconsole',
        '--clean',
        '--noconfirm',
        # Additional options for Windows 11
        '--version-file=version_info.txt' if os.path.exists('version_info.txt') else '',
        '--uac-admin',  # Request admin privileges
    ]

    # Remove empty strings
    args = [arg for arg in args if arg]

    print("Building Windows executable...")
    print(f"Arguments: {args}")

    # Run PyInstaller
    PyInstaller.__main__.run(args)

    print("\nBuild complete!")
    print("Executable location: dist/ONT-Flasher-GUI.exe")

if __name__ == '__main__':
    build_exe()
