from cx_Freeze import setup, Executable

base = None
executables = [Executable("detector.py", base=base)]

packages = ["idna"]
options = {
    'build_exe': {

        'packages': packages,
    },

}

setup(
    name="Stegano detector",
    options=options,
    version="1.0.0",
    description='Program to detect if .pcap file has got steganography traffic',
    executables=executables
)
