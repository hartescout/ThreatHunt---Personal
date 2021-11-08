```Python
import os, py7zr, lzma

for file in os.listdir():
    if file.endswith(".7z"):
        with py7zr.SevenZipFile(file, 'r', password='fake') as archive:
            try:
                archive.extractall()
            # Wrong Password exception
            except lzma.LZMAError as e:
                print(e)
            # Missing password exception
            except py7zr.exceptions.PasswordRequired as e:
                print(e)
```
