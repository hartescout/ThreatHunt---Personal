#!/usr/bin/python
import py7zr, os, lzma

pwd = input("Enter the password. If no password enter 'n/a': ")
directory = input("\nEnter full path to extract files to: ")
for file in os.listdir():
    if file.endswith(".7z"):
        if py7zr.SevenZipFile.needs_password():
                try:
                    print("Files will be extracted to ", directory)
                    os.mkdir(directory)
                except FileExistsError:
                    directory = input("\nDirectory or file exists, choose another. Enter full path of directory to extract the files: ")
                    print("Files will be extracted to ", directory)
                    pass
                except FileExistsError:
                    print("\n\n\nCheck filepath and try again.")
                    quit()
                pass
        for file in os.listdir():
                    with py7zr.SevenZipFile(file, 'r', password=pwd) as archive:
                        archive.extractall(path=directory)
    elif  py7zr.SevenZipFile.needs_password():
        with py7zr.SevenZipFile(file, 'r') as archive:
                try:
                    print("Files will be extracted to ", directory)
                    os.mkdir(directory)
                except FileExistsError:
                    directory = input("\nDirectory or file exists, choose another. Enter full path of directory to extract the files: ")
                    print("Files will be extracted to ", directory)
                    pass
                except FileExistsError:
                    print("\n\n\nCheck filepath and try again.")
                    quit()
                    pass
        for file in os.listdir():
                    with py7zr.SevenZipFile(file, 'r') as archive:
                        archive.extractall(path=directory)
    else: print("No 7z files present. Exiting.")
    quit()