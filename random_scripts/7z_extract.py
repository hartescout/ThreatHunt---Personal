#!/usr/bin/python
import py7zr, os, errno
#import os, errno

pwd = input("Enter the password. If no password enter 'n/a': ")
directory = input("\nEnter full path to extract files to: ")

if (pwd != 'n/a'):
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
    for file in os.listdir():
        if file.endswith(".7z"):
            with py7zr.SevenZipFile(file, 'r', password=pwd) as archive:
                archive.extractall(path=directory)
else:
    print('\nNo password entered, continuing operation.')
    try:
        print("Files will be extracted to ", directory)
        os.mkdir(directory)
    except FileExistsError:
        directory = input("\nDirectory or file exists, choose another. Enter full path of directory to extract the files: ")
        pass
    except FileExistsError:
        pass
        print("\n\n\nCheck filepath and try again.")
        quit()
    for file in os.listdir():
        if file.endswith(".7z"):
            with py7zr.SevenZipFile(file, 'r') as archive:
                archive.extractall(path=directory)