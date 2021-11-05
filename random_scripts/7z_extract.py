#!/usr/bin/python
import py7zr
import os, errno

pwd = input("Enter the password. If no password enter 'n/a': ")
directory = input("\nEnter full path to extract files to: ")

if (pwd != 'n/a'):
    print('\nFiles will be extracted to:', directory)
    try:
        os.mkdir(directory)
    except FileExistsError:
        directory = input("\nDirectory or file exists, choose another. Enter full path of directory to extract the files: ")
    try:
        os.mkdir(directory)
    except FileExistsError:
        directory = input("\n...Third try... Directory or file exists, choose another. Enter full path of directory to extract the files: ")
    try:
        os.mkdir(directory)
    except FileExistsError:
        print("\n\n\nCheck filepath and try again.")
        quit()
    for file in os.listdir():
        if file.endswith(".7z"):
            with py7zr.SevenZipFile(file, 'r', password=pwd) as archive:
                archive.extractall(path=directory)
    #except PermissionError:
    for file in os.listdir():
        if file.endswith(".7z"):
            with py7zr.SevenZipFile(file, 'r', password=pwd) as archive:
                archive.extractall(path=directory)
else:
    print('\nNo password entered, continuing operation.')
    try:
        os.mkdir(directory)
    except FileExistsError:
        directory = input("\nDirectory or file exists, choose another. Enter full path of directory to extract the files: ")
    try:
        os.mkdir(directory)
    except FileExistsError:
        directory = input("\n...Third try... Directory or file exists, choose another. Enter full path of directory to extract the files: ")
    try:
        os.mkdir(directory)
    except FileExistsError:
        pass
        print("\n\n\nCheck filepath and try again.")
        quit()
    for file in os.listdir():
        if file.endswith(".7z"):
            with py7zr.SevenZipFile(file, 'r') as archive:
                archive.extractall(path=directory)