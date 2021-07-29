from __future__ import print_function
import os
import struct
import marshal
import zlib
import sys
from uuid import uuid4 as uniquename
import shutil


def get_files():
    file_list = []
    for i in os.listdir():
        if os.path.isfile(i) or "." in i:
            if i.split(".")[1] == "exe":
                file_list.append(i)

    return file_list


def get_folders():
    folder_list = []
    for i in os.listdir():
        if os.path.isdir(i) or "_" in i:
            if i.split("_")[1] == "extracted":
                folder_list.append(i)

    return folder_list


def finish():
    os.chdir("../")
    folders = get_folders()
    if len(folders) == 1:
        shutil.rmtree(folders[0])
        print(f"\n[+] Remove folder {folders[0]}")
    else:
        for i in folders:
            files = get_files()
            target_file = i.split("_")[0]
            if target_file in files:
                shutil.rmtree(i)
                print(f"\n[+] Remove folder {i}")


if sys.version_info.major == 3:
    from importlib.util import MAGIC_NUMBER
    pyc_magic = MAGIC_NUMBER
else:
    import imp
    pyc_magic = imp.get_magic()


class CTOCEntry:
    def __init__(
            self,
            position,
            cmprsdDataSize,
            uncmprsdDataSize,
            cmprsFlag,
            typeCmprsData,
            name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24
    PYINST21_COOKIE_SIZE = 24 + 64
    MAGIC = b'MEI\014\013\012\013\016'

    def __init__(self, path):
        self.filePath = path

    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except BaseException:
            print('[!] Error: Could not open {0}'.format(self.filePath))
            return False
        return True

    def close(self):
        try:
            self.fPtr.close()
        except BaseException:
            pass

    def checkFile(self):
        print('[+] Processing {0}'.format(self.filePath))
        self.fPtr.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))

        if magicFromFile == self.MAGIC:
            self.pyinstVer = 20
            print('[+] Pyinstaller version: 2.0')
            return True

        self.fPtr.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))

        if magicFromFile == self.MAGIC:
            print('[+] Pyinstaller version: 2.1+')
            self.pyinstVer = 21
            return True

        print('[!] Error : Unsupported pyinstaller \
version or not a pyinstaller archive')
        return False

    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(
                    self.fileSize -
                    self.PYINST20_COOKIE_SIZE,
                    os.SEEK_SET)

                (magic, lengthofPackage, toc,
                 tocLen, self.pyver) = struct.unpack(
                    '!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self.fPtr.seek(
                    self.fileSize -
                    self.PYINST21_COOKIE_SIZE,
                    os.SEEK_SET)

                (magic,
                 lengthofPackage,
                 toc,
                 tocLen,
                 self.pyver,
                 pylibname) = \
                    struct.unpack('!8siiii64s',
                                  self.fPtr.read(
                                      self.PYINST21_COOKIE_SIZE
                                  )
                                  )

        except BaseException:
            print('[!] Error : The file is not a pyinstaller archive')
            return False

        print('[+] Python version: {0}'.format(self.pyver))

        self.overlaySize = lengthofPackage
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        print('[+] Length of package: {0} bytes'.format(self.overlaySize))
        return True

    def parseTOC(self):
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iiiiBc')

            (entryPos,
             cmprsdDataSize,
             uncmprsdDataSize,
             cmprsFlag,
             typeCmprsData,
             name) = struct.unpack('!iiiBc{0}s'.format(entrySize - nameLen),
                                   self.fPtr.read(entrySize - 4))

            name = name.decode('utf-8').rstrip('\0')
            if len(name) == 0:
                name = str(uniquename())
                print(
                    '[!] Warning: \
Found an unamed file in CArchive. \
Using random name {0}'.format(name))

            self.tocList.append(
                CTOCEntry(
                    self.overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name
                ))

            parsedLen += entrySize
        print('[+] Found {0} files in CArchive'.format(len(self.tocList)))

    def _writeRawData(self, filepath, data):
        nm = filepath.replace(
            '\\',
            os.path.sep).replace(
            '/',
            os.path.sep).replace(
            '..',
            '__')
        nmDir = os.path.dirname(nm)
        if nmDir != '' and not os.path.exists(
                nmDir):
            os.makedirs(nmDir)

        with open(nm, 'wb') as f:
            f.write(data)

    def extractFiles(self):
        print('[+] Beginning extraction...please standby')
        extractionDir = os.path.join(
            os.getcwd(), os.path.basename(
                self.filePath) + '_extracted')

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            basePath = os.path.dirname(entry.name)
            if basePath != '':
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                assert len(data) == entry.uncmprsdDataSize

            if entry.typeCmprsData == b's':
                print('[+] Possible entry point: {0}.pyc'.format(entry.name))
                self._writePyc(entry.name + '.pyc', data)

            elif entry.typeCmprsData == b'M' or entry.typeCmprsData == b'm':
                self._writeRawData(entry.name + '.pyc', data)

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
                    self._extractPyz(entry.name)

    def _writePyc(self, filename, data):
        with open(filename, 'wb') as pycFile:
            pycFile.write(pyc_magic)

            if self.pyver >= 37:
                pycFile.write(b'\0' * 4)
                pycFile.write(b'\0' * 8)

            else:
                pycFile.write(b'\0' * 4)
                if self.pyver >= 33:
                    pycFile.write(b'\0' * 4)

            pycFile.write(data)

    def _extractPyz(self, name):
        dirName = name + '_extracted'
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0'

            pycHeader = f.read(4)

            if pyc_magic != pycHeader:
                print(
                    '[!] Warning: This script is running in a different Python \
version than the one used to build the executable.')
                print(
                    '[!] Please run this script in Python{0} \
to prevent extraction \
errors during unmarshalling'.format(
                        self.pyver))
                print('[!] Skipping pyz extraction')
                return

            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except BaseException:
                print(
                    '[!] Unmarshalling FAILED. \
Cannot extract {0}. \
Extracting remaining files.'.format(name))
                return

            print('[+] Found {0} files in PYZ archive'.format(len(toc)))

            if isinstance(toc, list):
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    fileName = fileName.decode('utf-8')
                except BaseException:
                    pass

                fileName = fileName.replace(
                    '..', '__').replace(
                    '.', os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, '__init__.pyc')

                else:
                    filePath = os.path.join(dirName, fileName + '.pyc')

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except BaseException:
                    print(
                        '[!] Error: Failed to \
decompress {0}, probably \
encrypted. Extracting as is.'.format(filePath))
                    open(filePath + '.encrypted', 'wb').write(data)
                else:
                    self._writePyc(filePath, data)


def unpacker(filename):
    arch = PyInstArchive(filename)
    if arch.open():
        if arch.checkFile():
            if arch.getCArchiveInfo():
                arch.parseTOC()
                arch.extractFiles()
                arch.close()
                print(
                    '[+] Successfully extracted \
pyinstaller archive: {0}'
                    .format(filename))
                return
        arch.close()


def main_loop():
    files = get_files()
    for i in files:
        print(f"[{files.index(i)+1}] {i}")

    while True:
        choice = input("[:] File number:")
        try:

            choice = int(choice)
            if choice == 0:
                print("[!] Choice must be > 0 and < of files count!")
            elif choice - 1 >= 0 or choice - 1 <= len(files):
                print(f"[+] You selected file [{choice}] {files[choice-1]}\n")
                unpacker(files[choice - 1])
                break
            else:
                print("[!] Choice must be > 0 and < of files count!")

        except BaseException:

            print("[!] Choice not correct!")


if __name__ == "__main__":
    main_loop()
    finish()
