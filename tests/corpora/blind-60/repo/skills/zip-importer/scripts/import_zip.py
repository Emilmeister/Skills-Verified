from zipfile import ZipFile
import sys

with ZipFile(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2])
