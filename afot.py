#!/usr/bin/python

import pip
try:
    __import__('termcolor')
except ImportError:
    pip.main(['install', 'termcolor'])

try:
    __import__('simplejson')
except ImportError:
    pip.main(['install', 'simplejson'])

from termcolor import colored
from os import system
from platform import python_version


import codecs
import fileinput
import hashlib
import urllib2
import zipfile
import io
import os
import stat
import re
import subprocess
import platform
import sys
import time
import csv
import ntpath
from argparse import ArgumentParser
from datetime import datetime
from string import whitespace
from time import sleep
from traceback import format_exc
reload(sys)
sys.setdefaultencoding('utf8')


### Below are global internal variables. Do not edit these. #############
__VERSION__ = '0.0.1'                                                   #
__AUTHOR__ = 'Charalampos Raftopoulos (@harris_rafto)'                  #
__EMAIL__ = 'harrisrafto@gmail.com'                                     #
__ENDOFLINE__ = '\n----- End of Line -----\n\n'                         #
#########################################################################

__VIRUSTOTALAPIKEY__ = ''; # Add your virus-total api key here
__VIRUSTOTALSEARCHURL__ = 'http://didierstevens.com/files/software/virustotal-search_V0_1_2.zip'
__NSRLURL__ = 'http://didierstevens.com/files/software/nsrl_V0_0_2.zip'
__NISTDATABASE__ = 'http://www.nsrl.nist.gov/RDS/rds_2.52/rds_252m.zip'
__ANALYZEPESIGURL__ = 'http://didierstevens.com/files/software/AnalyzePESig_V0_0_0_2.zip'


def checkPythonVersion():
    """
    Check python version the user is using for compatibility reasons
    """
    version = python_version()
    if "2.7" not in version:
        print colored('\n------------------------------\nYour python version might not be sufficient for our script. Please use version 2.7 ! Keep going though...\n------------------------------', 'red')
        time.sleep(1)


def downloadFile(fileUrl):
    """
    Download needed script
    """
    url = fileUrl

    file_name = url.split('/')[-1]
    u = urllib2.urlopen(url)
    f = open(file_name, 'wb')
    meta = u.info()
    file_size = int(meta.getheaders("Content-Length")[0])
    print "Downloading: %s Bytes: %s" % (file_name, file_size)

    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break

        file_size_dl += len(buffer)
        f.write(buffer)
        status = r"%10d  [%3.2f%%]" % (
            file_size_dl, file_size_dl * 100. / file_size)
        status = status + chr(8) * (len(status) + 1)
        print status,

    f.close()


def unzipFile(fileName):
    """
    Extract a zipped file
    """
    zip_ref = zipfile.ZipFile(fileName, 'r')
    zip_ref.extractall()
    zip_ref.close()


def deleteFile(fileName):
    """
    Delete a file
    """
    os.remove(fileName)


def printInfo():
    """
    Print all user's info
    """
    print colored('\n\n------------------------------\nAutomated FOrensics Script: afos.py\n------------------------------', 'yellow')
    print colored('Version: %s' % __VERSION__, 'green')
    print colored('Author: %s' % __AUTHOR__, 'green')
    print colored('Email: %s' % __EMAIL__, 'green')
    print colored('%s' % __ENDOFLINE__, 'yellow')


def main():
    """
    Main routine
    """

    checkPythonVersion()

    printInfo()
    time.sleep(1)

    path = raw_input('Enter folder path (eg. c:/): ')
    formattedPath = path.replace('/', '\\')

    # if path not provided, set default path to "c:\"
    if not path:
        formattedPath = 'c:\\'

    if not os.path.isdir('AnalyzePESig'):
        print colored('\n------------------------------\nYou do not have AnalyzePESig! Downloading now...!\n------------------------------', 'red')
        time.sleep(1)
        # Download the script
        downloadFile(__ANALYZEPESIGURL__)
        # Unzip it
        unzipFile('AnalyzePESig_V0_0_0_2.zip')
        # Delete the downloaded zip file
        deleteFile('AnalyzePESig_V0_0_0_2.zip')

    if platform.system() == "Windows":
        # Check if AnalyzePESig exists, if not download it
        print colored('\n------------------------------\nGo grab a cup of coffee...this is gonna take a while!\n------------------------------', 'yellow')
        print colored('\n------------------------------\nChecking all files for signatures!\n------------------------------', 'yellow')
        time.sleep(1)
        subprocess.call(['AnalyzePESig\\Release\\AnalyzePESig.exe',
                         "-e", "-v", "-s", "-o", "windows.csv", formattedPath])

    # Get all hashes that are not signed
    hashes = []

    with open('windows.csv', 'rb') as f:
        reader = csv.reader(f, delimiter=';')
        for row in reader:
            if row[11] == "0":
                hashes.append(row[1])

    with open('hashes.txt', 'w+') as hashfile:
        for item in hashes[0:len(hashes)]:
            hashfile.write("%s\n" % item)

    print colored('\n------------------------------\nCross Checking with the NIST database...please be patient!\n------------------------------', 'yellow')
    time.sleep(1)

    # Check if nsrl script exists, if not download it
    if not os.path.isfile('nsrl.py'):
        print colored('\n------------------------------\nYou do not have the nsrl.py script! Downloading now...!\n------------------------------', 'red')
        time.sleep(1)
        # Download the script
        downloadFile(__NSRLURL__)
        # Unzip it
        unzipFile('nsrl_V0_0_2.zip')
        # Delete the downloaded zip file
        deleteFile('nsrl_V0_0_2.zip')

    # Check if NIST database 'Reduced Sets' exists, if not download it
    if not os.path.isfile('rds_252m.zip'):
        print colored('\n------------------------------\nYou do not have the Reduced Set of NIST\'s database! Downloading now...!\n------------------------------', 'red')
        time.sleep(1)
        # Download the file
        downloadFile(__NISTDATABASE__)

    # Cross-check with NIST's database
    subs = system('python nsrl.py -f -q -o nist.csv hashes.txt rds_252m.zip')

    hashes = []

    with open('nist.csv', 'rb') as f:
        reader = csv.reader(f, delimiter=';')
        for row in reader:
            hashes.append(row[0])

    if hashes:
        time.sleep(1)
        print colored('\n------------------------------\nFound something! Please wait...\n------------------------------', 'yellow')
        time.sleep(1)

        # get all hashes that were find in NIST's database and write them into
        # a text file
        with open('infected.txt', 'w+') as thefile:
            for item in hashes[1:len(hashes)]:
                thefile.write("%s\n" % item)

        print colored('\ninfected.txt', 'green') + colored(' file has been created containing all found hashes!', 'yellow')
        time.sleep(1)

        # Check if virustotal-search script exists, if not download it
        if not os.path.isfile('virustotal-search.py'):
            print colored('\n------------------------------\nYou do not have the virustotal-search.py script! Downloading now...!\n------------------------------', 'red')
            time.sleep(1)
            # Download the script
            downloadFile(__VIRUSTOTALSEARCHURL__)
            # Unzip it
            unzipFile('virustotal-search_V0_1_2.zip')
            # Delete the downloaded zip file
            deleteFile('virustotal-search_V0_1_2.zip')

        print colored('\nBegin querying VirusTotal...', 'yellow')
        time.sleep(1)

        # Search VirusTotal
        virustotalsearch = system(
            'python virustotal-search.py -k '+ __VIRUSTOTALAPIKEY__ +' -o report.csv infected.txt')

        possibleMd5 = []
        detections = []

        # Read the report file
        with open('report.csv', 'rb') as f:
            reader = csv.reader(f, delimiter=';')
            for row in reader:
                possibleMd5.append(row[0])
                detections.append(row[4])

        print colored('\n------------------------------\nReport\n------------------------------', 'yellow')

        # Format the array accordingly
        fmt = '{:<8}{:<35}{}'

        for i, (c1, c2) in enumerate(zip(possibleMd5, detections)):
            print(fmt.format(i, c1, c2))

        time.sleep(2)

        print colored('Cleaning up unnecessary files...', 'yellow')

        # Delete unnecessary files
        deleteFile('windows.csv')
        deleteFile('hashes.txt')
        deleteFile('nist.csv')
        deleteFile('infected.txt')

        time.sleep(2)

        print colored('\nreport.csv', 'green') + colored(' file has been created containing a full report!', 'yellow')

        sys.exit(1)

    else:
        print colored('\nNothing found!\n------------------------------', 'green')
        sys.exit(1)


if __name__ == '__main__':
    main()
