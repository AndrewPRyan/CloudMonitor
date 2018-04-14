# This program provides either a file system monitor for cloud service detection or pcap analysis for cloud service web traffic
# Created By: Andrew Ryan
# Last Modified: April 14, 2018

# System Modules/Libraries
import sys, time, logging, hashlib, os, ntpath, dpkt, socket, datetime, getpass

# Packet Parsing from PCAP File Modules/Libraries
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.arp import ARP
from dpkt.compat import compat_ord

# Path Reconstruction Library
from pathlib import Path

#Directory Observer Modules/Libraries
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler

# Email Modules/Libraries
import smtplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

awaitingEmailLogin = True
while awaitingEmailLogin:
    # Email Credentials
    emailAddress = input("Enter your Wentworth email address: ")
    emailPassword = getpass.getpass()

    s = smtplib.SMTP(host='smtp-mail.outlook.com', port=587)
    s.starttls()

    try:
        s.login(emailAddress, emailPassword)
        emailMessage = MIMEMultipart()
        body = ""
        print('Login Successful.')
        awaitingEmailLogin = False
    except:
        print('Could not log in. Try again')



# Buffer Size for MD5
BUF_SIZE = 10240

# User-defined Directory hash variable, hash list, and hash:src_path dictionary
userDirectoryMd5 = hashlib.md5()
userDirectoryHashes = []
userDirectoryDictionary = {}

# Dropbox Directory hash variable, hash list, and hash:src_path dictionary
dropBoxMd5 = hashlib.md5()
dropBoxHashes = []
dropBoxDictionary = {}

# Dropbox Directory hash variable, hash list, and hash:src_path dictionary
googleDriveMd5 = hashlib.md5()
googleDriveHashes = []
googleDriveDictionary = {}

#List of detected files where hashes match
detectedFiles = []
#List of detected files where filename exists in cloud directories
detectedFilesAtRisk = []

# Event Handler for User-defined Directory
class CloudEventHandler(FileSystemEventHandler):
    # Constructor
    def __init__(self, observer):
        self.observer = observer

    def on_any_event(self, event):
        # Detect whether file system event is not a directory, deletion event, or a hidden file
        if (not event.is_directory) and (not event.event_type == 'deleted') and (ntpath.basename(event.src_path) != ".DS_Store"):
            # Open file to perform MD5
            with open(event.src_path, 'rb') as f:
                while True:
                    # Read data in chunks specified by buffer size
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    # Update after every iteration
                    userDirectoryMd5.update(data)

        # Feed File MD5 to list of User Directory Hashes
        if not userDirectoryMd5.hexdigest() in userDirectoryHashes:
            # Insert hash into hash list, and hash:filename into dictionary
            userDirectoryHashes.append(userDirectoryMd5.hexdigest())
            userDirectoryDictionary[userDirectoryMd5.hexdigest()] = ntpath.basename(event.src_path)

# Event Handler for Dropbox Directory
class DropboxEventHandler(FileSystemEventHandler):
    # Constructor
    def __init__(self, observer):
        self.observer = observer

    # Detect whether file system event is not a directory, deletion event, or a hidden file
    def on_any_event(self, event):
        #print ("Event : ", event, " ", event.event_type)
        #print(event.src_path)
        if (not event.is_directory) and (not event.event_type == 'deleted') and ('.dropbox.cache' not in event.src_path) and (ntpath.basename(event.src_path) != ".DS_Store"):
            # Open file to perform MD5
            with open(event.src_path, 'rb') as f:
                while True:
                    # Read data in chunks specified by buffer size
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    # Update after every iteration
                    dropBoxMd5.update(data)
                    
        # Feed File MD5 to list of Dropbox Hashes
        if not dropBoxMd5.hexdigest() in dropBoxHashes:
            # Insert hash into hash list, and hash:filename into dictionary
            dropBoxHashes.append(dropBoxMd5.hexdigest())
            dropBoxDictionary[dropBoxMd5.hexdigest()] = ntpath.basename(event.src_path)
        
        #Check if file exists in User Directory, for file at risk report
        if os.path.exists(path + '' + ntpath.basename(event.src_path)):
            if not ntpath.basename(event.src_path) in detectedFilesAtRisk:
                detectedFilesAtRisk.append(ntpath.basename(event.src_path))

# Event Handler for Google Drive Directory
class GoogleDriveEventHandler(FileSystemEventHandler):
    # Constructor
    def __init__(self, observer):
        self.observer = observer

    # Detect whether file system event is not a directory, deletion event, or a hidden file
    def on_any_event(self, event):
        #print ("Event : ", event, " ", event.event_type)
        #print(event.src_path)
        if (not event.is_directory) and (not event.event_type == 'deleted') and (ntpath.basename(event.src_path) != ".DS_Store"):
            # Open file to perform MD5
            with open(event.src_path, 'rb') as f:
                while True:
                    # Read data in chunks specified by buffer size
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    # Update after every iteration
                    googleDriveMd5.update(data)
        
        # Feed File MD5 to list of Google Drive Hashes
        if not googleDriveMd5.hexdigest() in googleDriveHashes:
            # Insert hash into hash list, and hash:filename into dictionary
            googleDriveHashes.append(googleDriveMd5.hexdigest())
            googleDriveDictionary[googleDriveMd5.hexdigest()] = ntpath.basename(event.src_path)
        
        #Check if file exists in User Directory, for file at risk report
        if os.path.exists(path + '' + ntpath.basename(event.src_path)):
            if not ntpath.basename(event.src_path) in detectedFilesAtRisk:
                detectedFilesAtRisk.append(ntpath.basename(event.src_path))

def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

if __name__ == "__main__":

    print("This program expects either a pcap file to analyze or a specified directory to monitor.")
    executionType = input("Enter 'pcap' for packet parsing and analyzation or 'monitor' for directory monitoring: ")

    if executionType == 'monitor':
        # Initialize User Path
        path = ''

        #Dropbox Directory Path
        dropBoxDirectory = str(Path.home()) + '/Dropbox/'

        #Google Drive Directory Path
        googleDriveDirectory = str(Path.home()) + '/Google Drive/'

        #Configure Logging
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')

        #######################################################
        ##  User-inputted Directory Observer Setup
        #######################################################

        #Set up Desired Directory to be monitored
        awaitingDirectory = True
        while awaitingDirectory:
            try:
                path = input('Enter the directory you wish to monitor: ' + str(Path.home()) + '/')
                path = str(Path.home()) + '/' + path.strip()
                if os.path.exists(path):
                    print(path + ' now being monitored')
                    awaitingDirectory = False
                else:
                    print('Directory not found. Enter a valid directory.')
            except:
                print("Could not obtain directory. Program Terminating...")
                sys.exit()

        #Set up Directory Observer
        observer = Observer()
        #Set up Event Handler
        event_handler = CloudEventHandler(observer)
        #Schedule Observer with Path Information
        observer.schedule(event_handler, path, recursive=True)
        #Start Observer
        observer.start()

        #######################################################
        ##  Dropbox Directory Observer Setup
        #######################################################

        #Set up Desired Directory to be monitored
        path = dropBoxDirectory
        #Set up Directory Observer
        dropBoxObserver = Observer()
        #Set up Event Handler
        event_handler = DropboxEventHandler(dropBoxObserver)
        #Schedule Observer with Path Information
        dropBoxObserver.schedule(event_handler, path, recursive=True)
        #Start Observer
        dropBoxObserver.start()

        #######################################################
        ##  Google Drive Directory Observer Setup
        #######################################################

        #Set up Desired Directory to be monitored
        path = googleDriveDirectory
        #Set up Directory Observer
        googleDriveObserver = Observer()
        #Set up Event Handler
        event_handler = GoogleDriveEventHandler(googleDriveObserver)
        #Schedule Observer with Path Information
        googleDriveObserver.schedule(event_handler, path, recursive=True)
        #Start Observer
        googleDriveObserver.start()

        try:
            # Observer Execution Loop
            while True:

                time.sleep(1)

                # Detect if hashed file from event matches a file in Dropbox
                if userDirectoryMd5.hexdigest() in dropBoxHashes:
                    if userDirectoryMd5.hexdigest() in userDirectoryDictionary.keys():
                        if userDirectoryDictionary[userDirectoryMd5.hexdigest()] not in detectedFiles:
                            detectedFiles.append(userDirectoryDictionary[userDirectoryMd5.hexdigest()])
                
                # Detect if hashed file from event matches a file in Google Drive
                if userDirectoryMd5.hexdigest() in googleDriveHashes:
                    if userDirectoryMd5.hexdigest() in userDirectoryDictionary.keys():
                        if userDirectoryDictionary[userDirectoryMd5.hexdigest()] not in detectedFiles:
                            detectedFiles.append(userDirectoryDictionary[userDirectoryMd5.hexdigest()])

                # Detect if hashed file in Dropbox from event matches a file in User-defined Directory
                if dropBoxMd5.hexdigest() in userDirectoryHashes:
                    if dropBoxMd5.hexdigest() in dropBoxDictionary.keys():
                        if dropBoxDictionary[dropBoxMd5.hexdigest()] not in detectedFiles:
                            detectedFiles.append(dropBoxDictionary[dropBoxMd5.hexdigest()])
                
                # Detect if hashed file in Google Drive from event matches a file in User-defined Directory
                if googleDriveMd5.hexdigest() in userDirectoryHashes:
                    if googleDriveMd5.hexdigest() in googleDriveDictionary.keys():
                        if googleDriveDictionary[googleDriveMd5.hexdigest()] not in detectedFiles:
                            detectedFiles.append(googleDriveDictionary[googleDriveMd5.hexdigest()])

        except KeyboardInterrupt:
            print('Program Terminating...')
            try:
                # Form Email Message and Headers
                emailMessage['From'] = emailAddress
                emailMessage['To'] = emailAddress
                emailMessage['Subject'] = "File Risk Report"

                body += "File Risk Report\n"
                body += '\nFiles Detected in Cloud Service:\n'

                for f in detectedFiles:
                    if f != '' and f != '.DS_Store':
                        body += 'File : ' + f + '\n'

                body += '\nFiles at Risk:\n'

                for f in detectedFilesAtRisk:
                    if f != '' and f != '.DS_Store':
                        body += 'File : ' + f + '\n'

                # Attach Message Object to Email
                emailMessage.attach(MIMEText(body, 'plain'))
                
                # Form and Send Email Message
                text = emailMessage.as_string()
                s.sendmail(emailAddress, emailAddress, text)

                # Close SMTP Connection
                s.quit()

            except:
                print('Email Module Failure')

            observer.stop()
            dropBoxObserver.stop()
            googleDriveObserver.stop()

    elif executionType == 'pcap':

        #Initialize PCAP file
        pcapFile = ''

        #Set up PCAP File to be parsed
        awaitingFile = True
        while awaitingFile:
            try:
                path = input('Enter the pcap file you wish to analyze: ' + str(Path.home()) + '/')
                path = str(Path.home()) + '/' + path.strip()
                awaitingFile = False

            except:
                print("Could not obtain file. Program Terminating...")
                sys.exit()
            
        pcapFile = open(path, 'rb')
        pcap = dpkt.pcap.Reader(pcapFile)

        body += 'Cloud Activity:\n'
        
        # For each packet in the pcap process the contents
        for timestamp, buf in pcap:

            # Unpack the Ethernet frame (mac src/dst, ethertype)
            eth = dpkt.ethernet.Ethernet(buf)

            # Make sure the Ethernet data contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
                continue

            # Now grab the data within the Ethernet frame (the IP packet)
            ip = eth.data

            # Check for TCP in the transport layer
            if isinstance(ip.data, dpkt.tcp.TCP):

                # Set the TCP data
                tcp = ip.data

                # Now see if we can parse the contents as a HTTP request
                try:
                    # Parse Packet Data
                    request = dpkt.http.Request(tcp.data)
                    hostAddress = request.headers['host']
                    requestMethod = request.headers['method']
                    currentTimestamp = str(datetime.datetime.utcfromtimestamp(timestamp))

                    # Check host address of current packet to see if Dropbox accessed
                    if 'dropbox.com' in hostAddress:
                        body += 'Dropbox Activity Found: timestamp = ' + currentTimestamp + ', host = ' + hostAddress + ', method = ' + request + '\n'
                    
                    # Check host address of current packet to see if Google Drive accessed
                    if 'drive.google.com' in hostAddress:
                        body += 'Google Drive Activity Found: timestamp = ' + currentTimestamp + ', host = ' + hostAddress + ', method = ' + request + '\n'

                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    continue

        try:
            # Form Email Message and Headers
            emailMessage['From'] = emailAddress
            emailMessage['To'] = emailAddress
            emailMessage['Subject'] = "File Risk Report"

            # Attach Message Object to Email
            emailMessage.attach(MIMEText(body, 'plain'))
            
            # Form and Send Email Message
            text = emailMessage.as_string()
            s.sendmail(emailAddress, emailAddress, text)

            # Close SMTP Connection
            s.quit()

        except:
            
            sys.exit()
    else:
        print('Invalid argument provided. Program Terminating...')
        sys.exit()