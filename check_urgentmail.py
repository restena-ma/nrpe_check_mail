#!/usr/bin/python
# coding: utf-8 
__author__ = "Maxime Appolonia"
__license__ = "GPL"

"""
    NRPE check_urgentmail.py
    This check alerts on the presence of email in a specified folder (/var/lib/nrpe_check_urgentmail/incoming/).
    The script maintains a json file (/var/lib/nrpe_check_urgentmail/status.json) which contains the IP addresses of
    The nagios servers which have been informed of the presence of the email.
    This permits to fire the alert only once per nagios server.
    The emails and their associated information stored in the status.json file are clean 24h after their detection.  
"""

import sys
import os
import binascii
import traceback
import json
import hashlib
import datetime
from email.header import decode_header


VAR_FOLDER = "/var/lib/nrpe_check_urgentmail"
INCOMING_MAIL_FOLDER = os.path.join(VAR_FOLDER, "incoming")
STATUS_FILE_PATH = os.path.join(VAR_FOLDER, "status.json")
ALERT_TITLE = "Urgent mail received ! "
ALERT_DURATION_MINUTES = 05
DELETE_FILE_AFTER_MINUTES = 10



def bin_addr_to_ipv4(bin_addr):
    """
    Converts an ipv4 given as a binary (hex format) from /proc/net/tcp to an ipv4 in a normalised format
    """
    octets = [bin_addr[i:i+2] for i in range(0, len(bin_addr), 2)]
    ip = [int(i, 16) for i in reversed(octets)]
    ip_formatted = '.'.join(str(i) for i in ip)
    return ip_formatted

def bin_addr_to_ipv6(bin_addr):
    """
    Converts an ipv6 given as a binary (hex format) from /proc/net/tcp6 to an ipv6 in a normalised format (zero are not padded nor shortened)
    """
    def byte_to_binary(n):
        return ''.join(str((n & (1 << i)) and 1) for i in reversed(range(8)))

    bin_addr = binascii.unhexlify(bin_addr)
    bin_str = ''.join(byte_to_binary(ord(b)) for b in bin_addr)
    _bytes = [bin_str[i:i+4] for i in range(0, len(bin_str), 4)]
    _hexs = [ ("%01X" % int(_byte, 2)).lower()  for _byte in _bytes ]
    _hexs = [ "".join([_hexs[i+2] ,_hexs[i+3], _hexs[i], _hexs[i+1]])  for i in range(0,len(_hexs),4)]
    _hexs = ":".join( [ ":".join([_hexs[i+1] ,_hexs[i] ]) for i in range(0,len(_hexs),2)] )
    return _hexs


def get_nrpe_client_ip(pid):
        """
        NRPE script does not known of the ip of the calling nagios server. 
        This methods looks in the file descriptors of the script calling process the opened connection to the socket listening the nrpe port.
        Return the ipv4 or ipv6 as a string 
        """
        
        #
        # finds all the sockets inodes attached to the process
        #
        socket_inodes = []
        proc_fd_path = "/proc/{}/fd".format(pid)
        fds = os.listdir(proc_fd_path)          
        for fd in fds:
                fullpath = os.path.join(proc_fd_path, fd)
                if os.path.islink(fullpath):
                        realpath = os.path.realpath(fullpath)
                        #print(realpath)
                        if "socket:" in realpath:   
                                socket_inodes.append(realpath.split("[")[1][:-1])

        
        #
        # find the remote_ip off this socket in tcp4
        #
        matching_remote_ip = None
        with open("/proc/{}/net/tcp".format(pid)) as proc_tcp:
                for l in proc_tcp:
                        parts = l.strip().split()
                        #print(parts)
                        try:
                                if ":" in parts[0]: # : not present in header line
                                        remote_ip = bin_addr_to_ipv4(parts[2].split(":")[0])
                                        if parts[9] in socket_inodes:
                                                #print("[{}] {}->{}".format(parts[9], remote_ip, local_port))
                                                matching_remote_ip = remote_ip
                        except:
                                traceback.print_exc()
                                
        #
        # if the socket was not found in tcp4 we must look in the tcp6 layer
        #
        if matching_remote_ip is None:
                with open("/proc/{}/net/tcp6".format(pid)) as proc_tcp:
                        for l in proc_tcp:
                                parts = l.strip().split()
                                #print(parts)
                                try:
                                        if ":" in parts[0]: # : not present in header line
                                                remote_ip = bin_addr_to_ipv6(parts[2].split(":")[0])
                                                if parts[9] in socket_inodes:
                                                        #print("[{}] {}->{}".format(parts[9], remote_ip, local_port))
                                                        matching_remote_ip = remote_ip
                                except:
                                        traceback.print_exc()

        return matching_remote_ip


if __name__ == "__main__":
        exit_status = 0
        exit_message = ""
        
        try:
                #
                # Tests path are accessible / writeable (these tests may exit immediately in case of failure)
                #
                if not os.access(VAR_FOLDER, os.W_OK):
                        print("Cannot write to {} ! Check aborted".format(VAR_FOLDER))
                        sys.exit(3)

                if not os.access(INCOMING_MAIL_FOLDER, os.W_OK):
                        print("Cannot write to {} ! Check aborted".format(INCOMING_MAIL_FOLDER))
                        sys.exit(3)

                if not os.path.exists(STATUS_FILE_PATH): #if no status file, initialize an empty one (JSON)
                        with open(STATUS_FILE_PATH, "w") as status_file:
                                status_file.write("{}")

                #
                # Load status file
                #
                status = {}
                with open(STATUS_FILE_PATH) as status_file:
                        status = json.load(status_file)

                #
                # Gets the ip of the server calling this check
                #
                pid = os.getpid()
                remote_ip = get_nrpe_client_ip(pid)

                #print("Your IP is: {}".format(remote_ip))

                #
                # add every file just arrived in the incoming folder to the status (identifer is the file hash)
                #
                for f in os.listdir(INCOMING_MAIL_FOLDER):
                        filehash = hashlib.sha256(open(os.path.join(INCOMING_MAIL_FOLDER, f), 'rb').read()).hexdigest()


                        #
                        # If the file was not seen before, we add it to the status
                        #
                        if  filehash not in status.keys():
                                mail_from="?"
                                mail_to = "?"
                                mail_subject=u"?"
                                try:
                                        with open(os.path.join(INCOMING_MAIL_FOLDER, f)) as mail:
                                                for line in mail:
                                                        if line[:3].lower() == "to:":
                                                                mail_to = line[4:].strip()
                                                        if line[:5].lower() == "from:":
                                                                mail_from = line[6:].strip()
                                                        if line[:8].lower() == "subject:":
                                                                subject_tuple = decode_header(line[9:].strip())[0]
                                                                if subject_tuple[1] is not None:
                                                                    mail_subject = subject_tuple[0].decode(subject_tuple[1], "replace").encode("utf8", "replace")
                                                                else:
                                                                    mail_subject = subject_tuple[0]
                                except Exception, e:
                                        pass # dont care if we cannot parse the email content, the most important is to fire the alert
                                status[filehash] = { "date_first_seen": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "from": mail_from, "to":mail_to, "subject": mail_subject,  "nagios_server_status": {} }

                        #
                        # If the current nagios server has never seen this email, we add it to the list
                        #
                        if remote_ip not in status[filehash]["nagios_server_status"].keys():
                                status[filehash]["nagios_server_status"][remote_ip] = {"date_first_seen": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') }

                        #
                        # now everything is ready to send alert
                        # we will send alert if the date at which the current nagios server have first seen the message is within the alert delay
                        #
                        date_first_seen_str = status[filehash]["nagios_server_status"][remote_ip]["date_first_seen"]
                        date_first_seen = datetime.datetime.strptime(date_first_seen_str, "%Y-%m-%d %H:%M:%S")
                        if ( datetime.datetime.now() - date_first_seen).total_seconds() < ALERT_DURATION_MINUTES * 60:
                                if exit_message != "":
                                        exit_message += "\n"
                                else:
                                        exit_message += ALERT_TITLE
                                exit_status = 2
                                exit_message += " --- Subject: '{}' --- From: {} --- To:{} ---".format(status[filehash]["subject"].encode("utf8", "replace"), status[filehash]["from"], status[filehash]["to"])

                        #
                        # Cleanup by removing old files (from disk and from status)
                        #
                        date_first_seen = datetime.datetime.strptime(status[filehash]["date_first_seen"], "%Y-%m-%d %H:%M:%S")
                        if ( datetime.datetime.now() - date_first_seen).total_seconds() > DELETE_FILE_AFTER_MINUTES * 60:
                                fullpath = os.path.join(INCOMING_MAIL_FOLDER, f)
                                #print("Delete file {} with hash {}".format(fullpath, filehash))
                                try:
                                        os.remove(fullpath)                                    
                                except Exception, e:
                                        print("Exception: {}".format(str(e)))
                                else:
                                        if not os.path.exists(fullpath):
                                                del status[filehash]

                #
                # Write the status to a file on disk
                #
                with open(STATUS_FILE_PATH, "w") as status_file:
                        json.dump(status, status_file, indent=4)

                #
                # exiting verbosely but truncate the message to 1000 character to avoid falling in the nrpe message size limit trap
                #
                if exit_status == 0 and exit_message == "":
                        exit_message = "There is no new email in the incoming folder, everything OK."

                print(exit_message[0:1000])
                sys.exit(exit_status)
        except SystemExit, e:
                sys.exit(exit_status)
                # sys.exit() raise an exception but we want to catch all exceptions except sys.exit() !
        except:
                print("Exception while running check\n")
                print(traceback.format_exc()[0:1000]) # truncate to be sure nagios will handle it even if long output
                sys.exit(3)

                                                                               