__copyright__ = """
   Copyright 2017 FireEye, Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
__license__ = "Apache 2.0"

import datetime
import logging
import socket

# Below is simple syslog implementation written by Christian Stigen Larsen
# Found here: http://csl.name/py-syslog-win32/
# Will work on Windows
facility = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

level = {
    'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

syslog_time_format = "%b %d %H:%M:%S"
today = datetime.datetime.today()

def connect_syslog(syslog_server, syslog_port, syslog_proto):
    # set up the syslog connection
    try:
        logging.info("Connecting to syslog server %s:%s via %s", syslog_server, syslog_port, syslog_proto)
        if syslog_proto == "tcp":
            broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif syslog_proto == "udp":
            broker_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            logging.error("Unrecognized Syslog protocol specified!")
            return 1
        broker_socket.connect((syslog_server, syslog_port))
        logging.info("Connected to syslog server %s:%s via %s", syslog_server, syslog_port, syslog_proto)
        return broker_socket
    except Exception as e:
        logging.error("Could not connect to syslog server!")
        logging.error(e)
        return False

def format_syslog_message(hostname, program, message):
    syslog_message = "%s %s %s: %s" % (
        today.strftime('%b %d %H:%M:%S'), hostname, program, message)
    syslog_message = '<%d>%s' % (
        level['notice'] + facility['daemon'] * 8, syslog_message)
    return syslog_message
