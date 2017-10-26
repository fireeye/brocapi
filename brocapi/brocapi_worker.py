#!/usr/bin/env python
# Brocapi RQ Worker
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

import glob
import logging
import os
import subprocess

import brocapi_syslog

TYPE_BLACKLIST = [
    "capture_loss",
    "stats",
    "loaded_scripts",
    "packet_filter"
]

def process_job(job_uuid, job_tag, pcaps, bro_bin,
    bro_processing_dir, syslog_host, syslog_port,
    syslog_proto, syslog_prefix):

    logging.info("Received job: %s", job_uuid)

    bro_log_dir = bro_processing_dir + job_uuid + "/logs/bro/"
    logging.info("Moving into Bro log dir: %s", bro_log_dir)
    os.chdir(bro_log_dir)

    for pcap in pcaps:
        pcap_path = bro_processing_dir + job_uuid + '/pcaps/' + pcap
        logging.debug("Calling bro for pcap %s as part of job %s", pcap_path, job_uuid)
        try:
            subprocess.call([
                bro_bin,
                "-C",
                "-r",
                pcap_path,
                "local"])
        except Exception as e:
            logging.error("Bro processing failed for pcap %s", pcap)
            logging.error(e)
    
    # Get all the relevant bro logs in the dir
    bro_logs = glob.glob('*.log')
    logging.debug("Found bro logs: %s", str(bro_logs))

    if len(bro_logs) == 0:
        logging.error("No bro logs present for job %s", job_uuid)
        return False

    # Connect to syslog server
    logging.debug("Creating a syslog broker socket to %s:%s over %s for job %s", syslog_host, syslog_port, syslog_proto, job_uuid)
    broker_socket = brocapi_syslog.connect_syslog(syslog_host, syslog_port, syslog_proto)
    if not broker_socket:
        return False

    # Loop through all log types
    for _log in bro_logs:
        logging.debug("Processing log %s for job %s", _log, job_uuid)
        bro_type = _log.split(".")[0]
        if bro_type in TYPE_BLACKLIST:
            logging.debug("Skipping blacklisted type %s for job %s", bro_type, job_uuid)
            continue
        syslog_program = syslog_prefix % bro_type
        # handle every line in the log file
        with open(_log) as bro_file:
            for line in bro_file:
                if line.startswith("#"):
                    continue
                if job_tag is None:
                    job_tag = "brocapi"
                syslog_message = brocapi_syslog.format_syslog_message(job_tag, syslog_program, line)
                broker_socket.send(syslog_message)

    # close out the socket
    broker_socket.close()
