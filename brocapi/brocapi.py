#!/usr/bin/env python
# Brocapi HTTP API
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

import ConfigParser
import json
import logging
import os
import sys
import uuid

import flask
import redis
import rq

import brocapi_worker

# Set up our logger format
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s  [%(filename)s:%(funcName)s]')
logger = logging.getLogger(__name__)

# Grab config
logging.info("Loading config file")
try:
    config = ConfigParser.ConfigParser()
    config.read('/etc/brocapi.conf')
except Exception as e:
    logging.error("Could not read config file. Exiting.")
    logging.error(e)
    sys.exit(1)
logging.info("Config file loaded successfully.")

# Set to debug logging if enabled in the config
if config.getboolean("main", "debug"):
    logger.info("Debug logger enabled")
    logger.setLevel(logging.DEBUG)

# Find our processing dir, create it if it doesn't exist
BROCAPI_PROCESSING_DIR = config.get("bro", "processing_dir")
logger.debug("Using processing dir: %s", BROCAPI_PROCESSING_DIR)
if not os.path.isdir(BROCAPI_PROCESSING_DIR):
    logger.warning("Processing directory %s doesn't exist, attempting to create it", BROCAPI_PROCESSING_DIR)
    try:
        os.makedirs(BROCAPI_PROCESSING_DIR)
    except:
        logger.error("Could not create Brocapi tmp dirs.")
        sys.exit(1)
    logger.info("Successfully created the processing directory %s", BROCAPI_PROCESSING_DIR)

# Create a connection to our rq worker queue
logger.info("Connecting to worker queue..")
try:
    rs = redis.Redis()
    # Test if the redis server is up
    rs.get(None)
    brocapi_queue = rq.Queue(connection=rs)
except Exception as e:
    logger.error("Error attempting to connect to worker queue!")
    logger.error(e)
    sys.exit(1)
logger.info("Successfully connected to worker queue")

# Set up our Flask app
app = flask.Flask(__name__)


@app.route('/submit/pcap', methods=['POST'])
def api_submit_pcap():
    """API Endpoint for Bro pcap processing"""
    # Create a unique job uuid and folders
    job_uuid = str(uuid.uuid4())

    # Grab the job tag if it was supplied
    if 'tag' in flask.request.form:
        job_tag = str(flask.request.form['tag'])
    else:
        job_tag = None

    # Make sure we can get the pcaps from the POST data
    try:
        submitted_pcaps = flask.request.files.getlist("file[]")
    except:
        logger.error("Error retrieving pcaps from job %s", job_uuid)
        response = json.dumps({"job_id": job_uuid, "success": False, "status": "error retrieving supplied pcaps", "tag": job_tag})
        return response, 500
    # If we didn't get any pcaps in the request, don't waste our time
    if len(submitted_pcaps) == 0:
        logger.warning("Job %s contained no pcaps", job_uuid)
        response = json.dumps({"job_id": job_uuid, "success": False, "status": "no pcaps supplied", "tag": job_tag})
        return response, 500

    logger.info("Received the following PCAP request: job: %s, tag: %s, files: %s", job_uuid, job_tag, str(submitted_pcaps))
    
    # Create all the jobs dirs inside the processing dir
    job_path = os.path.join(BROCAPI_PROCESSING_DIR, job_uuid)
    job_logs_dir = os.path.join(job_path, "logs")
    job_logs_bro = os.path.join(job_logs_dir, "bro")
    job_logs_syslog = os.path.join(job_logs_dir, "syslog")
    job_pcaps_dir = os.path.join(job_path, "pcaps")
    try:
        logger.debug("Creating job directories for job %s", job_uuid)
        os.makedirs(job_logs_dir)
        os.makedirs(job_logs_bro)
        os.makedirs(job_logs_syslog)
        os.makedirs(job_pcaps_dir)
    except Exception as e:
        logger.error("Failed to create storage for job %s", job_uuid)
        logger.error(e)
        response = json.dumps({"job_id": job_uuid, "success": False, "status": "error creating job dirs", "tag": job_tag})
        return response, 500

    # Save all the files that were uploaded
    uploaded_filenames = []
    for _file in submitted_pcaps:
        filename = os.path.split(_file.filename)[-1]
        file_path = os.path.join(job_pcaps_dir, filename)
        _file.save(os.path.abspath(file_path))
        uploaded_filenames.append(filename)

    # Once we created the jobs dirs and saved the pcaps, queue the job in the worker queue
    brocapi_queue.enqueue(brocapi_worker.process_job, job_uuid, job_tag, 
        uploaded_filenames, config.get("bro", "bro_bin"), BROCAPI_PROCESSING_DIR,
        config.get("syslog", "syslog_host"), config.getint("syslog", "syslog_port"),
        config.get("syslog", "syslog_proto"), config.get("syslog", "syslog_prefix"))
    logger.info("Brocapi job added to worker queue: " + job_uuid)
    response = json.dumps({"job_id": job_uuid, "success": True, "status": "job queued", "tag": job_tag, "files": uploaded_filenames})
    return response, 200
