## Brocapi
HTTP API for mass processing PCAPs through Bro IDS and submitting the resulting logs to a syslog server.

## Overview
Brocapi consists of two parts: 
* A Flask API for receiving PCAPS via HTTP POST and queues a job in Redis via RQ
* An RQ worker that receives the jobs queued from the API to process the PCAPs through Bro and submit the resulting logs to a syslog server.

## Requirements
### Python Modules
```
flask
rq
redis
```
### System Packages
```
Bro IDS
Redis instance running on the same host as the worker
A Syslog server accepting TCP or UDP connections
```
### Optional
```
gunicorn
supervisor
```

## Configuration
By default Brocapi expects the config to be located at /etc/brocapi.conf
```
[main]
# debug logging
debug = off
# worker log file
worker_log = /var/log/brocapi/brocapi_worker.log
# api log file
api_log = /var/log/brocapi/brocapi_api.log

[bro]
# location of your Bro binary
bro_bin = /opt/bro/bin/bro
# directory to contain job output
processing_dir = /opt/brocapi/jobs/
# bro logs to ignore completely
log_blacklist = ["loaded_scripts.log", "packet_filter.log", "reporter.log"]

[syslog]
# syslog host
syslog_host = 127.0.0.1
# syslog port
syslog_port = 514
# syslog protocol (tcp/udp)
syslog_proto = tcp
# syslog program prefix (format string). For example if you use "bro_" as the program prefix, your HTTP logs will have the syslog program bro_http
syslog_prefix = bro25_%s%
```

## Running Brocapi
The API and workers can be run directly i.e.:
```
./brocapi.py
```
but there are a few sample configurations for running Brocapi as a service under Systemd:
* brocapi.service: Runs the flask app under gunicorn
* brocapi_worker.service: Runs the brocapi worker under supervisor. Included the supervisor config in brocapi_worker.ini

## Submitting a Job
Brocapi only has one route `/submit/pcap` and it expects a POST request with 1 required and 1 optional parameter:
* 1 or more PCAPs in an array called 'file'
* Optional 'tag' parameter which Brocapi will use as the value for the syslog hostname

Example submission using Curl without a job tag:
```
{11:38}~/Desktop ➭ curl -k -X POST -F 'file[]=@2017-08-28-Fobos-campaign-Rig-EK-sends-Bunitu.pcap' https://127.0.0.1/submit/pcap
{"status": "job queued", "files": ["2017-08-28-Fobos-campaign-Rig-EK-sends-Bunitu.pcap"], "tag": null, "job_id": "9179876e-08cf-4539-8de7-8a8bb3b0dcaf", "success": true}
```
Example submissions using Curl with a job tag:
```
{11:39}~/Desktop ➭ curl -k -X POST -F 'file[]=@2017-08-28-Fobos-campaign-Rig-EK-sends-Bunitu.pcap' -F 'tag=testing' https://127.0.0.1/submit/pcap
{"status": "job queued", "files": ["2017-08-28-Fobos-campaign-Rig-EK-sends-Bunitu.pcap"], "tag": "testing", "job_id": "507965ab-6511-4cd4-9542-4671eb140f92", "success": true}%
```

### Exmplaining the returned data:
```
{
  "status": "job queued",                                 ## Status of the job. Right now the only value is "job queued" since we're not async and waiting on the full status
  "files": [
    "2017-08-28-Fobos-campaign-Rig-EK-sends-Bunitu.pcap"  ## An array of the pcaps that were submitted
  ],
  "tag": "testing",                                       ## The tag that was supplied to mark the job
  "job_id": "507965ab-6511-4cd4-9542-4671eb140f92",       ## UUID for the job
  "success": true                                         ## Success or failure
}
```
## Job Directories
Once a job is received, the API will create the following example directory structure for the job:
```
jobs # Configured jobs directory
└── fe5f53b3-474d-4cb7-8ece-a2786f841af7 # UUID for the job
    ├── logs # Directory for all the logs
    │   ├── bro # Directory containing all the Bro logs
    │   │   ├── capture_loss.log
    │   │   ├── conn.log
    │   │   ├── dhcp.log
    │   │   ├── dns.log
    │   │   ├── files.log
    │   │   ├── http.log
    │   │   ├── loaded_scripts.log
    │   │   ├── packet_filter.log
    │   │   ├── ssl.log
    │   │   ├── stats.log
    │   │   ├── weird.log
    │   │   └── x509.log
    │   └── syslog # Not used right now
    └── pcaps # Directory containing the submitted PCAPS
        ├── 1725aa89-2f9e-5a44-88da-6bce278e77d3.pcap
        ├── 1ec8ca5f-66dd-5200-9cf2-235638ef13f9.pcap
        ├── 20a3341d-8134-5136-a03c-cb8c3d3fc5be.pcap
        ├── 20cf04e4-a9ef-5415-9f17-bf4c80214c33.pcap
        └── 2f506083-8a84-57c4-8d37-9304157b0899.pcap
```

## Worker Activity
Once the API queues a job into Redis via RQ, a worker will pick up the job and perform the following actions
* Iterate through the supplied PCAPS and invoke Bro with the following paramters: `bro -C -r <pcap> local`
* If any logs were generated, create a connection to the configured syslog server
* Iterate through each generated log type and submit each line to the configured syslog server

## TODO
* Make config location configurable
* Make log_blacklist configurable. It exists in the config, but isn't honored by the worker
* Make the Redis host configurable
* Support moving logs on the host post-job for setups where a log sender might be monitoring a directory
* Add a route for retrieving logs, pcaps, status, etc of previously submitted jobs