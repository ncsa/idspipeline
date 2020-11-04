# IDS Test Pipeline
This repo contains code and scripts to automate the process of setting 
up the entire data-driven pipeline for testing intrusion detection software. 
This is typically used for researching novel IDS software and techniques.
Note that the focus of this software is on host-based intrusion detection
software that consumes system or network logs--not packet based IDS.

There are 3 main directories in the repo: honeypot, aggregator, and collector.
These 3 directories contain everything that is necessary to recreate the
pipeline. You will need 2 separate machines (that can talk to each other) and
that support virtualization. 

Honeypot:
The honeypot is a VM that is created on one of the 2 machines. It will 
be setup using the setup scripts to install all of the monitoring and 
shipping tools that are necessary. After installing all of the tools, 
restart the VM to complete installation. After running the install 
script and restarting, you will need to make sure that the aggregator 
is setup correctly (especially with SSL) and then the honeypot will be 
good to go. 

Consider refining the honeypot with optional honeypot software such as
NCSA's low interactive ssh honeypot:

https://github.com/ncsa/ssh-auditor

Or a honeypot from the STINGAR project:

https://github.com/CommunityHoneyNetwork/

Aggregator:
The aggregator is the machine/processes that aggregate the host-based and 
network-based monitoring alerts together. In our setup, the network-based 
monitor and the aggregation both happen on the bare-metal host where the 
honeypots are running. Running the install script for the aggregator on the 
bare-metal machine where the honeypot is running will complete the setup 
for the network-based monitoring tools (make sure that Bro is listening on 
the correct interface) and also the aggregation tool (Logstash). SSL 
certificates will need to be made to allow for transport from the honeypot 
and to the collector. Additionally, firewall rules will need to be setup 
to protect the aggregator in the case that it is compromised via the 
honeypot.

Collector:
The collector is where the monitoring alerts get normalized and acted on. 
This is a separate machine than the machine that the honeypot and 
aggregator are running on. 
The aggregator will send all of the aggregated alerts to the collector over 
SSL (need to setup SSL certificates on all machines). Running the install 
script for the collector should setup all of the tools needed to 
ingest, normalize, store, and act on the alerts from the aggregator. 

**NOTES** 
You will need to setup the firewall rules 
on each machine to properly protect your honeypots and the machines that 
they run on. 
You will need to set up the SSL certificates between: 
1) the honeypot(s) and the aggregator
2) the aggregator and the collector

**Helpful Guides**
https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-ubuntu-14-04
https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-centos-7
https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-ossec-security-notifications-on-ubuntu-14-04

