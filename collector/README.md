The collector provides the mechanism to feed data into an intrusion detection
system.

Most of the work will do into the logstash configuration which normalizes the
data to be consumed by the intrusion detection system consuming this data.
The examples normalize the data for the AttackTagger factor graph IDS:

github.com/ncsa/AttackTagger

these files will have to be changed to adapt them for other IDSes.

This directory contains the scripts and configuration files that 
are necessary to create the collector machine. The collector is run on 
a separate machine from the honeypot and aggregator and is compromised 
of tools that ingest (Logstash), normalize (Logstash), 
store (Elasticsearch), visualize (Kibana), queue (Kafka), and correlate 
on the alerts that are sent from the aggregator using an IDS system. After 
running the 'install.sh' script, all of the necessary tools should be 
installed on the machine. The script works on both ubuntu and centos 
machines. For Logstash to work with the aggregator, the SSL certificates 
need to be created/configured correctly between the two hosts. You can 
find the configuration files for Logstash in '/etc/logstash/conf.d'. 
After the install script is run, Logstash, Elasticsearch, and Kibana 
will be setup as system services that start up when the machine starts 
up. 

To run and/or check the status of Elasticsearch/Kibana:
1) service {elasticsearch,kibana} {start,restart,stop,status}

To start up kafka, run the following commands in this directory:
1) kafka/bin/zookeeper-server-start.sh kafka/config/zookeeper.properties &
2) kafka/bin/kafka-server-start.sh kafka/config/server.properties &

To produce logs for kafka (run in this directory):
1) kafka/bin/kafka-console-producer.sh --broker-list localhost:9092 --topic logstash\_logs

Your intrsuion detection software will then need to integrate with kafka and
subscribe to the topic "logstash\_logs".


**NOTES**
- The logs will be written to '/var/log/logstash/'. Most of the logs 
will be written as '/var/log/logstash/var/log/{name}', 
because it was easy to 
setup things up that way in Logstash. To take a look at this, refer to the 
configuration files for Logstash ('/etc/logstash/conf.d/').
- SSL certificates need to be created/configured between the collector and 
the aggregator. 
