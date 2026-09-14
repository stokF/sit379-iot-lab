# sit379-iot-lab
An air-grapped penetration testing lab environment containg relevant penetration, high entropy encryption and defense oriented scripts. Within this environment a Raspberry Pi 5 is acting as an IoT device, running Node-RED and Mosquitto MQTT. This repository contains the primary scripts within the weaponisation stage.

# flowDeploy.py - Version Control 1.1 
This was a red team tool, developed to target Node-Red unauthenticated /flows admin API. When in use, it deploys a malicious flow that injects into exec nodes, which then allows for remote code execution on the Pi. Prior to execution, it backs up all existing flows for restoration. This script contains 4 specific tags, those being –check (auth probe), --verify (SSH Verification), --restore and –-dry-run. 

# mqttProbe.py - Version Control 1.1
This tool enables the process of reconnaissance on the Mosquitto MQTT broker. This is achieved by connecting to Mosquitto on port 1883, and then subscribes to wildcard topic #, where it then harvest all information for a user specified period. Once complete, the script produces mqtt_harvest.txt and mqtt_topic_map.txt. This provides insight into unauthorized actuator control via home/actuators/relay.

#deviceIOC.py - Version Control 1.1
This is tool was used to analyse indication of compromise within the host target system, it parses Node-Red and MQTT packet capture through tshark and auditd logs to detect markers and events that are suspected as malicious. Once the data is collected, it is compiled and organized into rankings of severity.

#dataImpact.py - Version Control 2.0
This program simulated an encryption-based ransomware script, through the utilization of the python cryptography library. It encrypted all files existing within /home/eh_pi/dummy_data using AES-256-GCM with individual per file keys. During the before and after process of encryption, it logs its current state of entropy and then stores the log in /tmp. Additionally, it has a built in reversal feature using –restore. 
