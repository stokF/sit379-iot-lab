import argparse
import sys 
import time

class notiColours:
    ERROR = '\033[91m'
    WARNING = '\033[93m'
    NOTIFICATION = '\033[96m'
    COLOUR_END = '\033[0m'

try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit("Error: paho-mqtt not installed. Run: sudo pip3 install paho-mqtt")

brokerHost = "10.10.10.40"
brokerPort = 1883 
harvestSecs = 30
harvestFile = "mqtt_harvest.txt"
topicMap_File = "mqtt_topic_map.txt"
actuatorTopic = "home/actuators/relay"
clientID = "kali_probe_01"

topicSet = set()
msg = []

def on_connect(client, userdata, flags, reasonCode, properties=None):
    if reasonCode == 0:
        print (f"{notiColours.NOTIFICATION}Connected to {brokerHost}:{brokerPort} anonymously - no authentication used")
        client.subscribe("$SYS/#", qos=0)
        print(f"Wildcard '#' subscribed.")
        print (f"Topics being sent now.{notiColours.COLOUR_END}")
    else:
        print(f"{notiColours.WARNING} MQTT Broker unable to connect on 1883 ({reasonCode}){notiColours.COLOUR_END}")
    sys.exit(1)
