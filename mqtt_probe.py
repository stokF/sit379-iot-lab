import argparse
import sys 
import time


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
        print (f"{NOTIFICATION}Connected to {brokerHost}:{brokerPort} anonymously - no authentication used")
        client.subscribe("$SYS/#", qos=0)
        print(f"Wildcard '#' subscribed.")
        print (f"Topics being sent now.{COLOUR_END}")
    else:
        print(f"{WARNING} MQTT Broker unable to connect on 1883 ({reasonCode}){COLOUR_END}")
    sys.exit(1)

def on_message(client, userdata, msg):
    ts = time.strftime("%H:%M:%S")
    topic = msg.topic
    payload = msg.payload.decode("utf-8", errors="replace")
    print(f"{NOTIFICATION}[{ts}] - {topic:<35}:{payload}{COLOUR_END}")

    topicSet.add(topic)
    msg.append((ts, topic, payload))

    def on_disconnect(client, userdata, disconnect_flags, reasonCode, properties=None):
        if reasonCode != 0:
            print(f"{WARNING}Unexpected disconnect ({reasonCode}){COLOUR_END}")

def main():
    parser = argparse.ArgumentParser(description="Anonymous MQTT client probe")
    parser.add_argument("time", type=int, default=harvestSecs, help=f"{NOTIFICATION}Harvest duration in seconds: {harvestSecs}{COLOUR_END}")
    args = parser.parse_args()

    client = mqtt.Client(
        callbackAPIVersion=mqtt.CallbackAPIVersion.VERSION2,
        client_id=clientID,
    )
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect # type: ignore

    print(f"{NOTIFICATION}Loading connection to: {brokerHost}/{brokerPort}{COLOUR_END}")

