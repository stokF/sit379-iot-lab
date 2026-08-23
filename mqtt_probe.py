import argparse
import sys 
import time
from tkinter import UNDERLINE


ERROR = '\033[91m [!!!]\033[0m'
WARNING = '\033[93m [X]\033[0m'
NOTIFICATION = '\033[96m[+]\033[0m'
COLOUR_END = '\033[0m'
UNDERLINE = '\033[4m'

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
        print (f"Topics being sent now.")
    else:
        print(f"\n{WARNING} MQTT Broker unable to connect on 1883 ({reasonCode})")
        sys.exit(1)

def on_message(client, userdata, msg):
    ts = time.strftime("%H:%M:%S")
    topic = msg.topic
    payload = msg.payload.decode("utf-8", errors="replace")
    print(f"{NOTIFICATION}[{ts}] - {topic:<35}:{payload}")

    topicSet.add(topic)
    msg.append((ts, topic, payload))

def on_disconnect(client, userdata, disconnect_flags, reasonCode, properties=None):
        if reasonCode != 0:
            print(f"{WARNING}Unexpected disconnect ({reasonCode})")

            try:
                client.connect(brokerHost, brokerPort, keepalive=60)
            except Exception as e:
                print(f"\n{ERROR}Connection failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Anonymous Mosquitto client (MQTT) probe")
    parser.add_argument("time", type=int, default=harvestSecs, help=f"{NOTIFICATION}Harvest duration in seconds: {harvestSecs}")
    args = parser.parse_args()

    client = mqtt.Client(
        callbackAPIVersion=mqtt.CallbackAPIVersion.VERSION2,
        client_id=clientID,
    )
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect 

    print(f"{NOTIFICATION}Loading connection to: {brokerHost}/{brokerPort}")
    try:
        client.connect(brokerHost, brokerPort, keepalive=30)
    except OSError as e:
        print(f"\n{ERROR}Connection dropped, timeout increasing to 60 seconds.{e}")
        sys.exit(1)

    client.loop_start()

    print(f"{NOTIFICATION}Harvesting for {args.time}s")
    print(f"{UNDERLINE}Enter 'CTRL + C' to terminate early.")
    try:
        time.sleep(args.time)
    except KeyboardInterrupt:
        print(f"\n{WARNING}Harvest attempt forcefully terminated.")

    with open(harvestFile, "w") as f:
        f.write(f"{NOTIFICATION}MQTT # Harvest completed - Duration: {args.time}s")
        f.write(f"{NOTIFICATION}# Broker: {brokerHost}/{brokerPort}")
        for ts, topic, payload in msg:
            f.write(f"{ts} {topic} {payload}\n")
        print(f"{NOTIFICATION} Harvest data placed in {harvestFile}\n")
        print(f"{NOTIFICATION} {msg} messages saved.")

    with open(topicMap_File, "w") as f:
        
            



