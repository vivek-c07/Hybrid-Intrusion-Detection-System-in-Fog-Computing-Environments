from scapy.all import sniff, IP, TCP, Raw
import paho.mqtt.client as mqtt
import json

def packet_callback(packet):
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if "MQTT" in payload:
                print(f"[MQTT Packet] {payload}")
                # Further analysis of MQTT headers can be done here
        except Exception as e:
            print(f"Error processing packet: {e}")

sniff(filter="port 1883", prn=packet_callback, store=0)
