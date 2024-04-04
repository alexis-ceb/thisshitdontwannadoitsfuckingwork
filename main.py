from typing import Union

from fastapi import FastAPI

import modules.scapy as scapy

from queue import Queue

app = FastAPI()

captured_packets = Queue()

# Modified function to process and store packets in the queue
def process_packet(packet):
    captured_packets.put(packet.summary())

# Thread to start packet capture
def start_capture(filter):
    try:
        scapy.sniff(prn=process_packet, filter=filter, store=False)
    except Exception as e:
        print(f"Error during packet capture: {e}")

@app.get("/")
def read_root():
    return {"Hello": "World"}

# I WANT TO GET ALL THE PACKETS CAPTURED AN RETURN THEM
@app.get("/packets")
def read_packets():
    packets = []
    while not captured_packets.empty():
        packets.append(captured_packets.get())
    return packets

@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}