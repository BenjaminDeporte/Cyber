#------------------------------------------------
#------- Toy Pyshark ----------------------------
#------------------------------------------------

#-- NB : PyShark collides with Jupyter NB as the asynco library does not handle nested eventloops...
#-- therefore, *.py can be useful

#---------------------------------------------------------------------------------------------------------------
#--- IMPORTS ---------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------

import numpy as np
import pandas as pd
import pyshark
import matplotlib.pyplot as plt
import json # original json library
import logging

#---------------------------------------------------------------------------------------------------------------
#--- LOG SET-UP ------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------

LOG_FILENAME = '/home/benjamin/Folders_Python/Cyber/logs/logfile.log'
LOG_FORMAT = '%(asctime)% -- %(name)s -- %(levelname)s -- %(message)s'
# LOG_LEVEL = logging.INFO

# specific logger for the module
logger = logging.getLogger(__name__)   # creates specific logger for the module
logger.setLevel(logging.DEBUG)    # entry level of messages from all handlers
LOG_FORMAT = '%(asctime)s -- %(name)s -- %(levelname)s -- %(message)s'
formatter = logging.Formatter(LOG_FORMAT)

# file handler to log everything
file_handler = logging.FileHandler(LOG_FILENAME, mode='w')
file_handler.setLevel(logging.INFO)  # all messages (DEBUG and up) get logged in the file
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# stream handler to show messages to the console
console = logging.StreamHandler()
console.setLevel(logging.WARNING)  # Warning messages and up get displayed to the console
console.setFormatter(formatter)
logger.addHandler(console)

# start your engine
logger.info("-------- new run --------")

#-------------------------------------------------------------------------------------------------------------------

capture = pyshark.FileCapture('/home/benjamin/Folders_Python/Cyber/data/input_pcaps/input.pcap')
print(capture)

pkt = capture[0]
print(pkt)