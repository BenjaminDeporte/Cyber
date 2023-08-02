import logging
import pandas as pd

# basic library for reuse

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
file_handler.setLevel(logging.DEBUG)  # all messages (DEBUG and up) get logged in the file
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# stream handler to show messages to the console
console = logging.StreamHandler()
console.setLevel(logging.WARNING)  # Warning messages and up get displayed to the console
console.setFormatter(formatter)
logger.addHandler(console)

# start your engine
logger.info("-------- new run --------")

class PyPacket():
    """Wrapper for PyShark packet. Creates a dictionnary with ETH, IP, TCP, UDP data if/when present.
    NB : use_ek = False.
    
    Methods :
    __init__    :   the constructor takes a PyShark packet object
    data        :   returns a dictonnary, whose keys are 'ETH', 'IP', 'TCP', 'UDP'
    dataframe   :   returns a Pandas dataframe with all key,value pairs in the dictionnary data     
    """
    
    MAP = {
        'ETH' : ['dst', 'src', 'type'], # 'dst_resolved', 'dst_oui', 'dst_oui_resolved', 'addr', 'addr_resolved', 'addr_oui', 'addr_oui_resolved', 'dst_lg', 'lg', 'dst_ig', 'ig', 'src_resolved', 'src_oui', 'src_oui_resolved', 'src_lg', 'src_ig', 
        'IP' : ['version', 'hdr_len', 'len', 'id', 'flags', 'ttl', 'proto',  'src', 'dst' ], 
        # 'dsfield', 'dsfield_dscp', 'dsfield_ecn',  'flags_rb', 'flags_df', 'flags_mf', 'frag_offset','checksum', 'checksum_status','addr', 'src_host', 'host', 'dst_host'
        'TCP' : ['srcport', 'dstport',  'stream', 'len', 'seq',  'ack',  'hdr_len', 'flags', 'time_relative', 'time_delta', 'payload'],
        # 'port','seq_raw', 'nxtseq','ack_raw','flags_res', 'flags_ns', 'flags_cwr', 'flags_ecn', 'flags_urg', 'flags_ack', 'flags_push', 'flags_reset', 'flags_syn', 'flags_fin', 'flags_str', 
        # 'window_size_value', 'window_size', 'window_size_scalefactor', 'checksum', 'checksum_status', 'urgent_pointer', 'options', 'options_nop', 'option_kind', 
        # 'options_timestamp', 'option_len', 'options_timestamp_tsval', 'options_timestamp_tsecr', 'analysis', 'analysis_bytes_in_flight', 'analysis_push_bytes_sent', 
        'UDP' : ['srcport', 'dstport', 'length',  'stream', 'time_relative', 'time_delta', 'payload']
        # 'port', 'checksum', 'checksum_status',
    }
    
    def __init__(self, packet) -> None:
        self._packet = packet
        self._data = None
        self._dataframe = None
        logger.debug('Instantiated PyPacket object')
        
    @property
    def data(self):
        if self._data is not None:
            return self._data
        else:
            self._data = {}
            for k, list_fields in self.MAP.items():
                if k in self._packet:
                    dict_fields = {}
                    for field in list_fields:
                        dict_fields[field] = self._packet[k].get(field)
                    self._data[k] = dict_fields
            self._data['TIMESTAMP'] = { 'ts' : self._packet.sniff_time }
            return self._data
        
    @data.setter
    def data(self, input):
        logger.critical("attempt to write data in a PyShark object")
        
    @property
    def dataframe(self):
        if self._dataframe is not None:
            return self._dataframe
        else:
            data = self.data
            dict_for_data = {}
            for layer, layer_dict in data.items():
                for field, value in layer_dict.items():
                    key = layer + '_' + field
                    dict_for_data[key] = value
            # dict_for_data['TIMESTAMP'] = data['TIMESTAMP']['ts']
            self._dataframe = pd.DataFrame(data=dict_for_data, index=[0])
            logger.debug("created a dataframe out of a PyPacket object")
            return self._dataframe