#!/usr/bin/env python

"""
Parse a pcap file containing CME MDP3 market data based on a SBE xml schema file.
"""

import sys
import os.path
from struct import unpack
from struct import unpack_from
from datetime import datetime
from sbedecoder import SBESchema
from sbedecoder import SBEMessageFactory
from sbedecoder import SBEParser
import gzip
import dpkt

seq_num = 0;
seq_num1 = 0;
loop_start = 0;
def parse_mdp3_packet(mdp_parser,  data, skip_fields):
    # parse the packet header: http://www.cmegroup.com/confluence/display/EPICSANDBOX/MDP+3.0+-+Binary+Packet+Header    
    global seq_num
    global loop_start
    sequence_number = unpack_from("<i", data, offset=0)[0]
    sending_time = unpack_from("<Q", data, offset=4)[0]
    # if sequence_number ==1 and loop_start == 0:
    #     loop_start = 1        
    # elif sequence_number != 1 and loop_start == 0:
    #     return    
    # elif sequence_number == 1 and loop_start == 1:
    #     sys.exit(0)
    
    print(':packet -  sequence_number: {} sending_time: {} '.format(sequence_number, sending_time))    
    # try:       
    #     if seq_num > 0:
    #         if((seq_num +1) != sequence_number):                
    #             sys.exit(0)        
    #     seq_num = sequence_number;         
    #     print(sequence_number);
    # except Exception as e:
    #     print e;
    #     raise           
    for mdp_message in mdp_parser.parse(data, offset=12):
        checker = False;
        # if mdp_message.template_id.value == 32 or mdp_message.template_id.value == 42 or mdp_message.template_id.value == 38 :
        #     checker = True;        
        # if mdp_message.template_id.value == 38:
        #      checker = False;
        # if mdp_message.template_id.value == 38:
        #     security_id = mdp_message.security_id.value
        #     if 160078 == security_id:
        #          checker = True;
        if mdp_message.template_id.value == 32 or mdp_message.template_id.value == 42 or mdp_message.template_id.value == 43:        
            for md_entry in mdp_message.no_md_entries:
                security_id = md_entry.security_id.value                
                if 66404 == security_id:
                    checker = True                
                # if md_entry.md_entry_type.value not in ['Bid', 'Offer']:            
                #     checker = False  
        if mdp_message.template_id.value == 36:        
            checker = True             
        checker = True
        # if mdp_message.template_id.value == 12:        
        #    checker = False
        if checker == True:          
            print('=======================================================================================') 
            print(':packet -  sequence_number: {} sending_time: {} '.format(sequence_number, sending_time))    
            message_fields = ''
            for field in mdp_message.fields:
                if field.name not in skip_fields:
                    message_fields += ' ' + str(field)
            print('::{} - {}'.format(mdp_message, message_fields))
            for iterator in mdp_message.iterators:
                print(':::{} - num_groups: {}'.format(iterator.name, iterator.num_groups))
                for index, group in enumerate(iterator):
                    group_fields = ''
                    for group_field in group.fields:
                        group_fields += str(group_field) + ' '
                    print('::::{}'.format(group_fields))
        # elif mdp_message.template_id.value == 38:
        #     security_id = mdp_messgae.security_id.value
        #     if 160078 == security_id:
        #         message_fields = ''
        #         for field in mdp_message.fields:
        #             if field.name not in skip_fields:
        #                 message_fields += ' ' + str(field)
        #         print('::{} - {}'.format(mdp_message, message_fields))
        #         for iterator in mdp_message.iterators:
        #             print(':::{} - num_groups: {}'.format(iterator.name, iterator.num_groups))
        #             for index, group in enumerate(iterator):
        #                 group_fields = ''
        #                 for group_field in group.fields:
        #                     group_fields += str(group_field) + ' '
        #                 print('::::{}'.format(group_fields))


def process_raw_file(args, filename):
    # Read in the schema xml as a dictionary and construct the various schema objects
    mdp_schema = SBESchema()
    mdp_schema.parse(args.schema)
    msg_factory = SBEMessageFactory(mdp_schema)
    mdp_parser = SBEParser(msg_factory)

    skip_fields = set(args.skip_fields.split(','))

    with gzip.open(filename, 'rb') if filename.endswith('.gz') else open(filename, 'rb') as file:
        while True:
            timestamp_count_bytes = file.read(1)
            timestamp_count, = unpack('B', timestamp_count_bytes)
            # print(timestamp_count)
            for i in range(0,timestamp_count):
                timestamps_bytes = file.read(8)
                timestamp, = unpack('L', timestamps_bytes)
                # print(timestamp)
            size_bytes = file.read(4)
            if size_bytes:
                chunk_size, = unpack('I', size_bytes)
                # print(chunk_size)
                chunk = file.read(chunk_size)
                try:
                    parse_mdp3_packet(mdp_parser, chunk, skip_fields)                                        
                except Exception:
                    print('could not parse packet number {}'.format(packet_number))
            else:
                break;   



def process_command_line():
    from argparse import ArgumentParser

    parser = ArgumentParser(
        description="Parse a pcap file containing CME MDP3 market data based on a SBE xml schema file.",
        version="0.1")

    parser.add_argument("pcapfile",
        help="Name of the pcap file to process")

    parser.add_argument("-s", "--schema", default='templates_FixBinary.xml',
        help="Name of the SBE schema xml file")

    default_skip_fields = 'message_size,block_length,template_id,schema_id,version'

    parser.add_argument("-f", "--skip-fields", default=default_skip_fields,
        help="Don't print these message fields (default={})".format(default_skip_fields))

    args = parser.parse_args()

    # check number of arguments, verify values, etc.:
    if not os.path.isfile(args.schema):
        parser.error("sbe schema xml file '{}' not found".format(args.schema))

    return args


def main(argv=None):
    args = process_command_line()
    process_raw_file(args, args.pcapfile)
    return 0  # success


if __name__ == '__main__':
    status = main()
    sys.exit(status)
