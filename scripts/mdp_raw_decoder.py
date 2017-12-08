#!/usr/bin/env python

from __future__ import print_function

"""
Parse a pcap file containing CME MDP3 market data based on a SBE xml schema file.
"""

import argparse
import sys
import os
from struct import unpack
from struct import unpack_from
from datetime import datetime
from sbedecoder import SBESchema
from sbedecoder import SBEMessageFactory
from sbedecoder import SBEParser
import gzip
import dpkt
import logging
import logging.handlers
import subprocess
import traceback
import progressbar


if __name__ == "__main__":
    # Logging setup
    logger = logging.getLogger()

    LOG_FORMATTER = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - " +
        "%(lineno)s - %(funcName)s - " +
        "%(message)s")
else:
    logger = logging.getLogger(__name__)


def setup_logging(level=logging.ERROR):
    file_log_handler = logging.handlers.RotatingFileHandler(
        __name__ + ".log",
        maxBytes=10000000,
        backupCount=5)
    console_log_handler = logging.StreamHandler()
    logger.addHandler(file_log_handler)
    logger.addHandler(console_log_handler)
    logger.setLevel(level)
    for handler in logging.root.handlers:
        handler.setFormatter(fmt=LOG_FORMATTER)


class MDP3Parser:
    def __init__(self, schema, out_file_handle=sys.stdout):
        self.seq_num = 0
        # Read in the schema xml as a dictionary and
        # construct the various schema objects
        mdp_schema = SBESchema()
        mdp_schema.parse(schema)
        msg_factory = SBEMessageFactory(mdp_schema)
        self.mdp_parser = SBEParser(msg_factory)
        self.out_file_handle = out_file_handle
        # self.loop_start = 0

    def handle_repeating_groups(self, group_container, msg_version, indent,
                                skip_fields=[], secdef=None):
        for group in group_container.groups:
            if group.since_version > msg_version:
                continue
            print(
                ":::{} - num_groups: {}".format(group.name,
                                                group.num_groups),
                file=self.out_file_handle
            )
            for index, group_field in enumerate(group.repeating_groups):
                group_fields = ""
                for group_field in group_field.fields:
                    if group_field.since_version > msg_version:
                        continue
                    group_fields += "\n" + " "*len(indent)
                    if secdef and group_field.id == '48':
                        security_id = group_field.value
                        symbol_info = secdef.lookup_security_id(security_id)
                        if symbol_info:
                            symbol = symbol_info[0]
                            group_fields += "security_id: {} [{}]".format(
                                security_id, symbol)
                            continue
                    group_fields += str(group_field)
                print(":::: {}{}".format(index, group_fields),
                      file=self.out_file_handle)
            self.handle_repeating_groups(
                group,
                msg_version,
                indent + ':',
                skip_fields=skip_fields,
                secdef=secdef
            )


    def parse_packet(self, data, skip_fields=[], token_filter=[]):
        seq_num_str = ":packet => sequence_number: {} sending_time: {}"
        # Parse the packet header:
        # http://www.cmegroup.com/confluence/display/EPICSANDBOX/MDP+3.0+-+Binary+Packet+Header

        sequence_number = unpack_from("<i", data, offset=0)[0]
        sending_time = unpack_from("<Q", data, offset=4)[0]

        template_id_filter = [32, 42, 43]
        for mdp_message in self.mdp_parser.parse(data, offset=12):
            template_val = mdp_message.template_id.value
            if template_val not in template_id_filter:
                continue

            checker = False
            if not token_filter:
                checker = True
            for md_entry in mdp_message.no_md_entries:
                security_id = md_entry.security_id.value
                if token_filter is not None and security_id in token_filter:
                    checker = True

            message_fields = ""
            for field in mdp_message.fields:
                if field.name not in skip_fields:
                    message_fields += "\n  " + str(field)

            if not checker:
                continue

            print("=" * 90, file=self.out_file_handle)
            print(seq_num_str.format(sequence_number, sending_time),
                  file=self.out_file_handle)
            print("::{} -{}\n".format(mdp_message, message_fields),
                  file=self.out_file_handle)

            try:
                # Code for older version
                _ = mdp_message.iterators
                for iterator in mdp_message.iterators:
                    print(
                        ":::{} - num_groups: {}\n".format(
                            iterator.name,
                            iterator.num_groups
                        ),
                        file=self.out_file_handle
                    )
                    group_fields = ""
                    for index, group in enumerate(iterator):
                        for group_field in group.fields:
                            group_fields += "\n    " + str(group_field)
                        print(':::: {}{}'.format(index, group_fields),
                              file=self.out_file_handle)
            except:
                self.handle_repeating_groups(
                    mdp_message,
                    mdp_message.version.value,
                    indent="::::",
                    skip_fields=skip_fields,
                    secdef=None
                )
                continue



def process_raw_file(args):
    ret_val = 0
    filename = args.input_file

    skip_fields = args.skip_fields.split(',')
    token_filter = args.token_filter.split(',')
    if token_filter == [""]:
        token_filter = []
    token_filter = [int(x) for x in token_filter]

    if filename.endswith(".gz"):
        file_handle = gzip.open(filename, "rb")
    else:
        file_handle = open(filename, "rb")

    if args.output_file == "-":
        out_file_handle = sys.stdout
    else:
        out_file_handle = open(args.output_file, "w+")
    mdp3_parser = MDP3Parser(args.schema,
                             out_file_handle=out_file_handle)

    file_size = os.stat(filename).st_size
    bar = progressbar.ProgressBar()
    while True:
        bar_val = 100.0 * float(file_handle.tell()) / file_size
        if bar_val > 100.0:
            bar_val = 100
        bar.update(bar_val)
        if bar_val == 100:
            break

        timestamp_count_bytes = file_handle.read(1)
        if timestamp_count_bytes is None:
            break
        timestamp_count, = unpack('B', timestamp_count_bytes)
        logger.debug("Timestamp byte length: %s", str(timestamp_count))

        for i in range(0, timestamp_count):
            timestamps_bytes = file_handle.read(8)
            if timestamps_bytes is None:
                break
            timestamp, = unpack('L', timestamps_bytes)
            logger.debug("Timestamp: %s", str(timestamp))

        size_bytes = file_handle.read(4)
        if size_bytes:
            chunk_size, = unpack('I', size_bytes)
            logger.debug("Chunk size: %d", chunk_size)
            chunk = file_handle.read(chunk_size)
            try:
                mdp3_parser.parse_packet(chunk, skip_fields, token_filter)
            except Exception as error:
                exc_mesg = traceback.format_exc()
                logger.error("\n%s", exc_mesg)
                logger.error("Error %s", error)
                ret_val = -1
                break
        else:
            break

    bar.finish()
    file_handle.close()
    return ret_val


def process_command_line():
    parser = argparse.ArgumentParser(
        description="Parse CME MDP3 market data",
        version="0.2"
    )

    parser.add_argument(
        "--input",
        dest="input_file",
        help="Input file to process",
        required=True
    )

    parser.add_argument(
        "--output",
        dest="output_file",
        default="out.log",
        help="Output file"
    )

    parser.add_argument(
        "--schema",
        dest="schema",
        default="templates_FixBinary.xml",
        help="Path to SBE schema xml file"
    )

    default_skip_fields = [
        "message_size",
        "block_length",
        "template_id",
        "schema_id",
        "version"
    ]

    parser.add_argument(
        "--skip_fields",
        dest="skip_fields",
        default=",".join(default_skip_fields),
        help="comma separated list of fields to skip. default={}".format(
            ",".join(default_skip_fields)
        )
    )

    parser.add_argument(
        "--token_filter",
        dest="token_filter",
        default="",
        help="comma separated list of venue tokens to use. Default: all"
    )

    args = parser.parse_args()

    # check number of arguments, verify values, etc.:
    if not os.path.isfile(args.schema):
        logger.info("Downloading sbe schema xml file from the web")
        command = "wget ftp://ftp.cmegroup.com/SBEFix/Production/Templates/templates_FixBinary.xml"
        subprocess.call(command, shell=True)

    if not os.path.isfile(args.input_file):
        parser.error("Cannot find file '{}' not found".format(args.input_file))

    return args


def main(argv=None):
    args = process_command_line()
    return process_raw_file(args)


if __name__ == '__main__':
    setup_logging(level=logging.INFO)
    sys.exit(main())
