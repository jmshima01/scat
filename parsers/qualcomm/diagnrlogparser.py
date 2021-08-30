#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging

class DiagNrLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            # NR
            0xB80C: lambda x, y, z: self.parse_nr_0xb80c(x, y, z),

            # NR RRC
            0xB821: lambda x, y, z: self.parse_nr_rrc(x, y, z), # NR RRC OTA Packet
            0xB822: lambda x, y, z: self.parse_nr_scell(x, y, z), # NR RRC Serving Cell
            0xB824: lambda x, y, z: self.parse_nr_0xb824(x, y, z),
            0xB825: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB825),
            0xB826: lambda x, y, z: self.parse_cacombos(x, y, z), # NR RRC Supported CA Combos

            0xB840: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB840),
            0xB841: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB841),
            0xB842: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB842),
            0xB843: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB843),
            0xB84B: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB84B),
            0xB84D: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB84D),
            0xB84E: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB84E),

            0xB856: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB856),
            0xB857: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB857),

            0xB860: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB860),
            0xB861: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB861),
            0xB862: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB862),
            0xB868: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB868),
            0xB869: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB869),

            0xB870: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB870),
            0xB871: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB871),
            0xB872: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB872),
            0xB873: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB873),

            0xB881: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB881),
            0xB882: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB882),
            0xB883: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB883),
            0xB885: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB885),
            0xB886: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB886),
            0xB887: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB887),
            0xB888: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB888),
            0xB889: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB889),
            0xB88A: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB88A),
            0xB88B: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB88B),
            0xB88C: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB88C),
            0xB88D: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB88D),
            0xB88F: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB88F),

            0xB890: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB890),
            0xB896: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB896),
            0xB897: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB897),
            0xB89B: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB89B),
            0xB89C: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB89C),
            0xB89D: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB89D),
            0xB89E: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB89E),

            0xB8A1: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8A1),
            0xB8A3: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8A3),
            0xB8A4: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8A4),
            0xB8A6: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8A6),
            0xB8A7: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8A7),
            0xB8A8: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8A8),

            0xB8C0: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8C0),
            0xB8C4: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8C4),
            0xB8C5: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8C5),
            0xB8C6: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8C6),
            0xB8C7: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8C7),
            0xB8C8: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8C8),
            0xB8C9: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8C9),
            0xB8CA: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8CA),
            0xB8CB: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8CB),
            0xB8CD: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8CD),
            0xB8CE: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8CE),

            0xB8D1: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8D1),
            0xB8D2: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8D2),
            0xB8D3: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8D3),
            0xB8DD: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8DD),
            0xB8DE: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8DE),
            0xB8E0: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8E0),
            0xB8E2: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB8E2),

            0xB951: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB951),
            0xB952: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB952),
            0xB954: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB954),
            0xB955: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB955),
            0xB956: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB956),
            0xB958: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB958),
            0xB959: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB959),
            0xB95B: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB95B),
            0xB95C: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB95C),
            0xB95D: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB95D),
            0xB960: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB960),
            0xB969: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB969),
            0xB96A: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB96A),
            0xB96B: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB96B),
            0xB96C: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB96C),
            0xB96E: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB96E),
            0xB96F: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB96F),
            0xB974: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB974),
            0xB977: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB977),
            0xB979: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB979),
            0xB97C: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB97C),
            0xB97F: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB97F),
            0xB980: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB980),
            0xB982: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB982),
            0xB983: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB983),
            0xB986: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB986),
            0xB987: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB987),
            0xB989: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB989),
            0xB98A: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB98A),
            0xB98F: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB98F),
            0xB9A3: lambda x, y, z: self.parse_nr_stub(x, y, z, 0xB9A3),
        }

    def parse_nr_stub(self, pkt_ts, pkt, radio_id, item_id):
        self.parent.logger.log(logging.WARNING, "NR_STUB " + hex(item_id) + " " + util.xxd_oneline(pkt))

    def parse_nr_0xb80c(self, pkt_ts, pkt, radio_id):
        # 01 00 00 00 | 01 02 00 62 f2 20 ff ff ff ff ff ff ff ff ff ff ff ff 01 00 00 00
        pass

    def parse_nr_rrc(self, pkt_ts, pkt, radio_id):
        msg_hdr = b''
        msg_content = b''

        pkt_ver = struct.unpack('<I', pkt[0:4])

        if pkt_ver in (0x09): # Version 9
            # 09 00 00 00 | 0f 90 | 01 | c6 02 | c0 ac 05 00 | 00 00 00 00 | 08 | 00 00 00 00 | 09 00 | 00 01 01 06 c6 5c fb d6 40
            msg_hdr = pkt[0:24] # 24 bytes
            msg_content = pkt[24:] # Rest of packet
            if len(msg_hdr) != 24:
                return 
            msg_hdr = struct.unpack('<IHBHIIBIH', msg_hdr) # Version, RRC Release, RBID, PCI, NR-ARFCN, SysFN/SubFN, PDUN, Len
            nr_pci = msg_hdr[3]
            nr_arfcn = msg_hdr[4]
            nr_pdu_id = msg_hdr[6]
            nr_pdu_len = msg_hdr[7]

        if pkt_ver in (0x09):
            # RRC Packet v9
            rrc_type_map = {
                # 1: unknown
                # 8: UL DCCH
                # 9: RRCReconfiguration
                # 10: RRCReconfigurationComplete
                # 25: nr-RadioBearerConfig[1-2]-r15
            }

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if not (nr_pdu_id in rrc_type_map.keys()):
            self.parent.logger.log(logging.WARNING, "Unknown RRC subtype 0x%02x for RRC packet version 0x%02x" % (nr_pdu_id, pkt_ver))
            self.parent.logger.log(logging.DEBUG, util.xxd(pkt))
            return 

        nr_pdu_id_gsmtap = rrc_type_map[nr_pdu_id]

        # TODO: GSMTAP header for 5GNR

    def parse_nr_scell(self, pkt_ts, pkt, radio_id):
        pkt_ver = struct.unpack('<I', pkt[0:4])

        if pkt_ver in (0x03): # Version 3
            # 03 00 00 00 | 50 01 | c0 ac 05 00 | 9a 00 00 3f
            msg = struct.unpack('<IHIBBH', pkt) # Version, PCI, NR-ARFCN, unknown yet

    def parse_nr_0xb824(self, pkt_ts, pkt, radio_id):
        # 05 00 00 00 | 01 01 0c | c0 ac 05 00 | 00 00
        pass

    def parse_cacombos(self, pkt_ts, pkt, radio_id):
        self.parent.logger.log(logging.WARNING, "0xB826 " + util.xxd_oneline(pkt))

