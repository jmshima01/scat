#!/usr/bin/env python3

import unittest
import binascii

from scat.parsers.samsung import sdmcmd
from scat.parsers.samsung.sdmedgeparser import SdmEdgeParser

class TestSdmEdgeParser(unittest.TestCase):
    parser = SdmEdgeParser(parent=None, model='e5123')
    maxDiff = None

    def test_sdm_edge_scell_info(self):
        payload = binascii.unhexlify('ffff00000000000000000000000000000000000000000000000000000000000000000000ffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_SCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_scell_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('2c003d2200080162f2200134012e060001000101000000000000000021011c1cffffffffc202')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_SCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_scell_info(packet)
        expected = {'stdout': '''EDGE Serving Cell Info: ARFCN: 44, BSIC: 0x3d, RxLev: 34 (RSSI: -76), PLMN: MCC 262/MNC 2, LAC: 0x134, RAC: 0x1, CID: 0x2e06'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('04003f1e00060162f220014101291b0001000101000000000000000021021a1affffffffc202')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_SCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_scell_info(packet)
        expected = {'stdout': '''EDGE Serving Cell Info: ARFCN: 4, BSIC: 0x3f, RxLev: 30 (RSSI: -80), PLMN: MCC 262/MNC 2, LAC: 0x141, RAC: 0x1, CID: 0x291b'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('3500141c00060062f210140701bb4400010001000000000000000000210018f9ffffffffd601')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_SCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_scell_info(packet)
        expected = {'stdout': '''EDGE Serving Cell Info: ARFCN: 53, BSIC: 0x14, RxLev: 28 (RSSI: -82), PLMN: MCC 262/MNC 1, LAC: 0x1407, RAC: 0x1, CID: 0xbb44'''}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_ncell_info(self):
        payload = binascii.unhexlify('067300ff35f9f9ffffffff00000000000000ff7600ff28f9f9ffffffff00000000000000ff5400ff26f9f9ffffffff00000000000000ff5200ff23f9f9ffffffff00000000000000ff4100ff1cf9f9ffffffff00000000000000ff4b00ff1df9f9ffffffff00000000000000ff0a73002954002252001f4b001e3a001d76001d41001c430018380018350016000000005ce79b417c061d43fd061d4311071d4300068114620000002875e44600204000020001000000000020282543060100001e0000007c426a413b5936417c426a417c000f1200060062f210140601418d0001000100000200')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_NCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_ncell_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_3g_ncell_info(self):
        payload = binascii.unhexlify('00000000a843c745989153645c99d5420f0000000200000054b6c5455003c84279181642000000002c003d2200080162f2200134989153647d02000000000000420000004838e4')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_3G_NCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_3g_ncell_info(packet)
        expected = {'stdout': 'EDGE 3G Neighbor Cell Info: 0 Cells'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('0a542a4f01015a3c542a2500016bf0542a4000016bf0542a6700016bf0542a7100016bf0542ac300016bf0542ad900016bf0542aef00016bf0542afa00016bf0542a0501016bf0')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_3G_NCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_3g_ncell_info(packet)
        expected = {'stdout': '''EDGE 3G Neighbor Cell Info: 10 Cells
NCell 0: UARFCN 10836, PSC 335, RSSI 1, RSCP -90, Ec/No -6.0
NCell 1: UARFCN 10836, PSC 37, RSSI 1, RSCP -107, Ec/No -24.0
NCell 2: UARFCN 10836, PSC 64, RSSI 1, RSCP -107, Ec/No -24.0
NCell 3: UARFCN 10836, PSC 103, RSSI 1, RSCP -107, Ec/No -24.0
NCell 4: UARFCN 10836, PSC 113, RSSI 1, RSCP -107, Ec/No -24.0
NCell 5: UARFCN 10836, PSC 195, RSSI 1, RSCP -107, Ec/No -24.0
NCell 6: UARFCN 10836, PSC 217, RSSI 1, RSCP -107, Ec/No -24.0
NCell 7: UARFCN 10836, PSC 239, RSSI 1, RSCP -107, Ec/No -24.0
NCell 8: UARFCN 10836, PSC 250, RSSI 1, RSCP -107, Ec/No -24.0
NCell 9: UARFCN 10836, PSC 261, RSSI 1, RSCP -107, Ec/No -24.0'''}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_handover_info(self):
        payload = binascii.unhexlify('000000000000000000000000000000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_HANDOVER_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_handover_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('000000000000000001000000000000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_HANDOVER_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_handover_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_handover_history_info(self):
        payload = binascii.unhexlify('000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_HANDOVER_HISTORY_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_handover_history_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('ffffffff44291501')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_HANDOVER_HISTORY_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_handover_history_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_meas_info(self):
        payload = binascii.unhexlify('4400320011000f0000000f00000000003a002d00020021000000340020000900000000003f00ff000100925302000b00ff0001007e4329004e00ff000800010000004500ff0002007c0027004300ff0001006f1c27004d003a000100551f0000ffffff001d00d3470d00')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_MEAS_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_meas_info(packet)
        expected = {'stdout': '''EDGE Measurement Info (Serving Cell): ARFCN 68, BSIC 0x32, RxLev 17 (RSSI -93), TxLev 0
EDGE Measurement Info (Neighbor Cell): ARFCN 58, BSIC 0x2d, RxLev 2 (RSSI -108)
EDGE Measurement Info (Neighbor Cell): ARFCN 52, BSIC 0x20, RxLev 9 (RSSI -101)
EDGE Measurement Info (Neighbor Cell): ARFCN 63, BSIC 0x3f, RxLev 1 (RSSI -109)
EDGE Measurement Info (Neighbor Cell): ARFCN 11, BSIC 0x3f, RxLev 1 (RSSI -109)
EDGE Measurement Info (Neighbor Cell): ARFCN 78, BSIC 0x3f, RxLev 8 (RSSI -102)
EDGE Measurement Info (Neighbor Cell): ARFCN 69, BSIC 0x3f, RxLev 2 (RSSI -108)
EDGE Measurement Info (Neighbor Cell): ARFCN 67, BSIC 0x3f, RxLev 1 (RSSI -109)
EDGE Measurement Info (Neighbor Cell): ARFCN 77, BSIC 0x3a, RxLev 1 (RSSI -109)'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('350014002100000000000000000000003b0018001a00756407004b00ff001300756407003900ff001400000000003e00ff000c00571108003300ff000e00756407004200ff000e000100000035001400220075640700ffffff00000000000000ffffff00000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_MEAS_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_meas_info(packet)
        expected = {'stdout': '''EDGE Measurement Info (Serving Cell): ARFCN 53, BSIC 0x14, RxLev 33 (RSSI -77), TxLev 0
EDGE Measurement Info (Neighbor Cell): ARFCN 59, BSIC 0x18, RxLev 26 (RSSI -84)
EDGE Measurement Info (Neighbor Cell): ARFCN 75, BSIC 0x3f, RxLev 19 (RSSI -91)
EDGE Measurement Info (Neighbor Cell): ARFCN 57, BSIC 0x3f, RxLev 20 (RSSI -90)
EDGE Measurement Info (Neighbor Cell): ARFCN 62, BSIC 0x3f, RxLev 12 (RSSI -98)
EDGE Measurement Info (Neighbor Cell): ARFCN 51, BSIC 0x3f, RxLev 14 (RSSI -96)
EDGE Measurement Info (Neighbor Cell): ARFCN 66, BSIC 0x3f, RxLev 14 (RSSI -96)
EDGE Measurement Info (Neighbor Cell): ARFCN 53, BSIC 0x14, RxLev 34 (RSSI -76)'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('350014001e00000000000000000021003b001800120000000000390004000a00e3ac00004b00ff00110047a100004900ff000d0047a100003e0005000d002c57260042000b000a00bd0b1000ffffff00000000000000ffffff00000000000000ffffff00000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_MEAS_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_meas_info(packet)
        expected = {'stdout': '''EDGE Measurement Info (Serving Cell): ARFCN 53, BSIC 0x14, RxLev 30 (RSSI -80), TxLev 33
EDGE Measurement Info (Neighbor Cell): ARFCN 59, BSIC 0x18, RxLev 18 (RSSI -92)
EDGE Measurement Info (Neighbor Cell): ARFCN 57, BSIC 0x04, RxLev 10 (RSSI -100)
EDGE Measurement Info (Neighbor Cell): ARFCN 75, BSIC 0x3f, RxLev 17 (RSSI -93)
EDGE Measurement Info (Neighbor Cell): ARFCN 73, BSIC 0x3f, RxLev 13 (RSSI -97)
EDGE Measurement Info (Neighbor Cell): ARFCN 62, BSIC 0x05, RxLev 13 (RSSI -97)
EDGE Measurement Info (Neighbor Cell): ARFCN 66, BSIC 0x0b, RxLev 10 (RSSI -100)'''}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()
