#!/usr/bin/python

# Copyright (c) 2012 Jonathan Perry
# Copyright (c) 2013 Chenchong Qin
# This code is released under the MIT license (see LICENSE file).

import math
from pprint import pprint
import numpy, copy, struct

import wireless

from FactoryCollection import FactoryCollection

from gnuradio import digital

class Spinal(object):
    def __init__(self, specific, initialSeed, verbosity):
        
        self.factories = FactoryCollection(['make_pre_packet_manipulator',
                                            'make_packet_generator',
                                            'make_encoder',
                                            'make_mapper',
                                            'make_channel',
                                            'make_demapper',
                                            'make_decoder',
                                            'make_detector',
                                            'make_protocol',
                                            'make_statistics'])
        
        try:
            from alt_configuration import get_factory_list
        except:
            from default_configuration import get_factory_list
            
        for fobj in get_factory_list():
            self.factories.add_factory(fobj)
        
        self.verbosity = verbosity
        
        # Random generator
        self.random = numpy.random.mtrand.RandomState()
        
        # Get components
        self.getComponents(specific)
                
        # initialize random
        self.seed(initialSeed)
        
        self.curPacket = None
        self.curCrc32 = None
        self.tx_done = True
        self.rx_success = False
        # for txer, it records how many pkts (encoding the same msg) have been sent.
        # for rxer, it counts num of pkts received for decoding the same msg.
        self.pktno = 0
       
        # some redundancy here. 
        self.tx_reset()
        self.rx_reset()
    
    def gen_raw_pkt(self):
        '''
        Generate raw data packet (randomly).
        '''
        return self.packetGen.get()
    
    def print_pkt(self, packet, desc='packet'):
        '''
        Print contents (0x format) of a packet.
        '''
        print "%s = 0x%s" % (desc, packet.encode("hex"))

    def get_cur_pkt(self):
        return self.curPacket

    def tx_next_video_pkt(self, packet):
        '''
        NB: pkt here means payload to be sent, 
              not the initial data (unfortunately, we also call it a pkt).
        '''
        
        if self.tx_done:
            self.tx_reset()
            # packet = self.gen_raw_pkt()
            self.tx_set_pkt(packet)
        
        symbols = self.coding()

        return self.pack_pkt(self.pktno, symbols, self.curCrc32)

    def tx_next_pkt(self):
        '''
        NB: pkt here means payload to be sent, 
              not the initial data (unfortunately, we also call it a pkt).
        '''
        
        if self.tx_done:
            self.tx_reset()
            packet = self.gen_raw_pkt()
            self.tx_set_pkt(packet)
        
        symbols = self.coding()

        return self.pack_pkt(self.pktno, symbols, self.curCrc32)

    def pack_pkt(self, pktno, symbols, crc32):

        # build the packet to be sent. packet = pktno + pkt + crc32
        #   - pktno: the pass count
        #   - pkt:   spinal encoder/mapper output
        #   - crc32: crc32 of the original data. decoder uses it to check whether decoding is done.
        
        def hexint(mask):
            if mask >= 2**31:
                return int(mask-2**32)
            return mask
        trunk = ''
        for symbol in symbols:
            trunk += struct.pack('!I', symbol & 0xffffffff)
        print "[pack_pkt] pktno: %d  crc32: 0x%x" % (pktno, crc32)
        return struct.pack('!H', pktno & 0xffff) + trunk + struct.pack("!I", hexint(crc32) & 0xffffffff)

    def unpack_pkt(self, payload):
        if len(payload) < 6:
            return (False, None, None, None)
        
        pkt_ok = True

        (pktno,) = struct.unpack('!H', payload[0:2])
        pkt = payload[2:-4]
        (crc32,) = struct.unpack('!I', payload[-4:])

        symbols = list()

        for pos in xrange(0, len(pkt), 4):
            symbols.append(struct.unpack('!I', pkt[pos:pos+4])[0])

        print "[unpack_pkt] pkt_ok: %r  pktno: %d  crc32: 0x%x" % (pkt_ok, pktno, crc32)
        return (pkt_ok, pktno, symbols, crc32)
    
    def pack_ack(self, pktno = None, crc32 = None):
        if pktno is None:
            pktno = self.pktno
        if crc32 is None:
            crc32 = self.curCrc32

        return struct.pack('!HI', pktno & 0xffff, crc32 & 0xffffffff)

    def unpack_ack(self, ack):
        if len(ack) != 6:
            return (None, None)

        return struct.unpack('!HI', ack)

    def tx_set_pkt(self, packet):
        self.encoder.setPacket(packet)
        self.curPacket = packet
        self.curCrc32 = digital.crc32(packet)
        self.tx_done = False
        
        #if self.verbosity >= 3:
            #self.print_pkt(packet)

    def num_next_channel_outputs(self):
        nextNumChannelSymbols = self.protocol.numSymbolsNextDecode(0)
        return nextNumChannelSymbols - self.lastNumChannelSymbols

    def coding(self):
        minNeededEncoderOutputs = self.num_next_channel_outputs()
        self.encoder.encode(minNeededEncoderOutputs, self.encodeBuffer)
        self.mapper.process(self.encodeBuffer, self.mapperBuffer)
        self.lastNumChannelSymbols += minNeededEncoderOutputs
        self.protocol.setResult(0, self.lastNumChannelSymbols, 0)
        self.pktno += 1
        #if self.verbosity >= 3:
            #print "EncoderOut:", list(self.encodeBuffer)
            #print "MapperOut: " , list(self.mapperBuffer)
        return list(self.mapperBuffer)
    
    def decoding(self, symbols):
        encoderOut = wireless.general.vectori(symbols)

        if self.demap is not None:
            # the decoder works with LLRs, demap and then decode
            self.demap.process(encoderOut, self.n0, self.demapperBuffer)
            self.decoder.add(self.demapperBuffer)
        else:
            # the decoder works on symbols directly
            self.decoder.add(encoderOut, self.n0)
        decodeResult = self.decoder.decode()
        self.pktno += 1     # add the counter
        if self.verbosity >= 3:
            self.print_pkt(decodeResult.packet, 'decode')    
        return decodeResult.packet

    def tx_reset(self):
        self.protocol.resetPacket(0)
        self.curPacket = None
        self.curCrc32 = None
        self.pktno = 0
        self.lastNumChannelSymbols = 0
        self.tx_done = True

    def rx_reset(self):
        self.decoder.reset()
        self.curCrc32 = None
        self.pktno = 0
        self.rx_success = False

    def rx_is_success(self, decodeOut):
        crc = digital.crc32(decodeOut)
        is_success = (crc == self.curCrc32)
        if is_success:
            print "decoding success!\n"
        else:
            print "decoding not done yet...\n"
        return is_success

    def run_pkt(self, packet):
        '''
        A simple simulator.
        '''
        self.tx_reset()
        self.rx_reset()

        self.tx_set_pkt(packet) 
        
        count = 0
        decoderOut = ''  
        
        print "drop odd-pktno packet"
        while not self.rx_is_success(decoderOut):
            count += 1
            print '\ntry %d' % count
            pkt = self.tx_next_pkt()
            # we drop odd-pktno packet
            pkt = self.tx_next_pkt()
            (ok, pktno, symbols, crc32) = self.unpack_pkt(pkt)
            print "ok: %r  pktno: %r  crc32: 0x%x" % (ok, pktno, crc32)
            self.print_pkt(packet)
            decoderOut = self.decoding(symbols)
            # raw_input()
            
        print '\ndone! %d tries\n' % count
    
    def getComponents(self, experiment):
        """
        Makes the components needed for the experiment specified by 'experiment'
        """
        try:
            self.prePacketManipulator = self.factories.make('make_pre_packet_manipulator', experiment)
        except:
            self.prePacketManipulator = None
            
        self.packetGen = self.factories.make('make_packet_generator', experiment['packetGen'])
        self.encoder, self.encoderVectorType = self.factories.make('make_encoder',
                                           experiment['code'], 
                                           experiment['packetGen']['length'])
        self.mapper, self.mapperVectorType, self.Es = \
                        self.factories.make('make_mapper', experiment['map'])
        self.channel, self.channelVectorType, self.n0 = \
                        self.factories.make('make_channel', experiment['channel'],
                                                 self.Es)
        self.demap, self.demapType = \
                self.factories.make('make_demapper', experiment['map'], experiment['demap'])
        self.decoder = self.factories.make('make_decoder',
                                           experiment['code'], 
                                           experiment['packetGen']['length'],
                                           experiment['decoder'],
                                           experiment['map'],
                                           experiment['channel'])
        self.detector = self.factories.make('make_detector',
                                            experiment['detector'],
                                            experiment['code'],
                                            experiment['packetGen']['length'],
                                            self.Es)
        self.protocol = self.factories.make('make_protocol',
                                            experiment['protocol'],
                                            experiment['code'],
                                            experiment['packetGen']['length'])
        
        self.statistics = self.factories.make('make_statistics', experiment['statistics'])
        self.statistics.reset()

        # buffers between components
        self.encodeBuffer = self.encoderVectorType();
        
        if self.mapper is not None:
            self.mapperBuffer = self.mapperVectorType();
        else:
            self.mapperBuffer = self.encodeBuffer
            
        self.channelBuffer = self.channelVectorType();
        
        if self.demap is not None:
            self.demapperBuffer = self.demapType();

        
    def seed(self, seed):
        """
        Seeds all components with the given seed
        """
        self.random.seed(seed)
        self.packetGen.seed(self.random.tomaxint(4).astype(numpy.uint32))
        self.channel.seed(self.random.tomaxint(4).astype(numpy.uint32))
        
        if self.prePacketManipulator is not None:
            if 'seed' in dir(self.prePacketManipulator):
                self.prePacketManipulator.seed(self.random.randint(1,1<<62))
        
if __name__ == '__main__':
    experimentSpec = {
        'packetGen': {'type': 'random',
                      'length': 300},
        'code': {'type': 'spinal',
                 'puncturing': {'type': '8-way-v2',
                                'numLastCodeStep': 2},
                 'hash': 'one-at-a-time',
                 'bitsPerSymbol': 10,
                 'k': 3},
        'map': {'type': 'linear',
                'bitsPerSymbol': 10,
                'precisionBits': 14},
        'channel': {'type': 'AWGN',
                    'SNR_dB': 10},
        'demap': {'type': 'null'},
        'decoder': {'type': 'regular',
                   'beamWidth': 16,
                   'maxPasses': 48*8},
        'detector': {'type': 'oracle'},
        'protocol': {'type': 'sequential',
                     'maxPasses': 48*8},
        'statistics': {'type': 'errors'}
        }
    spinal = Spinal(experimentSpec, 
                    numpy.random.RandomState().tomaxint(4), 
                    3)

    packet = spinal.gen_raw_pkt()

    spinal.run_pkt(packet)    

    packet = spinal.gen_raw_pkt()

    spinal.run_pkt(packet)

 

