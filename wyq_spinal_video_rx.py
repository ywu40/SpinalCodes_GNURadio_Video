#!/usr/bin/env python
#
# Copyright 2005,2006,2009,2011 Free Software Foundation, Inc.
# 
# This file is part of GNU Radio
# 
# GNU Radio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with GNU Radio; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 


# ////////////////////////////////////////////////////////////////////
#
#    This code sets up up a virtual ethernet interface (typically
#    gr0), and relays packets between the interface and the GNU Radio
#    PHY+MAC
#
#    What this means in plain language, is that if you've got a couple
#    of USRPs on different machines, and if you run this code on those
#    machines, you can talk between them using normal TCP/IP
#    networking.
#
# ////////////////////////////////////////////////////////////////////


from gnuradio import gr, digital
from gnuradio import eng_notation
from gnuradio.eng_option import eng_option
from optparse import OptionParser

# from current dir
from receive_path  import receive_path
from transmit_path import transmit_path
from uhd_interface import uhd_transmitter
from uhd_interface import uhd_receiver

from spinal_video import Spinal
from expecific import experimentSpec

import os, sys
import random, time, struct
import numpy

#print os.getpid()
#raw_input('Attach and press enter')

# ////////////////////////////////////////////////////////////////////
#
#   Use the Universal TUN/TAP device driver to move packets to/from
#   kernel
#
#   See /usr/src/linux/Documentation/networking/tuntap.txt
#
# ////////////////////////////////////////////////////////////////////

# Linux specific...
# TUNSETIFF ifr flags from <linux/tun_if.h>

IFF_TUN		= 0x0001   # tunnel IP packets
IFF_TAP		= 0x0002   # tunnel ethernet frames
IFF_NO_PI	= 0x1000   # don't pass extra packet info
IFF_ONE_QUEUE	= 0x2000   # beats me ;)

def open_tun_interface(tun_device_filename):
    from fcntl import ioctl
    
    mode = IFF_TAP | IFF_NO_PI
    TUNSETIFF = 0x400454ca

    tun = os.open(tun_device_filename, os.O_RDWR)
    ifs = ioctl(tun, TUNSETIFF, struct.pack("16sH", "gr%d", mode))
    ifname = ifs[:16].strip("\x00")
    return (tun, ifname)
    

# ////////////////////////////////////////////////////////////////////
#                     the flow graph
# ////////////////////////////////////////////////////////////////////

class my_top_block(gr.top_block):

    def __init__(self, mod_class, demod_class,
                 rx_callback, options):

        gr.top_block.__init__(self)

        # Get the modulation's bits_per_symbol
        args = mod_class.extract_kwargs_from_options(options)
        symbol_rate = options.bitrate / mod_class(**args).bits_per_symbol()

        self.source = uhd_receiver(options.args, symbol_rate,
                                   options.samples_per_symbol,
                                   options.rx_freq, options.rx_gain,
                                   options.spec, options.antenna,
                                   options.verbose)
        
        self.sink = uhd_transmitter(options.args, symbol_rate,
                                    options.samples_per_symbol,
                                    options.tx_freq, options.tx_gain,
                                    options.spec, options.antenna,
                                    options.verbose)
        
        options.samples_per_symbol = self.source._sps

        self.txpath = transmit_path(mod_class, options)
        self.rxpath = receive_path(demod_class, rx_callback, options)
        self.connect(self.txpath, self.sink)
        self.connect(self.source, self.rxpath)

    def send_pkt(self, payload='', eof=False):
        return self.txpath.send_pkt(payload, eof)

    def carrier_sensed(self):
        """
        Return True if the receive path thinks there's carrier
        """
        return self.rxpath.carrier_sensed()

    def set_freq(self, target_freq):
        """
        Set the center frequency we're interested in.
        """

        self.sink.set_freq(target_freq)
        self.source.set_freq(target_freq)
        

# ////////////////////////////////////////////////////////////////////
#                           Carrier Sense MAC
# ////////////////////////////////////////////////////////////////////

isDecSuccess = False
prevCrc32 = None

class cs_mac(object):
    """
    Prototype carrier sense MAC

    Reads packets from the TUN/TAP interface, and sends them to the
    PHY. Receives packets from the PHY via phy_rx_callback, and sends
    them into the TUN/TAP interface.

    Of course, we're not restricted to getting packets via TUN/TAP,
    this is just an example.
    """

    def __init__(self, spinal, received_file, verbose=False):
        #self.tun_fd = tun_fd       # file descriptor for TUN/TAP interface
        self.spinal = spinal       # spinal instance
        self.received_file = received_file
        self.verbose = verbose
        self.tb = None             # top block (access to PHY)

    def set_top_block(self, tb):
        self.tb = tb

    def phy_rx_callback(self, ok, payload):
        """
        Invoked by thread associated with PHY to pass received packet up.

        Args:
            ok: bool indicating whether payload CRC was OK
            payload: contents of the packet (string)
        """
        global isDecSuccess
        global prevCrc32

        if self.spinal.rx_success:
            print "[warring] decoding done and receiver hasn't been reseted, but a new pkt received."
            print "[warring] discard it and go on."
            pass
       
        #if len(payload) > 58:
        #    print "len(payload) > 58, we can't handle it now. pass and go on.\n"
        #    pass

        if self.verbose:
            print "Rx: ok = %r  len(payload) = %4d" % (ok, len(payload))
            #print "payload = 0x%s" % ''.join(x.encode('hex') for x in payload)

        #if ok:
        #    os.write(self.tun_fd, payload)

        (pkt_ok, pktno, symbols, thisCrc32) = self.spinal.unpack_pkt(payload)
        
        if not pkt_ok:
            print "[warring] payload unpack faid. len(payload) < 6"
            print "[warring] discard it and go on."
            pass

        #print "isDecSuccess: %4d" % isDecSuccess
        # if the ofdm crc check is passed, we set or update the curCrc32 value 
        if ok:
            if isDecSuccess == True and prevCrc32 == thisCrc32:
                #print "1: here should return"
                return
            if self.spinal.curCrc32 is None:
                self.spinal.curCrc32 = thisCrc32
                isDecSuccess = False
            if self.spinal.curCrc32 != thisCrc32:
                print "Attention: a strange crc value received!"
                print "The sender may be misleaded or some serious errors occured."
                #print "But we update the crc value."
                #self.spinal.curCrc32 = thisCrc32

        #print "2: still be here?"
        prevCrc32 = thisCrc32
        
        # whether the ofdm crc check is passed or not, the received pkts is used for decoding
        #if 1:
        decodeOut = ''
        if ok:
            decodeOut = self.spinal.decoding(symbols)
            #self.spinal.pktno += 1      # count the passes received by now
        
        if self.spinal.rx_is_success(decodeOut):
            print "************Done!**************"
            self.spinal.rx_success = True   # triger the ack sending process. XXX mutexing problems?
            isDecSuccess = True
            self.received_file.write(decodeOut)



    def main_loop(self):
        """
        Main loop for MAC.
        Only returns if we get an error reading from TUN.

        FIXME: may want to check for EINTR and EAGAIN and reissue read
        """
        min_delay = 0.001               # seconds

        while 1:
            #payload = os.read(self.tun_fd, 10*1024)
            #if not payload:
            #    self.tb.send_pkt(eof=True)
            #    break

            while not self.spinal.rx_success:       # before decoding success, sending routine spins here.
                time.sleep(min_delay / 100)
            
            '''
                the ACK msg's layout shown below:
                    +-------------------+
                    | tries |    crc    |
                    +-------------------+
                tries:
                    pkts used to successfully decode the original message.
                crc:
                    crc value of the original message.
            '''
            packet = self.spinal.pack_ack()


            if self.verbose:
                print "Tx: len(payload) = %4d" % (len(packet),)

            delay = min_delay
            while self.tb.carrier_sensed():
                sys.stderr.write('B')
                time.sleep(delay)
                if delay < 0.050:
                    delay = delay * 2       # exponential back-off

            #self.tb.send_pkt(payload)
            self.tb.txpath.send_pkt(packet)
            
            # reset rx states after sending ack
            self.spinal.rx_reset()



# /////////////////////////////////////////////////////////////////////////////
#                                   main
# /////////////////////////////////////////////////////////////////////////////

def main():

    mods = digital.modulation_utils.type_1_mods()
    demods = digital.modulation_utils.type_1_demods()

    parser = OptionParser (option_class=eng_option, conflict_handler="resolve")
    expert_grp = parser.add_option_group("Expert")
    parser.add_option("-m", "--modulation", type="choice", choices=mods.keys(),
                      default='gmsk',
                      help="Select modulation from: %s [default=%%default]"
                            % (', '.join(mods.keys()),))

    parser.add_option("-s", "--size", type="eng_float", default=1500,
                      help="set packet size [default=%default]")
    parser.add_option("-v","--verbose", action="store_true", default=False)
    expert_grp.add_option("-c", "--carrier-threshold", type="eng_float", default=30,
                          help="set carrier detect threshold (dB) [default=%default]")
    expert_grp.add_option("","--tun-device-filename", default="/dev/net/tun",
                          help="path to tun device file [default=%default]")

    transmit_path.add_options(parser, expert_grp)
    receive_path.add_options(parser, expert_grp)
    uhd_receiver.add_options(parser)
    uhd_transmitter.add_options(parser)

    for mod in mods.values():
        mod.add_options(expert_grp)

    for demod in demods.values():
        demod.add_options(expert_grp)

    (options, args) = parser.parse_args ()
    if len(args) != 0:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # open the TUN/TAP interface
    #(tun_fd, tun_ifname) = open_tun_interface(options.tun_device_filename)

    if options.rx_freq is None or options.tx_freq is None:
        sys.stderr.write("You must specify -f FREQ or --freq FREQ\n")
        parser.print_help(sys.stderr)
        sys.exit(1)

    received_file = open ('./output.264', 'w')

    # get a Spinal instance
    spinal = Spinal(experimentSpec, 
                    numpy.random.RandomState().tomaxint(4), 
                    3)

    # Attempt to enable realtime scheduling
    r = gr.enable_realtime_scheduling()
    if r == gr.RT_OK:
        realtime = True
    else:
        realtime = False
        print "Note: failed to enable realtime scheduling"

    # instantiate the MAC
    #mac = cs_mac(tun_fd, verbose=True)
    mac = cs_mac(spinal, received_file, verbose=True)

    # build the graph (PHY)
    tb = my_top_block(mods[options.modulation],
                      demods[options.modulation],
                      mac.phy_rx_callback,
                      options)

    mac.set_top_block(tb)    # give the MAC a handle for the PHY

    if tb.txpath.bitrate() != tb.rxpath.bitrate():
        print "WARNING: Transmit bitrate = %sb/sec, Receive bitrate = %sb/sec" % (
            eng_notation.num_to_str(tb.txpath.bitrate()),
            eng_notation.num_to_str(tb.rxpath.bitrate()))
             
    print "modulation:     %s"   % (options.modulation,)
    print "freq:           %s"      % (eng_notation.num_to_str(options.tx_freq))
    print "bitrate:        %sb/sec" % (eng_notation.num_to_str(tb.txpath.bitrate()),)
    print "samples/symbol: %3d" % (tb.txpath.samples_per_symbol(),)

    tb.rxpath.set_carrier_threshold(options.carrier_threshold)
    print "Carrier sense threshold:", options.carrier_threshold, "dB"
    
    #print
    #print "Allocated virtual ethernet interface: %s" % (tun_ifname,)
    #print "You must now use ifconfig to set its IP address. E.g.,"
    #print
    #print "  $ sudo ifconfig %s 192.168.200.1" % (tun_ifname,)
    #print
    #print "Be sure to use a different address in the same subnet for each machine."
    #print


    tb.start()    # Start executing the flow graph (runs in separate threads)

    mac.main_loop()    # don't expect this to return...

    tb.stop()     # but if it does, tell flow graph to stop.
    tb.wait()     # wait for it to finish
    received_file.close()
                

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
