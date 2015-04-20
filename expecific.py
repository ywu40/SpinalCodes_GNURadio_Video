
# /////////////////////////////////////////////////////////////////////////////
#                         spinal experiment specific
# /////////////////////////////////////////////////////////////////////////////

experimentSpec = {
    'packetGen': {'type': 'random',
                  'length': 9600},
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

