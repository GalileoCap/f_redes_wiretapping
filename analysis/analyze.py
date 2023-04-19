#!/usr/bin/env python3
from scapy.all import *

import pandas as pd
import numpy as np

from time import time

def processPkt(pkt, *, start_time):
  return {
    'dire': 'BROADCAST' if pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' else 'UNICAST',
    'proto': pkt[Ether].type, # El campo type del frame tiene el protocolo
    'dt': pkt.time - start_time,
  }

def getSymbolsDf(pkts):
  symbols = '(' + pkts['dire'] + ', ' + pkts['proto'].astype(str) + ')'
  counts = symbols.value_counts(normalize = True)
  return pd.DataFrame([
    {'symbol': symbol, 'p': counts[symbol]}
    for symbol in list(symbols.unique())
  ])

def analyzePkts(pkts):
  symbols = getSymbolsDf(pkts)
  symbols['information'] = -np.log2(symbols['p'])
  H = (symbols['p'] * symbols['information']).sum()
  print(symbols, f'Tramas: {len(pkts)}', f'Entropy: {H}', sep = '\n')
