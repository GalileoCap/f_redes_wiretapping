#!/usr/bin/env python3
from scapy.all import *

import pandas as pd
import numpy as np

from datetime import datetime
from time import time
import sys
import os

OUTDIR = './out'

def savePkts(pkts, fpath):
  print('[savePkts]')
  os.makedirs(OUTDIR, exist_ok = True)
  pkts.to_csv(fpath)

def callback(pkt, *, start_time):
  return {
    'dire': 'BROADCAST' if pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' else 'UNICAST',
    'proto': pkt[Ether].type, # El campo type del frame tiene el protocolo
    'dt': time() - start_time,
  }

def sniffPkts():
  print(f'[sniffPkts] now={datetime.now()}')
  start_time = time()

  res = []
  sniff(
    lfilter = lambda pkt: pkt.haslayer(Ether),
    prn = lambda pkt: res.append(callback(pkt, start_time = start_time))
  )
  return pd.DataFrame(res)

def getSymbolsDf(pkts):
  symbols = '(' + pkts['dire'] + ', ' + pkts['proto'].astype(str) + ')'
  counts = symbols.value_counts(normalize = True)
  return pd.DataFrame([
    {'symbol': symbol, 'p': counts[symbol]}
    for symbol in list(symbols.unique())
  ])

def experiment(user, name):
  pkts = pd.DataFrame()
  fpath = f'{OUTDIR}/{user}_{name}.csv.tar.gz'
  try:
    pkts = pd.read_csv(fpath)
  except:
    pkts = sniffPkts()
    savePkts(pkts, fpath)

  symbols = getSymbolsDf(pkts)
  symbols['information'] = -np.log2(symbols['p'])
  H = (symbols['p'] * symbols['information']).sum()
  print(symbols, f'Entropy: {H}', sep = '\n')

if __name__ == '__main__':
  if len(sys.argv) != 3:
    print('usage: sudo python sniff.py {USER} {EXPERIMENT_NAME}')
  else:
    experiment(sys.argv[1], sys.argv[2])
