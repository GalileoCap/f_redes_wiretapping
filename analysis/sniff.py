#!/usr/bin/env python3
from scapy.all import *

import pandas as pd
import numpy as np

from time import time
import sys
import os

OUTDIR = './out'

def savePkts(pkts, fpath):
  os.makedirs(OUTDIR, exist_ok = True)
  pkts.to_csv(fpath)

def callback(pkt, *, start_time):
  return {
    'dire': 'BROADCAST' if pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' else 'UNICAST',
    'proto': pkt[Ether].type, # El campo type del frame tiene el protocolo
    'dt': time() - start_time,
  }

def sniffPkts(count = 10):
  start_time = time()

  res = []
  sniff(
    count,
    lfilter = lambda pkt: pkt.haslayer(Ether),
    prn = lambda pkt: res.append(callback(pkt, start_time = start_time))
  )
  return pd.DataFrame(res)

def experiment(user, name):
  pkts = pd.DataFrame()
  fpath = f'{OUTDIR}/{user}_{name}.csv.tar.gz'
  try:
    pkts = pd.read_csv(fpath)
  except:
    pkts = sniffPkts(10000)
    savePkts(pkts, fpath)

if __name__ == '__main__':
  if len(sys.argv) != 3:
    print('usage: sudo python sniff.py {USER} {EXPERIMENT_NAME}')
  else:
    experiment(sys.argv[1], sys.argv[2])
