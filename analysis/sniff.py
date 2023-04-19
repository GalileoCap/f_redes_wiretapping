#!/usr/bin/env python3
from scapy.all import *

import pandas as pd
import numpy as np

from datetime import datetime
from time import time
import sys

from analyze import processPkt, analyzePkts
from utils import getOPath, savePkts

totalPkts = 0
def callback(pkt, start_time):
  global totalPkts
  totalPkts += 1
  if (totalPkts % 10) == 0:
    print(f'\r{totalPkts=}', end = '')

  return processPkt(pkt, start_time = start_time)

def sniffPkts():
  print(f'[sniffPkts] now={datetime.now()}')
  start_time = time()

  res = []
  sniff(
    lfilter = lambda pkt: pkt.haslayer(Ether),
    prn = lambda pkt: res.append(callback(pkt, start_time))
  )
  print()
  return pd.DataFrame(res)

def experiment(user, name):
  pkts = pd.DataFrame()
  fpath = getOPath(user, name)
  try:
    pkts = pd.read_csv(fpath)
  except:
    pkts = sniffPkts()
    savePkts(pkts, fpath)

  analyzePkts(pkts)

if __name__ == '__main__':
  if len(sys.argv) != 3:
    print('usage: sudo python sniff.py {USER} {EXPERIMENT_NAME}')
  else:
    experiment(sys.argv[1], sys.argv[2])
