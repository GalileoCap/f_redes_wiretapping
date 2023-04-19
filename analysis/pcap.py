#!/usr/bin/env python3
from scapy.all import *

import pandas as pd
import numpy as np

import sys

from analyze import processPkt, analyzePkts
from utils import savePkts, getOPath, getIPath

def processPcap(fpath):
  pkts = rdpcap(fpath)
  return pd.DataFrame([
    processPkt(pkt, start_time = 0) #TODO: start_time
    for pkt in pkts
  ])

def analyzePcap(user, name):
  pkts = processPcap(getIPath(user, name))
  savePkts(pkts, getOPath(user, name))

  analyzePkts(pkts)

if __name__ == '__main__':
  if len(sys.argv) != 3:
    print('usage: sudo python pcap.py {USER} {EXPERIMENT_NAME}')
  else:
    analyzePcap(sys.argv[1], sys.argv[2])
