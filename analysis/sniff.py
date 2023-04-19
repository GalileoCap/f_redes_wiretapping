#!/usr/bin/env python3
from scapy.all import *

from argparse import ArgumentParser
from datetime import datetime
import sys

from analyze import analyzeAndSavePcap
from utils import savePcap

totalPkts = 0
def callback(pkt):
  global totalPkts
  totalPkts += 1
  if (totalPkts % 10) == 0:
    print(f'\r{totalPkts=}', end = '')

def sniffPkts():
  print(f'[sniffPkts] now={datetime.now()}\nPress Ctrl+C to stop')

  pkts = sniff(
    lfilter = lambda pkt: pkt.haslayer(Ether),
    prn = callback,
  )

  print()
  return pkts

if __name__ == '__main__':
  parser = ArgumentParser(
    prog = 'sniff',
    description = '', #TODO
  )
  parser.add_argument('experiment', nargs = 2, help = '{USER} {EXPERIMENT_NAME}')
  args = parser.parse_args()

  user, experiment = args.experiment

  pkts = sniffPkts()
  savePcap(pkts, user, experiment)
  analyzeAndSavePcap(user, experiment)
