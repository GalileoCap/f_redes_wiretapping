#!/usr/bin/env python3
from scapy.all import Ether

import pandas as pd
import numpy as np

from argparse import ArgumentParser
import os

from utils import dfExists, saveDf, readDf, readPcap

def processPkt(pkt, *, start_time):
  return {
    'dire': 'BROADCAST' if pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' else 'UNICAST',
    'proto': pkt[Ether].type, # El campo type del frame tiene el protocolo
    'dt': pkt.time - start_time,
  }

def getPktsDf(pkts):
  start_time = pkts[0].time
  return pd.DataFrame([
    processPkt(pkt, start_time = start_time)
    for pkt in pkts
  ])

def getSymbolsDf(pkts):
  pktsDf = getPktsDf(pkts)

  symbols = '(' + pktsDf['dire'] + ', ' + pktsDf['proto'].astype(str) + ')'
  counts = symbols.value_counts()
  return pd.DataFrame([
    {'symbol': symbol, 'p': counts[symbol] / len(pkts), 'count': counts[symbol]}
    for symbol in list(symbols.unique())
  ])

def analyzeSymbols(symbols):
  symbols['information'] = -np.log2(symbols['p'])
  H = (symbols['p'] * symbols['information']).sum()

  print(symbols, f'Tramas: {symbols["count"].sum()}', f'Entropy: {H}', sep = '\n')
  return symbols

def analyzePcap(user, experiment):
  pkts = readPcap(user, experiment)
  symbols = getSymbolsDf(pkts)
  analyzeSymbols(symbols)
  return symbols

def analyzeAndSavePcap(user, experiment):
  symbols = analyzePcap(user, experiment)
  saveDf(symbols, user, experiment)

if __name__ == '__main__':
  parser = ArgumentParser(
    prog = 'analyze',
    description = '', #TODO
  )
  parser.add_argument('experiment', nargs = 2, help = '{USER} {EXPERIMENT_NAME}')
  parser.add_argument('-f', '--force', default = False, help = 'Replace previously saved csv')
  args = parser.parse_args()

  user, experiment = args.experiment

  if args.force:
    analyzeAndSavePcap(user, experiment) 
  elif dfExists(user, experiment):
    symbols = readDf(user, experiment)
    analyzeSymbols(symbols)
  else:
    analyzeAndSavePcap(user, experiment) 
