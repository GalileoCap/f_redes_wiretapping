#!/usr/bin/env python3
import scapy.all as scapy
import pandas as pd
import numpy as np

from datetime import datetime
import sys
import os

import utils

class Experiment:
  def __init__(self, user, name):
    self.user = user; self.name = name
    self.fbase = utils.experimentName(user, name)
    self.mkDir()

  #************************************************************
  #* Sniff ****************************************************

  def sniff(self):
    print(f'[{self.fbase}.sniff]: now={datetime.now()}\nPress Ctrl+C to stop')
    self.totalPkts = 0
    self.pcap = scapy.sniff(
      lfilter = lambda pkt: pkt.haslayer(scapy.Ether),
      prn = self.sniffCallback,
    )
    return self

  def sniffCallback(self, pkt):
    self.totalPkts += 1
    if (self.totalPkts % 10) == 0:
      print(f'\rtotalPkts={self.totalPkts}', end = '')

  #************************************************************
  #* Process **************************************************

  def process(self, *, save = True, load = True):
    print(f'[{self.fbase}.analyze] {save=}, {load=}')
  
    self.getPcapDf(save, load)
    self.getSymbolsDf(save, load)

    return self

  def getPcapDf(self, save = True, load = True):
    fpath = utils.dfPath(self.fbase, 'pcap')
    if load and os.path.isfile(fpath):
      self.pcapDf = pd.read_csv(fpath, index_col = 0)
      return

    start_time = self.pcap[0].time
    self.pcapDf = pd.DataFrame([
      self.processPkt(pkt, start_time = start_time)
      for pkt in self.pcap
    ])

    if save:
      self.pcapDf.to_csv(fpath)
    return self
    
  def processPkt(self, pkt, *, start_time):
    return {
      'dire': 'BROADCAST' if pkt[scapy.Ether].dst == 'ff:ff:ff:ff:ff:ff' else 'UNICAST',
      'proto': pkt[scapy.Ether].type, # El campo type del frame tiene el protocolo #TODO: To string
      'dt': pkt.time - start_time,
    }
   
  def getSymbolsDf(self, save = True, load = True):
    #TODO: Repeated code with getPcapDf
    fpath = utils.dfPath(self.fbase, 'symbols')
    if load and os.path.isfile(fpath):
      self.symbolsDf = pd.read_csv(fpath, index_col = 0)
      return

    symbols = '(' + self.pcapDf['dire'] + ', ' + self.pcapDf['proto'].astype(str) + ')'
    counts = symbols.value_counts()
    self.symbolsDf = pd.DataFrame([
      {
        'symbol': symbol, 
        'p': counts[symbol] / len(self.pcapDf),
        'count': counts[symbol]
      }
      for symbol in list(symbols.unique())
    ])
    self.symbolsDf['information'] = -np.log2(self.symbolsDf['p'])
    
    if save:
      self.symbolsDf.to_csv(fpath)
    return self

  #************************************************************
  #* Report ***************************************************

  def report(self):
    print(f'[{self.fbase}.report]')

    H = (self.symbolsDf['p'] * self.symbolsDf['information']).sum()
    print(self.symbolsDf, f'Tramas: {self.symbolsDf["count"].sum()}', f'Entropy: {H}', sep = '\n')

    return self
  
  #************************************************************
  #* Utils ****************************************************

  def loadPcap(self):
    print(f'[{self.fbase}.loadPcap]')
    fpath = utils.pcapPath(self.fbase)
    self.pcap = scapy.rdpcap(fpath)
    return self

  def savePcap(self):
    print(f'[{self.fbase}.savePcap]')
    fpath = utils.pcapPath(self.fbase)
    scapy.wrpcap(fpath, self.pcap)
    return self

  def mkDir(self):
    os.makedirs(utils.experimentPath(self.fbase), exist_ok = True)
