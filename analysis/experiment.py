#!/usr/bin/env python3
import scapy.all as scapy
import pandas as pd
import numpy as np

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

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

  def sniff(self, *, save = True):
    print(f'[{self.fbase}.sniff]: now={datetime.now()}\nPress Ctrl+C to stop')
    self.totalPkts = 0
    self.pcap = scapy.sniff(
      lfilter = lambda pkt: pkt.haslayer(scapy.Ether),
      prn = self.sniffCallback,
    )

    if save:
      self.savePcap()
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

    if not hasattr(self, 'pcap') or self.pcap is None:
      self.loadPcap()
    start_time = self.pcap[0].time
    self.pcapDf = pd.DataFrame([
			{
				'dire': 'BROADCAST' if pkt[scapy.Ether].dst == 'ff:ff:ff:ff:ff:ff' else 'UNICAST',
				'proto': utils.getTypeStr(pkt[scapy.Ether].type), # El campo type del frame tiene el protocolo
				'dt': pkt.time - start_time,
			}
      for pkt in self.pcap
    ])
    self.pcapDf['symbol'] = '(' + self.pcapDf['dire'] + ', ' + self.pcapDf['proto'] + ')'

    if save:
      self.pcapDf.to_csv(fpath)
    return self
   
  def getSymbolsDf(self, save = True, load = True):
    #TODO: Repeated code with getPcapDf
    fpath = utils.dfPath(self.fbase, 'symbols')
    if load and os.path.isfile(fpath):
      self.symbolsDf = pd.read_csv(fpath, index_col = 0)
      return

    counts = self.pcapDf['symbol'].value_counts()
    self.symbolsDf = pd.DataFrame([
      {
        'symbol': symbol, 
        'p': counts[symbol] / len(self.pcapDf),
        'count': counts[symbol]
      }
      for symbol in list(self.pcapDf['symbol'].unique())
    ])
    self.symbolsDf['information'] = -np.log2(self.symbolsDf['p'])
    
    if save:
      self.symbolsDf.to_csv(fpath)
    return self

  #************************************************************
  #* Report ***************************************************

  def report(self):
    print(f'[{self.fbase}.report]')

    self.reportOverall()
    self.reportHITime()

    return self

  def reportOverall(self):
    H = (self.symbolsDf['p'] * self.symbolsDf['information']).sum()
    print(self.symbolsDf, f'Tramas: {self.symbolsDf["count"].sum()}', f'Entropy: {H}', sep = '\n')

  def reportHITime(self):
    # H and I (per type), over time
    # TODO: Optimize
    symbols = {symbol: {'count': 0, 'p': 0, 'I': 0} for symbol in self.symbolsDf['symbol']}
    H = []
    def foo(row):
      symbolState = symbols[row['symbol']]
      symbolState['count'] += 1
      symbolState['p'] = symbolState['count'] / sum([state['count'] for _, state in symbols.items()])
      symbolState['I'] = -np.log2(symbolState['p'])

      H.append(sum([
        state['p'] * state['I']
        for _, state in symbols.items()
      ]))
      res = {}
      for symbol, state in symbols.items():
        res[f'{symbol}_count'] = state['count']
        res[f'{symbol}_p'] = state['p']
        res[f'{symbol}_I'] = state['I']
      return pd.Series(res)

    df = self.pcapDf.apply(foo, axis = 'columns')
    fig = go.Figure()
    for symbol in self.symbolsDf['symbol']:
      fig.add_trace(go.Scatter(
        # x = ,
        y = df[f'{symbol}_I'],
        name = symbol,
      ))
    fig.add_trace(go.Scatter(
      # x = ,
      y = H,
      name = 'H',
    ))
    fig.update_layout(
      # title = f'Relación entre el tiempo resolver y el tiempo para calcular LU ({reps} reps)',
      xaxis_title = 'Time', # TODO: Not time
      yaxis_title = 'Information',
    )
    fig.write_image(utils.imgPath(self.fbase, 'hitime'))
  
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
