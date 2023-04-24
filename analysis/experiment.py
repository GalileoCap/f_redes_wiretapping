#!/usr/bin/env python3
import scapy.all as scapy
import pandas as pd
import numpy as np

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

from datetime import datetime
from time import time
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
    self.getFooDf(save, load)
    self.getOptDf(save, load)

    return self

  def getPcapDf(self, save = True, load = True):
    fpath = utils.dfPath(self.fbase, 'pcap')
    if load and os.path.isfile(fpath):
      self.pcapDf = pd.read_csv(fpath, index_col = 0)
      return

    self.loadPcap()
    # self.pcap = self.pcap[:min(20000, len(self.pcap))]
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

  def getOptDf(self, save = True, load = True):
    #TODO: Repeated code with getPcapDf
    fpath = utils.dfPath(self.fbase, 'opt')
    if load and os.path.isfile(fpath):
      self.optDf = pd.read_csv(fpath, index_col = 0)
      return
  
    self.loadPcap()
    self.optDf = pd.DataFrame([
      {
        'ptype': pkt[scapy.ARP].ptype,
        'psrc': pkt[scapy.ARP].psrc,
        'pdst': pkt[scapy.ARP].pdst,
        'hwtype': pkt[scapy.ARP].hwtype,
        'hwsrc': pkt[scapy.ARP].hwsrc,
        'hwdst': pkt[scapy.ARP].hwdst,
        'op': "whois" if pkt[scapy.ARP].op == 1 else "reply",
      }
      for pkt in self.pcap
      if pkt.haslayer(scapy.Ether) and pkt[scapy.Ether].type == 0x0806 # Is ARP
    ])
    
    if save:
      self.optDf.to_csv(fpath)

  def getFooDf(self, save = True, load = True):
    fpath = utils.dfPath(self.fbase, 'foo')
    if load and os.path.isfile(fpath):
      self.fooDf = pd.read_csv(fpath, index_col = 0)
      return

    df = self.pcapDf.apply(
      lambda row: pd.Series({
        symbol: int(symbol == row['symbol'])
        for symbol in self.symbolsDf['symbol']
      }),
      axis = 'columns'
    )
    for symbol in self.symbolsDf['symbol']:
      df[f'{symbol}_count'] = df[symbol].cumsum()
      df[f'{symbol}_p'] = df[f'{symbol}_count'] / (df.index + 1)
      np.seterr(divide = 'ignore') # SEE: https://stackoverflow.com/a/53357052
      df[f'{symbol}_I'] = -np.log2(df[f'{symbol}_p'])
      np.seterr(divide = 'warn')
      df[f'{symbol}_H'] = df[f'{symbol}_p'] * df[f'{symbol}_I']
    df.replace([np.inf, -np.inf], 0, inplace = True)
    df['H'] = df[[f'{symbol}_H' for symbol in self.symbolsDf['symbol']]].sum(axis = 'columns')

    self.fooDf = df
    if save:
      self.fooDf.to_csv(fpath)

  #************************************************************
  #* Report ***************************************************

  def report(self):
    print(f'[{self.fbase}.report]')

    self.reportMsg = f'# Report for **{self.fbase}**'

    self.reportOverall()
    self.reportCounts()
    self.reportHITime()
    self.reportOpt()

    print(self.reportMsg)
    with open(utils.mdPath(self.fbase, 'report'), 'w') as fout:
      fout.write(self.reportMsg)

    return self

  def reportOverall(self):
    H = (self.symbolsDf['p'] * self.symbolsDf['information']).sum()

    self.addReport('Overall', [
        f'Tramas: {len(self.pcapDf)}',
        f'Entropy: {H}',
        '\n' + self.symbolsDf.sort_values("information", ascending = False).to_string(index = False)
    ])

    self.reportPct()
    self.reportInformation()
    self.reportBroadcast()

  def reportPct(self):
    self.plotBar(
      self.symbolsDf, 'symbol', 'p',
      name = 'pct', title = 'pct', xaxis_title = 'Symbol', yaxis_title = '% of total packets',
    )

  def reportInformation(self):
    self.plotBar(
      self.symbolsDf, 'symbol', 'information',
      name = 'info', title = 'Information', xaxis_title = 'Symbol', yaxis_title = 'Information',
    )

  def reportBroadcast(self):
    counts = self.pcapDf['dire'].value_counts()
    df = pd.DataFrame(counts)
    df['type'] = df.index
    df['p'] = df['count'] / counts.sum()
    self.plotBar(
      df, 'type', 'p',
      name = 'unibroadcast', title = 'Unibroadcast', xaxis_title = 'Tipo', yaxis_title = '% de los paquetes',
    )

  def reportCounts(self):
    fig = go.Figure()
    for symbol in self.symbolsDf['symbol']:
      fig.add_trace(go.Scatter(
        y = self.fooDf[f'{symbol}_count'],
        name = symbol,
      ))
    fig.update_layout(
      # title = f'Relación entre el tiempo resolver y el tiempo para calcular LU ({reps} reps)',
      xaxis_title = 'Time', # TODO: Not time
      yaxis_title = 'Count of packets',
    )
    utils.saveFig(fig, self.fbase, 'counts')

  def reportHITime(self):
    # H and I (per type), over time

    fig = go.Figure()
    for symbol in self.symbolsDf['symbol']:
      fig.add_trace(go.Scatter(
        y = self.fooDf[f'{symbol}_I'],
        name = symbol,
      ))
    fig.add_trace(go.Scatter(
      y = self.fooDf['H'],
      name = 'H',
    ))
    fig.update_layout(
      # title = f'Relación entre el tiempo resolver y el tiempo para calcular LU ({reps} reps)',
      xaxis_title = 'Time', # TODO: Not time
      yaxis_title = 'Information',
    )
    utils.saveFig(fig, self.fbase, 'hitime')

  def reportOpt(self):
    if len(self.optDf) == 0:
      self.addReport('Optional', ['NO ARP DATA'])
      return

    _counts = self.optDf['pdst'].value_counts() + self.optDf['psrc'].value_counts()
    _counts.dropna(inplace = True)
    _df = pd.DataFrame()
    _df['count'] = _counts
    _df['symbol'] = _counts.index
    _df['p'] = _counts / _counts.sum()
    _df['information'] = -np.log2(_df['p'])
    _df.sort_values('information', ascending = True, inplace = True)

    self.addReport('Optional', [
      f'Hosts:\n{_df[["information"]].head()}',
      f'Predicted router: {_df.iloc[0]["symbol"]}'
    ])

    self.plotBar(
      _df, 'symbol', 'p',
      name = f'opt_pct_F', title = f'opt_pct_F', xaxis_title = 'Symbol', yaxis_title = '% of total packets',
    )
    self.plotBar(
      _df, 'symbol', 'information',
      name = f'opt_info_F', title = f'opt_info_F', xaxis_title = 'Symbol', yaxis_title = 'Information',
    )

    self.optDf['symbol_src'] = '(' + self.optDf['psrc'] + ', ' + self.optDf['op'] + ')'
    self.optDf['symbol_dst'] = '(' + self.optDf['pdst'] + ', ' + self.optDf['op'] + ')'

    allCounts = {
      'src': self.optDf['symbol_src'].value_counts(),
      'dst': self.optDf['symbol_dst'].value_counts(),
    }
    for v, counts in allCounts.items():
      df = pd.DataFrame([
        {
          'symbol': symbol, 
          'count': counts[symbol]
        }
        for symbol in list(self.optDf[f'symbol_{v}'].unique())
      ])
      df['p'] = df['count'] / len(self.optDf)
      df['information'] = -np.log2(df['p'])
      self.plotBar(
        df, 'symbol', 'p',
        name = f'opt_pct_{v}', title = f'opt_pct_{v}', xaxis_title = 'Symbol', yaxis_title = '% of total packets',
      )
      self.plotBar(
        df, 'symbol', 'information',
        name = f'opt_info_{v}', title = f'opt_info_{v}', xaxis_title = 'Symbol', yaxis_title = 'Information',
      )

  #************************************************************
  #* Plot *****************************************************

  def plotBar(self, df, x, y, *, title, xaxis_title, yaxis_title, name, ascending = False):
    fig = px.bar(
      df.sort_values(y, ascending = ascending),
      x = x, y = y,
    )
    fig.update_layout(
      title = title, xaxis_title = xaxis_title, yaxis_title = yaxis_title, 
    )
    utils.saveFig(fig, self.fbase, name)
  
  #************************************************************
  #* Utils ****************************************************

  def loadPcap(self):
    if not hasattr(self, 'pcap') or self.pcap is None:
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

  def addReport(self, title, info):
    #TODO: Correctly format df
    lines = '\n'.join([f'* {line}' for line in info])
    self.reportMsg += f'\n\n## {title}\n{lines}'
