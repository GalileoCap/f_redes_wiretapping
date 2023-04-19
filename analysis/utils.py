#!/usr/bin/env python3
from scapy.all import rdpcap, wrpcap

import pandas as pd
import os

OUTDIR = './out'
INDIR = './data'

def getExperimentName(user, experiment):
  return f'{user}_{experiment}'

def dfPath(user, experiment):
  return os.path.join(OUTDIR, getExperimentName(user, experiment) + '.csv.tar.gz')
def pcapPath(user, experiment):
  return os.path.join(INDIR, getExperimentName(user, experiment) + '.pcap')

def savePcap(pkts, user, experiment):
  fpath = pcapPath(user, experiment)

  print(f'[savePcap] {fpath=}')
  os.makedirs(INDIR, exist_ok = True)
  wrpcap(fpath, pkts)

def saveDf(df, user, experiment):
  fpath = dfPath(user, experiment)

  print(f'[saveDf] {fpath=}')
  os.makedirs(OUTDIR, exist_ok = True)
  df.to_csv(fpath)

def readPcap(user, experiment):
  fpath = pcapPath(user, experiment)
  return rdpcap(fpath)

def readDf(user, experiment):
  fpath = dfPath(user, experiment)
  return pd.read_csv(fpath, index_col = 0)

def dfExists(user, experiment):
  return os.path.isfile(dfPath(user, experiment))
