#!/usr/bin/env python3
from scapy.all import rdpcap, wrpcap

import pandas as pd
import os

OUTDIR = './out'
INDIR = './data'
os.makedirs(OUTDIR, exist_ok = True)
os.makedirs(INDIR, exist_ok = True)

def experimentName(user, experiment):
  return f'{user}_{experiment}'

def experimentPath(fbase):
  return os.path.join(OUTDIR, fbase)
def dfPath(fbase, name):
  return os.path.join(experimentPath(fbase), f'{name}.csv.tar.gz')
def pcapPath(fbase):
  return os.path.join(INDIR, f'{fbase}.pcap')

def saveDf(df, fpath):
  fpath = dfPath(fpath)

  print(f'[saveDf] {fpath=}')
  os.makedirs(OUTDIR, exist_ok = True)
  df.to_csv(fpath)

def loadPcap(fpath):
  fpath = pcapPath(fpath)

  print(f'[loadPcap] {fpath=}')
  return rdpcap(fpath)

def loadDf(fpath):
  fpath = dfPath(fpath)

  print(f'[loadDf] {fpath=}')
  return pd.read_csv(fpath, index_col = 0)

def dfExists(fbase, name):
  return os.path.isfile(dfPath(fbase, name))
def pcapExists(fbase):
  return os.path.isfile(pcapPath(fbase))
