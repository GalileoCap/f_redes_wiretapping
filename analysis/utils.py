#!/usr/bin/env python3
import os

OUTDIR = './out'
INDIR = './data'

def getExperimentName(user, experiment):
  return f'{user}_{experiment}'

def getOPath(user, experiment):
  return os.path.join(OUTDIR, getExperimentName(user, experiment) + '.csv.tar.gz')
def getIPath(user, experiment):
  return os.path.join(INDIR, getExperimentName(user, experiment) + '.pcap')

def savePkts(pkts, fpath):
  print('[savePkts]')
  os.makedirs(OUTDIR, exist_ok = True)
  pkts.to_csv(fpath)
