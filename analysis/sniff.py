#!/usr/bin/env python3
from scapy.all import *

import numpy as np
from datetime import datetime
from time import time
import sys
import os

OUT_DIR = './out'
prev_len = 0
count = 0

def entropia(simbolos):
  return sum([p * i for _, p, i in simbolos])

def formatear_simbolos(simbolos):
  return '\n'.join([f'{d}, {p}, {i}' for d, p, i in simbolos])

def formatear_fuente(S, start_time):
  dt = time() - start_time

  N = sum(S.values())
  simbolos = [
    (d, k/N, -np.log2(k/N))
    for d, k in sorted(S.items(), key=lambda x: -x[1])
  ]
  H = entropia(simbolos)

  return (
    f'{dt}\n{count}\n{H}\n{formatear_simbolos(simbolos)}\n',
    len(simbolos) + 4
  )

def mostrar_fuente(S, start_time):
  global prev_len

  s, largo = formatear_fuente(S, start_time)
  sys.stdout.write('\033[F' * prev_len)
  print(s)

  prev_len = largo

def guardar_fuente(S, start_date, start_time):
  with open(os.path.join(OUT_DIR, start_date), 'w') as fout:
    s, _ = formatear_fuente(S, start_time)
    fout.write(s)

def callback(pkt, S, start_time):
  global count

  if pkt.haslayer(Ether):
    count += 1

    dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
    proto = pkt[Ether].type # El campo type del frame tiene el protocolo
    s_i = (dire, proto) # Aca se define el simbolo de la fuente
    if s_i not in S:
      S[s_i] = 0.0

    S[s_i] += 1.0

  mostrar_fuente(S, start_time)

def sniffAndSave():
  os.makedirs(OUT_DIR, exist_ok = True)

  S = {}
  start_date = datetime.now().strftime('%Y-%m-%d-%a_%H:%M:%S')
  start_time = time()

  print(start_date)
  try:
    sniff(prn = lambda pkt: callback(pkt, S, start_time))
  except KeyboardInterrupt:
    pass

  guardar_fuente(S, start_date, start_time)

if __name__ == '__main__':
  sniffAndSave()
