#!/usr/bin/env python3
from scapy.all import *

from datetime import datetime
from time import time
import sys
import os

OUT_DIR = './out'
prev_len = 0
count = 0

def formatear_fuente(S, start_time):
  N = sum(S.values())
  simbolos = sorted(S.items(), key=lambda x: -x[1])
  return (
    "\n".join([ "%s : %.5f" % (d,k/N) for d,k in simbolos ]),
    time() - start_time,
    len(simbolos)
  )

def mostrar_fuente(S, start_time):
  global prev_len
  fuentes, dt, largo = formatear_fuente(S, start_time)

  sys.stdout.write('\033[F' * prev_len)
  print(f'{dt}\n{count}\n{fuentes}\n')

  prev_len = largo + 3

def guardar_fuente(S, start_date, start_time):
  with open(os.path.join(OUT_DIR, start_date), 'w') as fout:
    fuentes, dt, _ = formatear_fuente(S, start_time)
    fout.write(f'{start_date}\n{dt}\n{count}\n{fuentes}\n')

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
