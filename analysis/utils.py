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
def imgPath(fbase, name):
  return os.path.join(experimentPath(fbase), f'{name}.pdf')
def htmlPath(fbase, name):
  return os.path.join(experimentPath(fbase), f'{name}.html')
def mdPath(fbase, name):
  return os.path.join(experimentPath(fbase), f'{name}.md')


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

def saveFig(fig, fbase, name):
  fig.write_html(htmlPath(fbase, name))
  fig.write_image(imgPath(fbase, name))
  fig.write_image(imgPath(fbase, name)) # Do it a second time, wasteful but a quick solution for plotly's pdf error

def dfExists(fbase, name):
  return os.path.isfile(dfPath(fbase, name))
def pcapExists(fbase):
  return os.path.isfile(pcapPath(fbase))

def cleanName(name):
  if name == 'busy_150K':
    name = 'busy'

  d = {
    'baseline': 'Hands-off',
    'comun': 'Uso común',
    'boot': 'Boot',
    'busy': 'Busy',
  }
  return d.get(name, name)

def cleanUser(user):
  d = {
    'LP': 'Red 1',
    'JB': 'Red 2',
    'martin': 'Red 3',
    'galileo': 'Red 4',
  }
  return d.get(user, f'Red {user}')

def hmaxX(name):
  if name == 'busy_150K':
    name = 'busy'

  d = {
    'baseline': 4195,
    'comun': 20378,
    'boot': 3392,
    'busy': 29120,
  }
  return d[name]

#************************************************************
#* Ethertypes ***********************************************
# SEE: https://github.com/secdev/scapy/blob/master/scapy/libs/ethertypes.py

def getTypeStr(t):
  return type2Str.get(t, str(t))

type2Str = {
  0x0004: '8023', # IEEE 802.3 packet
  0x0200: 'PUP', # Xerox PUP protocol - see 0A00
  0x0200: 'PUPAT', # PUP Address Translation - see 0A01
  0x0600: 'NS', # XNS
  0x0601: 'NSAT', # XNS Address Translation (3Mb only)
  0x0660: 'DLOG1', # DLOG (?)
  0x0661: 'DLOG2', # DLOG (?)
  0x0800: 'IPv4', # IP protocol
  0x0801: 'X75', # X.75 Internet
  0x0802: 'NBS', # NBS Internet
  0x0803: 'ECMA', # ECMA Internet
  0x0804: 'CHAOS', # CHAOSnet
  0x0805: 'X25', # X.25 Level 3
  0x0806: 'ARP', # Address resolution protocol
  0x0808: 'FRARP', # Frame Relay ARP (RFC1701)
  0x0BAD: 'VINES', # Banyan VINES
  0x1000: 'TRAIL', # Trailer packet
  0x1234: 'DCA', # DCA - Multicast
  0x1600: 'VALID', # VALID system protocol
  0x1995: 'RCL', # Datapoint Corporation (RCL lan protocol)
  0x3C04: 'NBPCC', # 3Com NBP Connect complete not registered
  0x3C07: 'NBPDG', # 3Com NBP Datagram (like XNS IDP) not registered
  0x4242: 'PCS', # PCS Basic Block Protocol
  0x4C42: 'IMLBL', # Information Modes Little Big LAN
  0x6001: 'MOPDL', # DEC MOP dump/load
  0x6002: 'MOPRC', # DEC MOP remote console
  0x6004: 'LAT', # DEC LAT
  0x6007: 'SCA', # DEC LAVC, SCA
  0x6008: 'AMBER', # DEC AMBER
  0x6559: 'RAWFR', # Raw Frame Relay (RFC1701)
  0x7000: 'UBDL', # Ungermann-Bass download
  0x7001: 'UBNIU', # Ungermann-Bass NIUs
  0x7003: 'UBNMC', # Ungermann-Bass ??? (NMC to/from UB Bridge)
  0x7005: 'UBBST', # Ungermann-Bass Bridge Spanning Tree
  0x7007: 'OS9', # OS/9 Microware
  0x7030: 'RACAL', # Racal-Interlan
  0x8005: 'HP', # HP Probe
  0x802F: 'TIGAN', # Tigan, Inc.
  0x8048: 'DECAM', # DEC Availability Manager for Distributed Systems DECamds (but someone at DEC says not)
  0x805B: 'VEXP', # Stanford V Kernel exp.
  0x805C: 'VPROD', # Stanford V Kernel prod.
  0x805D: 'ES', # Evans & Sutherland
  0x8067: 'VEECO', # Veeco Integrated Auto.
  0x8069: 'ATT', # AT&T
  0x807A: 'MATRA', # Matra
  0x807B: 'DDE', # Dansk Data Elektronik
  0x807C: 'MERIT', # Merit Internodal (or Univ of Michigan?)
  0x809B: 'ATALK', # AppleTalk
  0x80C6: 'PACER', # Pacer Software
  0x80D5: 'SNA', # IBM SNA Services over Ethernet
  0x80F2: 'RETIX', # Retix
  0x80F3: 'AARP', # AppleTalk AARP
  0x8100: 'VLAN', # IEEE 802.1Q VLAN tagging (XXX conflicts)
  0x8102: 'BOFL', # Wellfleet; BOFL (Breath OF Life) pkts [every 5-10 secs.]
  0x8130: 'HAYES', # Hayes Microcomputers (XXX which?)
  0x8131: 'VGLAB', # VG Laboratory Systems
  0x8137: 'IPX', # Novell (old) NetWare IPX (ECONFIG E option)
  0x813F: 'MUMPS', # M/MUMPS data sharing
  0x8146: 'FLIP', # Vrije Universiteit (NL) FLIP (Fast Local Internet Protocol)
  0x8149: 'NCD', # Network Computing Devices
  0x814A: 'ALPHA', # Alpha Micro
  0x814C: 'SNMP', # SNMP over Ethernet (see RFC1089)
  0x817D: 'XTP', # Protocol Engines XTP
  0x817E: 'SGITW', # SGI/Time Warner prop.
  0x8181: 'STP', # Scheduled Transfer STP, HIPPI-ST
  0x86DD: 'IPv6', # IP protocol version 6
  0x8739: 'RDP', # Control Technology Inc. RDP Without IP
  0x873A: 'MICP', # Control Technology Inc. Mcast Industrial Ctrl Proto.
  0x876C: 'IPAS', # IP Autonomous Systems (RFC1701)
  0x8809: 'SLOW', # 803.3ad slow protocols (LACP/Marker)
  0x880B: 'PPP', # PPP (obsolete by PPPOE)
  0x8847: 'MPLS', # MPLS Unicast
  0x8856: 'AXIS', # Axis Communications AB proprietary bootstrap/config
  0x8864: 'PPPOE', # PPP Over Ethernet Session Stage
  0x888E: 'PAE', # 802.1X Port Access Entity
  0x88A2: 'AOE', # ATA over Ethernet
  0x88A8: 'QINQ', # 802.1ad VLAN stacking
  0x88CC: 'LLDP', # Link Layer Discovery Protocol
  0x88E7: 'PBB', # 802.1Q Provider Backbone Bridging
  0x9001: 'XNSSM', # 3Com (Formerly Bridge Communications), XNS Systems Management
  0x9002: 'TCPSM', # 3Com (Formerly Bridge Communications), TCP/IP Systems Management
  0xAAAA: 'DEBNI', # DECNET? Used by VAX 6220 DEBNI
  0xFAF5: 'SONIX', # Sonix Arpeggio
  0xFF00: 'VITAL', # BBN VITAL-LanBridge cache wakeups
  0xFFFF: 'MAX', # Maximum valid ethernet type, reserved
}
