#!/usr/bin/env python3
from argparse import ArgumentParser
import os

from experiment import Experiment
import utils

if __name__ == '__main__':
  parser = ArgumentParser(
    prog = 'analyze',
    description = '', #TODO
  )
  parser.add_argument('experiment', nargs = 2, help = '{USER} {EXPERIMENT_NAME}')
  parser.add_argument('--all', default = False, help = 'Run for all .pcap files (ignores user and experiment)')
  parser.add_argument('-f', '--force', default = False, help = 'Replace previously saved csv')
  args = parser.parse_args()
  args.all = bool(args.all)
  args.force = bool(args.force)

  if args.all:
    for fpath in os.listdir(utils.INDIR):
      user, rest = fpath.split('_', maxsplit = 1)
      name, _ = rest.split('.', maxsplit = 1)
      experiment = Experiment(user, name)
      experiment.process(load = not args.force).report()
  else:
    experiment = Experiment(*args.experiment)
    experiment.process(load = not args.force).report()
