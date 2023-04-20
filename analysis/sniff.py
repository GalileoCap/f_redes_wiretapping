#!/usr/bin/env python3
from argparse import ArgumentParser

from experiment import Experiment

if __name__ == '__main__':
  parser = ArgumentParser(
    prog = 'sniff',
    description = '', #TODO
  )
  parser.add_argument('experiment', nargs = 2, help = '{USER} {EXPERIMENT_NAME}')
  args = parser.parse_args()

  experiment = Experiment(*args.experiment)
  experiment.sniff().process(load = False).report()
