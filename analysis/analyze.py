#!/usr/bin/env python3
from argparse import ArgumentParser

from experiment import Experiment

if __name__ == '__main__':
  parser = ArgumentParser(
    prog = 'analyze',
    description = '', #TODO
  )
  parser.add_argument('experiment', nargs = 2, help = '{USER} {EXPERIMENT_NAME}')
  parser.add_argument('-f', '--force', default = False, help = 'Replace previously saved csv')
  args = parser.parse_args()
  args.force = args.force != False # To True if not False

  experiment = Experiment(*args.experiment)
  experiment.process(load = not args.force).report()
