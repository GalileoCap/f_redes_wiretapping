import re
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np

from analyze import analyzeAll
import utils

def cleanName(name):
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
  return d.get(user, f'Red {name}')

def mergeI(name, exps):
  fig = go.Figure()

  for exp in exps:
    fig.add_trace(go.Bar(
      x = exp.symbolsDf['symbol'],
      y = exp.symbolsDf['information'],
      name = cleanUser(exp.user),
    ))

  fig.update_layout(
    title = f'Información por símbolo en el contexto "{cleanName(name)}"',
    xaxis_title = 'Símbolo',
    yaxis_title = 'Información (bits)',
    legend_title = 'Red',
  )

  utils.saveFig(fig, '.', f'{name}_info')

def mergeH(name, exps):
  fig = go.Figure()

  maxX = np.Inf
  for exp in exps:
    fig.add_trace(go.Scatter(
      y = exp.fooDf['H'],
      name = cleanUser(exp.user),
    ))
    maxX = min(maxX, len(exp.fooDf))

  fig.update_layout(
    title = f'Entropía en el contexto "{cleanName(name)}"',
    xaxis_title = 'Cantidad de paquetes',
    yaxis_title = 'Entropía',
    legend_title = 'Red',

    xaxis_range = [0, maxX],
  )

  utils.saveFig(fig, '.', f'{name}_h')

if __name__ == '__main__':
  exps = analyzeAll(True)
  for name in ['baseline', 'comun', 'boot', 'busy']:
    _exps = filter(lambda exp: re.search(name, exp.name), exps)
    mergeI(name, _exps)
    mergeH(name, _exps)
