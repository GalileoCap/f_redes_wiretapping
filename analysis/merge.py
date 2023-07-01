import re
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np

from analyze import analyzeAll
import utils

def mergeI(name, exps):
  fig = go.Figure()

  for exp in exps:
    fig.add_trace(go.Bar(
      x = exp.symbolsDf['symbol'],
      y = exp.symbolsDf['information'],
      name = utils.cleanUser(exp.user),
    ))

  fig.update_layout(
    title = f'Información por símbolo en el contexto "{utils.cleanName(name)}"',
    xaxis_title = 'Símbolo',
    yaxis_title = 'Información (bits)',
    legend_title = 'Red',
  )

  utils.saveFig(fig, '.', f'merge_{name}_info')

def mergeH(name, exps):
  fig = go.Figure()

  maxX = np.Inf
  for exp in exps:
    fig.add_trace(go.Scatter(
      y = exp.fooDf['H'],
      name = utils.cleanUser(exp.user),
    ))
    maxX = min(maxX, len(exp.fooDf))

  fig.update_layout(
    title = f'Entropía en el contexto "{utils.cleanName(name)}"',
    xaxis_title = 'Cantidad de paquetes',
    yaxis_title = 'Entropía',
    legend_title = 'Red',

    xaxis_range = [0, maxX],
  )

  print('hmaxX', name, utils.hmaxX(name))
  utils.saveFig(fig, '.', f'merge_{name}_h')

if __name__ == '__main__':
  exps = analyzeAll(True)
  for name in ['baseline', 'comun', 'boot', 'busy']:
    _exps = list(filter(lambda exp: re.search(name, exp.name), exps))
    mergeI(name, _exps)
    mergeH(name, _exps)
