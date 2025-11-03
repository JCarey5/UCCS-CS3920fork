#!/usr/bin/env python3
"""
attack_graph_viz.py
Drop this next to graph.py and the data/ folder in your repo root.
Run: python attack_graph_viz.py
Open: http://localhost:5000
"""

import os
import sys
from pathlib import Path
from flask import Flask, Response
import yaml
from pyvis.network import Network

# --- Ensure repo root (where graph.py lives) is on sys.path ---
repo_dir = Path(__file__).resolve().parent
if str(repo_dir) not in sys.path:
    sys.path.insert(0, str(repo_dir))

# Import AttackGraph from your graph.py
from graph import AttackGraph

# --- Load env.yaml ---
def load_env_yaml(path="data/env.yaml"):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found. Make sure data/env.yaml exists relative to repo root.")
    return yaml.safe_load(p.read_text())

# --- Convert AttackGraph adjacency to edge list ---
def edges_from_attackgraph(g: AttackGraph):
    edges = []
    for src, elist in g.adj.items():
        for e in elist:
            edges.append({
                "src": src,
                "dst": e["dst"],
                "technique": e.get("technique", "?"),
                "p": float(e.get("p", 0.5)),
                "impact": float(e.get("impact", 1.0)),
                "detect": float(e.get("detect", 0.3)),
                "time": float(e.get("time", 1.0))
            })
    return edges

# --- Build PyVis HTML from edges ---
def build_pyvis_html(edges, start_nodes=None, goal_nodes=None, title="Attack Graph"):
    if start_nodes is None:
        start_nodes = set()
    if goal_nodes is None:
        goal_nodes = set()

    net = Network(height='800px', width='100%', directed=True)
    
    # --- Hierarchical layout options (Horizontal Left-to-Right) ---
    net.set_options("""
    var options = {
      "layout": {
        "hierarchical": {
          "enabled": true,
          "direction": "LR",
          "sortMethod": "directed",
          "levelSeparation": 200,
          "nodeSpacing": 150,
          "treeSpacing": 250
        }
      },
      "edges": {
        "arrows": {"to": {"enabled": true}},
        "smooth": {"type": "cubicBezier"},
        "font": {"align": "top", "size": 12, "face": "arial"}
      },
      "nodes": {"font": {"size": 18, "face": "arial"}, "shadow": true},
      "physics": {"enabled": false}
    }
    """)

    # --- Add nodes ---
    nodes = set()
    for e in edges:
        nodes.add(e['src'])
        nodes.add(e['dst'])

    for n in nodes:
        if n in start_nodes:
            color = "lightgreen"
            size = 30
        elif n in goal_nodes:
            color = "orange"
            size = 40
        else:
            color = "lightblue"
            size = 20
        net.add_node(n, label=n, color=color, size=size)

    # --- Add edges with hover info ---
    for e in edges:
        src, dst = e['src'], e['dst']
        label = e.get('technique','?')
        title_text = f"Technique: {label}<br>p={e.get('p','')}, impact={e.get('impact','')}, detect={e.get('detect','')}, time={e.get('time','')}"
        net.add_edge(src, dst, label=label, title=title_text, font={"align":"top","size":10})

    # --- HTML wrapper ---
    html = net.generate_html()
    header_html = f"<h2 style='text-align:center;margin:8px 0'>{title}</h2>\n"
    return header_html + html

# --- Flask app ---
app = Flask(__name__)

@app.route('/')
def index():
    cfg = load_env_yaml("data/env.yaml")
    attack_graph = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    edges = edges_from_attackgraph(attack_graph)
    html = build_pyvis_html(edges, start_nodes=attack_graph.start_nodes, goal_nodes=attack_graph.goal_nodes)
    return Response(html, mimetype='text/html')

# --- Optional function to call from other scripts ---
def visualize_attack_graph(env_file="data/env.yaml"):
    cfg = load_env_yaml(env_file)
    attack_graph = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    edges = edges_from_attackgraph(attack_graph)
    html_file = Path("attack_graph.html")
    with html_file.open("w") as f:
        f.write(build_pyvis_html(edges, start_nodes=attack_graph.start_nodes, goal_nodes=attack_graph.goal_nodes))
    print(f"Attack graph saved to {html_file.resolve()} (open in a browser)")

if __name__ == "__main__":
    print("Starting Attack Graph Visualization at http://localhost:5000")
    try:
        import pyvis  # noqa: F401
    except Exception:
        print("Missing dependencies: pip install flask pyvis pyyaml")
        raise
    app.run(host='0.0.0.0', port=5000, debug=True)

