#!/usr/bin/env python3
"""
attack_graph_viz.py
Integrated version:
- Loads env.yaml
- Keeps clean hierarchical PyVis layout
- Highlights #1 ranked attack path
- Displays ranked paths table
Run: python attack_graph_viz.py
Open: http://localhost:5000
"""

import sys
from pathlib import Path
from flask import Flask, Response
import yaml
from pyvis.network import Network

# --- Ensure repo root (where graph.py lives) is on sys.path ---
repo_dir = Path(__file__).resolve().parent
if str(repo_dir) not in sys.path:
    sys.path.insert(0, str(repo_dir))

# --- Imports ---
from graph import AttackGraph
from planner import rank_paths

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

# --- Build PyVis HTML ---
def build_pyvis_html(g: AttackGraph, ranked_paths):
    edges = edges_from_attackgraph(g)
    top_path = ranked_paths[0]["path"] if ranked_paths else []

    # Set of (src, dst) tuples for the top-ranked path
    top_edges = {(e["src"], e["dst"]) for e in top_path}

    net = Network(height='800px', width='100%', directed=True)

    # --- Layout options (clean horizontal flow) ---
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
    all_nodes = set(g.assets)
    for n in all_nodes:
        if n in g.start_nodes:
            color = "lightgreen"
            size = 30
        elif n in g.goal_nodes:
            color = "orange"
            size = 40
        else:
            color = "lightblue"
            size = 20
        net.add_node(n, label=n, color=color, size=size)

    # --- Add edges, highlighting top path ---
    for e in edges:
        src, dst = e["src"], e["dst"]
        label = e.get("technique", "?")
        title_text = (
            f"Technique: {label}<br>"
            f"p={e['p']}, impact={e['impact']}, detect={e['detect']}, time={e['time']}"
        )

        if (src, dst) in top_edges:
            color = "red"
            width = 4
        else:
            color = "gray"
            width = 1

        net.add_edge(src, dst, label=label, title=title_text, color=color, width=width, font={"align": "top", "size": 10})

    # --- Generate HTML and append ranked paths table ---
    html = net.generate_html()
    path_list_html = "<h3>Ranked Attack Paths</h3><table border='1' cellpadding='4' cellspacing='0' style='border-collapse: collapse;'>"
    path_list_html += "<tr><th>Rank</th><th>Utility</th><th>Probability</th><th>Impact</th><th>Detect</th><th>Time</th><th>Techniques</th></tr>"

    for i, r in enumerate(ranked_paths, 1):
        steps = " → ".join(e.get("technique", "?") for e in r["path"])
        path_list_html += (
            f"<tr>"
            f"<td>{i}</td>"
            f"<td>{r['utility']:.3f}</td>"
            f"<td>{r['prob']:.3f}</td>"
            f"<td>{r['impact']:.2f}</td>"
            f"<td>{r['detect']:.2f}</td>"
            f"<td>{r['time']:.2f}</td>"
            f"<td>{steps}</td>"
            f"</tr>"
        )
    path_list_html += "</table>"

    header_html = f"<h2 style='text-align:center;margin:8px 0'>Attack Graph Visualization</h2>\n"
    return header_html + html + "<br><br>" + path_list_html

# --- Flask app ---
app = Flask(__name__)

@app.route('/')
def index():
    cfg = load_env_yaml("data/env.yaml")
    g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    paths = g.enumerate_paths(max_depth=5)
    ranked = rank_paths(paths, top_k=5)
    html = build_pyvis_html(g, ranked)
    return Response(html, mimetype='text/html')

# --- Optional standalone visualization (no server) ---
def visualize_attack_graph(env_file="data/env.yaml"):
    cfg = load_env_yaml(env_file)
    g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    paths = g.enumerate_paths(max_depth=5)
    ranked = rank_paths(paths, top_k=5)
    html_file = Path("attack_graph.html")
    with html_file.open("w") as f:
        f.write(build_pyvis_html(g, ranked))
    print(f"Attack graph saved to {html_file.resolve()} (open in a browser)")

# --- Main entry ---
if __name__ == "__main__":
    print("Starting Attack Graph Visualization at http://localhost:5000")
    try:
        import pyvis  # noqa: F401
    except Exception:
        print("Missing dependencies: pip install flask pyvis pyyaml")
        raise
    app.run(host='0.0.0.0', port=5000, debug=True)

