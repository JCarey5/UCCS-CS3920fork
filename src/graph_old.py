#!/usr/bin/env python3
"""
attack_graph_viz.py — Enhanced visual version
- Loads env.yaml
- Hierarchical PyVis layout (LR)
- Highlights #1 ranked attack path
- Displays styled ranked paths table
Run: python attack_graph_viz.py
Open: http://localhost:5000
"""

import sys
from pathlib import Path
from flask import Flask, Response
import yaml
from pyvis.network import Network

# --- Ensure repo root ---
repo_dir = Path(__file__).resolve().parent
if str(repo_dir) not in sys.path:
    sys.path.insert(0, str(repo_dir))

from graph import AttackGraph
from planner import rank_paths


# --- Load env.yaml ---
def load_env_yaml(path="data/env.yaml"):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found. Make sure data/env.yaml exists relative to repo root.")
    return yaml.safe_load(p.read_text())


# --- Convert adjacency to edge list ---
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


# --- Build styled HTML ---
def build_pyvis_html(g: AttackGraph, ranked_paths):
    edges = edges_from_attackgraph(g)
    top_path = ranked_paths[0]["path"] if ranked_paths else []
    top_edges = {(e["src"], e["dst"]) for e in top_path}

    net = Network(height='800px', width='100%', directed=True, bgcolor="#1a1a1a", font_color="white")

    # --- Layout options ---
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
    for n in g.assets:
        if n in g.start_nodes:
            color = "#7DCEA0"  # green
            size = 30
        elif n in g.goal_nodes:
            color = "#F5B041"  # amber
            size = 40
        else:
            color = "#5DADE2"  # blue
            size = 20
        net.add_node(n, label=n, color=color, size=size)

    # --- Add edges ---
    for e in edges:
        src, dst = e["src"], e["dst"]
        label = e.get("technique", "?")
        title_text = (
            f"Technique: {label}<br>"
            f"p={e['p']}, impact={e['impact']}, detect={e['detect']}, time={e['time']}"
        )

        if (src, dst) in top_edges:
            color = "#E74C3C"  # red
            width = 4
        else:
            color = "gray"
            width = 1

        net.add_edge(src, dst, label=label, title=title_text,
                     color=color, width=width, font={"align": "top", "size": 10})

    html = net.generate_html()

    # --- Custom CSS (dark modern style) ---
    custom_css = """
    <style>
      body {
        font-family: 'Segoe UI', Roboto, sans-serif;
        background-color: #121212;
        color: #f0f0f0;
        margin: 0;
        padding: 0;
      }
      h2 {
        text-align: center;
        margin-top: 20px;
        color: #f1c40f;
        font-weight: 600;
      }
      .container {
        max-width: 1100px;
        margin: 0 auto;
        padding: 20px;
      }
      .graph-box {
        background: #1e1e1e;
        border-radius: 12px;
        box-shadow: 0 0 20px rgba(0,0,0,0.5);
        padding: 10px;
      }
      table {
        border-collapse: collapse;
        width: 100%;
        margin-top: 40px;
        background: #1f1f1f;
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 0 10px rgba(0,0,0,0.3);
      }
      th, td {
        padding: 10px 12px;
        text-align: center;
      }
      th {
        background-color: #333;
        color: #f1c40f;
        text-transform: uppercase;
        font-size: 0.9em;
      }
      tr:nth-child(even) {
        background-color: #2a2a2a;
      }
      tr:hover {
        background-color: #383838;
      }
      .footer {
        text-align: center;
        color: #999;
        margin-top: 40px;
        font-size: 0.85em;
      }
    </style>
    """

    # --- Ranked paths table ---
    path_list_html = """
    <div class="container">
      <h3 style='text-align:center;margin-top:30px;color:#f1c40f;'>Ranked Attack Paths</h3>
      <div style='overflow-x:auto;'>
        <table>
          <tr>
            <th>Rank</th><th>Utility</th><th>Probability</th><th>Impact</th>
            <th>Detect</th><th>Time</th><th>Techniques</th>
          </tr>
    """

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
    path_list_html += "</table></div></div>"

    footer_html = "<div class='footer'>Attack Graph Visualizer © 2025</div>"

    # --- Inject custom CSS and layout ---
    html = html.replace("</head>", custom_css + "\n</head>")
    html = html.replace("<body>", "<body><div class='container'><h2>Attack Graph Visualization</h2><div class='graph-box'>")
    html = html.replace("</body>", "</div>" + path_list_html + footer_html + "</body>")

    return html


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


# --- Optional standalone mode ---
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

