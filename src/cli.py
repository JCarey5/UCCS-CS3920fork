import argparse, json
from pathlib import Path
import sys

src_dir = Path(__file__).resolve().parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

try:
    import yaml
except ImportError:
    yaml = None

import graph_viz
VISUALIZE_AVAILABLE = True

from graph import AttackGraph
from planner import rank_paths

def load_env(path: str):
    p = Path(path)
    if p.suffix.lower() in (".yaml", ".yml") and yaml:
        return yaml.safe_load(p.read_text())
    return json.loads(p.read_text())

def main():
    ap = argparse.ArgumentParser(
        description="Attack Graph Planning and Visualization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Visualize original simple graph
  python src/cli.py --visualize

  # Visualize your system template graph
  python src/cli.py --env updated_graph.yaml --visualize
  
  # Generate graph from system template and visualize
  python mock_workflow.py --system-config data/system_template.yaml --export
  python src/cli.py --env results/updated_graph.yaml --visualize

  # Rank paths without visualization
  python src/cli.py --env data/env.yaml --max-depth 4 --top-k 5
        """
    )
    ap.add_argument("--env", default="data/env.yaml", 
                    help="Attack graph YAML file (default: data/env.yaml)")
    ap.add_argument("--max-depth", type=int, default=4)
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--wI", type=float, default=1.0)
    ap.add_argument("--wD", type=float, default=0.5)
    ap.add_argument("--wT", type=float, default=0.1)
    ap.add_argument("--wP", type=float, default=1.0)
    ap.add_argument("--visualize", action="store_true", 
                    help="Launch attack graph visualization in browser")
    ap.add_argument("--port", type=int, default=5000,
                    help="Port for visualization server (default: 5000)")
    
    a = ap.parse_args()

    # --- Visualization branch ---
    if a.visualize:
        if VISUALIZE_AVAILABLE:
            print("="*70)
            print(f"Launching Attack Graph Visualization")
            print(f"Graph file: {a.env}")
            print(f"URL: http://localhost:{a.port}")
            print("="*70)
            
            # Check if file exists
            if not Path(a.env).exists():
                print(f"\n✗ Error: {a.env} not found!")
                print(f"\nAvailable options:")
                print(f"  1. Use default: python src/cli.py --visualize")
                print(f"  2. Generate from system template:")
                print(f"     python mock_workflow.py --system-config data/system_template.yaml --export")
                print(f"     python src/cli.py --env results/updated_graph.yaml --visualize")
                return 1
            
            # Set the graph file path in the Flask app config
            graph_viz.app.config['GRAPH_FILE'] = a.env
            
            # Run Flask app
            graph_viz.app.run(host="0.0.0.0", port=a.port, debug=True)
        else:
            print("Visualization not available. Make sure graph_viz.py is in your repo and dependencies are installed.")
        return

    # --- Normal CLI path ---
    print(f"Loading graph from: {a.env}")
    cfg = load_env(a.env)
    g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    paths = g.enumerate_paths(max_depth=a.max_depth)
    ranked = rank_paths(paths, wI=a.wI, wD=a.wD, wT=a.wT, wP=a.wP, top_k=a.top_k)

    print("\n" + "="*70)
    print(f"Attack Graph Analysis: {a.env}")
    print("="*70)
    print(f"Assets: {len(cfg['assets'])}")
    print(f"Start nodes: {len(cfg['start_nodes'])}")
    print(f"Goal nodes: {len(cfg['goal_nodes'])}")
    print(f"Edges: {len(cfg['edges'])}")
    print(f"Total paths found: {len(paths)}")
    print(f"Showing top {a.top_k} paths:")
    print("="*70 + "\n")

    for i, r in enumerate(ranked, 1):
        steps = " -> ".join(e.get("technique", "?") for e in r["path"])
        print(f"[{i}] U={r['utility']:.3f}  P={r['prob']:.3f}  I={r['impact']:.2f}  D={r['detect']:.2f}  T={r['time']:.2f}")
        print(f"    {steps}")
        print()

if __name__ == "__main__":
    sys.exit(main() or 0)
