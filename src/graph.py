from typing import List, Dict, Any

class AttackGraph:
    def __init__(self, assets: List[str], start_nodes: List[str],
                 goal_nodes: List[str], edges: List[Dict[str, Any]]):
        self.assets = set(assets) | set(start_nodes) | set(goal_nodes)
        self.start_nodes = set(start_nodes)
        self.goal_nodes = set(goal_nodes)
        self.edges = edges
        self.adj = {}
        for e in edges:
            self.adj.setdefault(e["src"], []).append(e)

    def neighbors(self, node: str):
        return self.adj.get(node, [])

    def enumerate_paths(self, max_depth: int = 5):
        paths = []
        for s in self.start_nodes:
            self._dfs(current=s, path=[], seen={s}, paths=paths, max_depth=max_depth)
        return paths

    def _dfs(self, current: str, path, seen, paths, max_depth: int):
        if len(path) > max_depth:
            return
        if current in self.goal_nodes:
            paths.append(path.copy())
            return
        for e in self.neighbors(current):
            nxt = e["dst"]
            if nxt in seen and nxt not in self.goal_nodes:
                continue
            seen.add(nxt)
            path.append(e)
            self._dfs(nxt, path, seen, paths, max_depth)
            path.pop()
            seen.discard(nxt)

