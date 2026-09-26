"""The structural module call graph: configuration CALLS local module source.

Pure and deterministic: strongly connected components (iterative Tarjan over
sorted adjacency) and a topological order of the component DAG with callers
first, ties broken by the smallest member path (proposal §19 step 1). Cycles
never cause recursion here, so no input can make this loop forever.
"""
from __future__ import annotations

import heapq
from collections.abc import Iterable, Mapping


def strongly_connected_components(nodes: Iterable[str], edges: Mapping[str, Iterable[str]]) -> list[tuple[str, ...]]:
    """SCCs (each sorted) in topological order of the condensation: every
    component comes after all components that call into it."""
    all_nodes = sorted(set(nodes))
    adj = {n: sorted(set(edges.get(n, ())) & set(all_nodes)) for n in all_nodes}
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    comps: list[tuple[str, ...]] = []
    counter = 0
    for root in all_nodes:
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, i = work.pop()
            if i == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            recurse = False
            for j in range(i, len(adj[node])):
                succ = adj[node][j]
                if succ not in index:
                    work.append((node, j + 1))
                    work.append((succ, 0))
                    recurse = True
                    break
                if succ in on_stack:
                    low[node] = min(low[node], index[succ])
            if recurse:
                continue
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                comps.append(tuple(sorted(comp)))
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return _topological(comps, adj)


def _topological(comps: list[tuple[str, ...]], adj: Mapping[str, list[str]]) -> list[tuple[str, ...]]:
    comp_of = {n: i for i, c in enumerate(comps) for n in c}
    out_edges: dict[int, set[int]] = {i: set() for i in range(len(comps))}
    indegree = dict.fromkeys(range(len(comps)), 0)
    for n, succs in adj.items():
        for s in succs:
            a, b = comp_of[n], comp_of[s]
            if a != b and b not in out_edges[a]:
                out_edges[a].add(b)
                indegree[b] += 1
    heap = [(comps[i][0], i) for i, d in indegree.items() if d == 0]
    heapq.heapify(heap)
    order: list[tuple[str, ...]] = []
    while heap:
        _, i = heapq.heappop(heap)
        order.append(comps[i])
        for j in sorted(out_edges[i]):
            indegree[j] -= 1
            if indegree[j] == 0:
                heapq.heappush(heap, (comps[j][0], j))
    return order


def is_cyclic(component: tuple[str, ...], edges: Mapping[str, Iterable[str]]) -> bool:
    """A component is a cycle if it has several members or a self-call."""
    return len(component) > 1 or component[0] in set(edges.get(component[0], ()))
