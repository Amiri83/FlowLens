"""FlowLens CLI (Typer). Every command is local/deterministic; AWS discovery
issues only read-only boto3 calls.
"""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from flowlens.graph.traversal import resolve_node_ref, shortest_path
from flowlens.ingest.terraform import combine_config_and_state, ingest_path
from flowlens.linking.linker import link_graph
from flowlens.models.graph import Graph
from flowlens.storage.repository import GraphRepository

app = typer.Typer(help="FlowLens: local-first DevOps infrastructure visualization & troubleshooting.")
aws_app = typer.Typer(help="Read-only AWS discovery.")
app.add_typer(aws_app, name="aws")
console = Console()

DEFAULT_DB = "data/flowlens.db"


def _summary(graph: Graph) -> None:
    table = Table(show_header=True, header_style="bold")
    table.add_column("resource_type")
    table.add_column("count", justify="right")
    counts: dict[str, int] = {}
    for node in graph.nodes.values():
        counts[node.resource_type] = counts.get(node.resource_type, 0) + 1
    for rtype, count in sorted(counts.items()):
        table.add_row(rtype, str(count))
    console.print(table)
    console.print(f"[bold]{len(graph.nodes)}[/bold] nodes, [bold]{len(graph.edges)}[/bold] edges")


def _load(db: str) -> Graph:
    repo = GraphRepository(db)
    try:
        return repo.load_graph()
    finally:
        repo.close()


def _merge_and_save(graph: Graph, db: str, *, link: bool = False) -> Graph:
    repo = GraphRepository(db)
    try:
        merged = repo.load_graph().merge(graph)
        if link:
            link_graph(merged)
        repo.save_graph(merged)
    finally:
        repo.close()
    return merged


def _resolve_or_exit(graph: Graph, ref: str) -> str:
    node_id = resolve_node_ref(graph, ref)
    if node_id is None:
        console.print(f"[red]No unique node matches[/red] {ref!r} (try a node id, terraform address, ARN, cloud id or name)")
        raise typer.Exit(code=1)
    return node_id


def _print_tf_scan_warnings(graph: Graph) -> None:
    warnings = (graph.metadata.get("terraform_scan") or {}).get("warnings") or []
    if warnings:
        console.print(f"[yellow]{len(warnings)} Terraform warning(s) — affected files/blocks were skipped, the rest was scanned:[/yellow]")
        for w in warnings:
            console.print(f"  [yellow]-[/yellow] {escape(w)}")


@app.command("ingest-tf")
def ingest_tf(
    path: str = typer.Argument(..., help="Directory of .tf files, a single .tf file, terraform.tfstate, or `terraform show -json` output"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Parse Terraform config/state/plan and merge into the stored graph as desired-state nodes."""
    console.print(f"[cyan]Ingesting Terraform from[/cyan] {path}")
    graph = ingest_path(path)
    _print_tf_scan_warnings(graph)
    merged = _merge_and_save(graph, db)
    console.print(f"[green]Ingested[/green] {len(graph.nodes)} nodes, {len(graph.edges)} edges from Terraform.")
    _summary(merged)


@app.command("scan")
def scan(
    path: str = typer.Argument(..., help="Terraform config directory / .tf file / state or plan JSON"),
    state: str | None = typer.Option(None, "--state", help="terraform.tfstate or `terraform show -json` output for the same stack"),
    link: bool = typer.Option(True, "--link/--no-link", help="Compute semantic edges after ingesting"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Scan Terraform (desired state) into the graph: ingest + link in one step."""
    console.print(f"[cyan]Scanning Terraform[/cyan] {path}" + (f" with state {state}" if state else ""))
    graph = ingest_path(path)
    _print_tf_scan_warnings(graph)
    if state:
        graph = combine_config_and_state(graph, ingest_path(state))
    merged = _merge_and_save(graph, db, link=link)
    console.print(f"[green]Scanned[/green] {len(graph.nodes)} Terraform resources.")
    _summary(merged)


def _run_aws_scan(region: str | None, profile: str | None, db: str, link: bool) -> None:
    from flowlens.discover.aws import AWSDiscoverer

    console.print(f"[cyan]Discovering AWS resources[/cyan] (read-only; region={region or 'default'}, profile={profile or 'default'})")
    discoverer = AWSDiscoverer(region=region, profile=profile)
    graph = discoverer.discover_all()
    merged = _merge_and_save(graph, db, link=link)
    console.print(f"[green]Discovered[/green] {len(graph.nodes)} nodes from AWS.")
    report = discoverer.report
    if report.partial:
        console.print("[yellow]Partial scan — these resource types could not be read (skipped, not fatal):[/yellow]")
        for err in discoverer.errors:
            console.print(f"  [yellow]-[/yellow] {err}")
        if report.denied_permissions:
            console.print("[yellow]Denied permissions:[/yellow] " + ", ".join(report.denied_permissions))
    _summary(merged)


@app.command("discover-aws")
def discover_aws(
    region: str | None = typer.Option(None, help="AWS region (defaults to boto3's normal resolution)"),
    profile: str | None = typer.Option(None, help="AWS named profile (defaults to boto3's normal resolution)"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Read-only AWS discovery (Describe*/List*/Get* only) merged into the stored graph as actual-state nodes."""
    _run_aws_scan(region, profile, db, link=False)


@aws_app.command("scan")
def aws_scan(
    profile: str | None = typer.Option(None, help="AWS named profile (defaults to boto3's normal resolution)"),
    region: str | None = typer.Option(None, help="AWS region (defaults to boto3's normal resolution)"),
    link: bool = typer.Option(True, "--link/--no-link", help="Compute semantic edges after discovery"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Scan AWS (actual state), read-only. Missing IAM permissions are reported, not fatal."""
    _run_aws_scan(region, profile, db, link=link)


@app.command("build-graph")
def build_graph(db: str = typer.Option(DEFAULT_DB, help="SQLite database path")):
    """Recompute semantic edges (contains, forwards_to, allows, ...) over the stored graph."""
    repo = GraphRepository(db)
    try:
        graph = repo.load_graph()
        before = len(graph.edges)
        link_graph(graph)
        repo.save_graph(graph)
    finally:
        repo.close()
    console.print(f"[green]Linked graph.[/green] Added {len(graph.edges) - before} semantic edges.")
    _summary(graph)


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8000),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Start the FastAPI server + web UI."""
    import uvicorn

    from flowlens.api.app import create_app

    console.print(f"[cyan]Serving FlowLens[/cyan] on http://{host}:{port} (db={db})")
    uvicorn.run(create_app(db), host=host, port=port)


@app.command("ui")
def ui(
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8000),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Open the web UI (alias for `serve`)."""
    serve(host=host, port=port, db=db)


@app.command("path")
def path_cmd(
    source: str = typer.Argument(..., help="Start node: id, terraform address, ARN, cloud id, or name"),
    target: str = typer.Argument(..., help="End node: id, terraform address, ARN, cloud id, or name"),
    undirected: bool = typer.Option(False, "--undirected", help="Ignore edge direction"),
    max_depth: int | None = typer.Option(None, help="Maximum number of hops"),
    as_json: bool = typer.Option(False, "--json", help="Print the path as JSON"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Print the shortest connectivity path between two resources (BFS, follows edge direction)."""
    graph = _load(db)
    src, dst = _resolve_or_exit(graph, source), _resolve_or_exit(graph, target)
    result = shortest_path(graph, src, dst, directed=not undirected, max_depth=max_depth)
    if result is None:
        if as_json:
            console.print_json(json.dumps({"found": False, "nodes": [], "edges": []}))
        else:
            hint = "" if undirected else " (try --undirected)"
            console.print(f"[yellow]No path[/yellow] from {src} to {dst}{hint}")
        raise typer.Exit(code=1)
    if as_json:
        console.print_json(json.dumps(result.to_dict()))
        return
    console.print(f"[green]Path found[/green] ({len(result.steps)} hops)")
    console.print(f"  {src}  [dim]({graph.nodes[src].resource_type})[/dim]")
    for step in result.steps:
        arrow = f"<-{step.edge.relationship_type.value}--" if step.reversed else f"--{step.edge.relationship_type.value}->"
        console.print(f"    [cyan]{arrow}[/cyan] {step.to_node}  [dim]({graph.nodes[step.to_node].resource_type})[/dim]")


@app.command("reachability")
def reachability_cmd(
    source: str = typer.Argument(..., help="'internet', an IP/CIDR, or a resource (id, terraform address, ARN, cloud id, name)"),
    destination: str = typer.Argument(..., help="'internet', an IP/CIDR, or a resource (id, terraform address, ARN, cloud id, name)"),
    protocol: str = typer.Option("tcp", "--protocol", "-p", help="tcp | udp | icmp | icmpv6 | -1 (all traffic)"),
    port: str | None = typer.Option(None, "--port", help="Destination port or range, e.g. 443 or 8000-8100 (ICMP: type)"),
    as_json: bool = typer.Option(False, "--json", help="Print the full result (checks + evidence) as JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every evidence line"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Can traffic flow from SOURCE to DESTINATION on protocol/port? Where is it blocked and why?

    Evaluates routes (longest-prefix match), network ACLs (stateless), security groups (stateful)
    and load balancer port transitions. Result is ALLOWED, BLOCKED or UNKNOWN (never guessed).
    Unlike `flowlens path`, graph connectivity is not treated as reachability.
    """
    from flowlens.reachability import EndpointError, ReachabilityEngine
    from flowlens.reachability.render import render_text

    graph = _load(db)
    try:
        result = ReachabilityEngine(graph).analyze(source, destination, protocol, port)
    except (EndpointError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if as_json:
        console.print_json(json.dumps(result.to_dict(), default=str))
        return
    # Plain print: output must stay readable without color or markup.
    typer.echo(render_text(result, verbose=verbose))


@app.command("info")
def info(
    resource: str = typer.Argument(..., help="Node id, terraform address, ARN, cloud id, or name"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Show one resource: identity, status, desired/actual state and its edges."""
    graph = _load(db)
    node = graph.nodes[_resolve_or_exit(graph, resource)]
    table = Table(show_header=False)
    for label, value in [
        ("id", node.id),
        ("name", node.name),
        ("type", node.resource_type),
        ("source", node.source.value),
        ("status", node.status.value),
        ("terraform_address", node.terraform_address),
        ("aws_arn", node.aws_arn),
        ("region", node.region),
        ("account_id", node.account_id),
    ]:
        if value:
            table.add_row(label, str(value))
    console.print(table)
    for label, state in (("desired_state", node.desired_state), ("actual_state", node.actual_state)):
        if state is not None:
            console.print(f"[bold]{label}[/bold]")
            console.print_json(json.dumps(state, default=str))
    edges = sorted(graph.edges_for(node.id), key=lambda e: e.id)
    console.print(f"[bold]edges[/bold] ({len(edges)})")
    for e in edges:
        if e.source_node == node.id:
            console.print(f"  --{e.relationship_type.value}-> {e.target_node}")
        else:
            console.print(f"  <-{e.relationship_type.value}-- {e.source_node}")


@app.command("compare")
def compare(
    status: str | None = typer.Option(None, help="Only show one status (MATCHED, DIFFERENT, TERRAFORM_ONLY, AWS_ONLY, UNKNOWN)"),
    as_json: bool = typer.Option(False, "--json", help="Print results as JSON"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Desired (Terraform) vs actual (AWS): a status per resource."""
    from flowlens.compare.diff import compare_graph, summarize

    results = compare_graph(_load(db))
    shown = [r for r in results if status is None or r.status.value == status.upper()]
    if as_json:
        console.print_json(json.dumps({"summary": summarize(results), "results": [r.to_dict() for r in shown]}, default=str))
        return
    table = Table(show_header=True, header_style="bold")
    for col in ("status", "type", "terraform", "aws", "details"):
        table.add_column(col)
    for r in shown:
        details = r.reason or "; ".join(f"{d.key}: {d.desired!r} != {d.actual!r}" for d in r.differences)
        if not details and r.matched_by:
            details = f"matched by {r.matched_by}"
        table.add_row(r.status.value, r.resource_type, r.desired_id or "-", r.actual_id or "-", details)
    console.print(table)
    console.print(", ".join(f"{k}={v}" for k, v in summarize(results).items()))


@app.command("export-json")
def export_json(
    output: str = typer.Argument(..., help="Output JSON file path"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Export the stored graph as JSON."""
    graph = _load(db)
    Path(output).write_text(json.dumps(graph.to_dict(), indent=2))
    console.print(f"[green]Exported[/green] {len(graph.nodes)} nodes, {len(graph.edges)} edges to {output}")


@app.command("import-json")
def import_json(
    input: str = typer.Argument(..., help="Input JSON file path (as produced by export-json)"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
    merge: bool = typer.Option(False, help="Merge into the existing stored graph instead of replacing it"),
):
    """Import a previously exported graph JSON file."""
    data = json.loads(Path(input).read_text())
    graph = Graph.from_dict(data)
    repo = GraphRepository(db)
    try:
        if merge:
            graph = repo.load_graph().merge(graph)
        repo.save_graph(graph)
    finally:
        repo.close()
    console.print(f"[green]Imported[/green] {len(graph.nodes)} nodes, {len(graph.edges)} edges into {db}")


if __name__ == "__main__":
    app()
