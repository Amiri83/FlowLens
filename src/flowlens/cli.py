"""FlowLens CLI (Typer). Every command is local/deterministic; AWS discovery
issues only read-only boto3 calls.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from flowlens.ingest.terraform import ingest_path
from flowlens.linking.linker import link_graph
from flowlens.models.graph import Graph
from flowlens.storage.repository import GraphRepository

app = typer.Typer(help="FlowLens: local-first DevOps infrastructure visualization & troubleshooting.")
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


@app.command("ingest-tf")
def ingest_tf(
    path: str = typer.Argument(..., help="Directory of .tf files, a single .tf file, terraform.tfstate, or `terraform show -json` output"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Parse Terraform config/state/plan and merge into the stored graph as desired-state nodes."""
    console.print(f"[cyan]Ingesting Terraform from[/cyan] {path}")
    graph = ingest_path(path)
    repo = GraphRepository(db)
    try:
        merged = repo.load_graph().merge(graph)
        repo.save_graph(merged)
    finally:
        repo.close()
    console.print(f"[green]Ingested[/green] {len(graph.nodes)} nodes, {len(graph.edges)} edges from Terraform.")
    _summary(merged)


@app.command("discover-aws")
def discover_aws(
    region: Optional[str] = typer.Option(None, help="AWS region (defaults to boto3's normal resolution)"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Read-only AWS discovery (Describe*/List*/Get* only) merged into the stored graph as actual-state nodes."""
    console.print(f"[cyan]Discovering AWS resources[/cyan] (region={region or 'default'})")
    from flowlens.discover.aws import AWSDiscoverer

    discoverer = AWSDiscoverer(region=region)
    graph = discoverer.discover_all()
    repo = GraphRepository(db)
    try:
        merged = repo.load_graph().merge(graph)
        repo.save_graph(merged)
    finally:
        repo.close()
    console.print(f"[green]Discovered[/green] {len(graph.nodes)} nodes from AWS.")
    if discoverer.errors:
        console.print("[yellow]Some services could not be discovered (skipped, not fatal):[/yellow]")
        for err in discoverer.errors:
            console.print(f"  [yellow]-[/yellow] {err}")
    _summary(merged)


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


@app.command("export-json")
def export_json(
    output: str = typer.Argument(..., help="Output JSON file path"),
    db: str = typer.Option(DEFAULT_DB, help="SQLite database path"),
):
    """Export the stored graph as JSON."""
    repo = GraphRepository(db)
    try:
        graph = repo.load_graph()
    finally:
        repo.close()
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
