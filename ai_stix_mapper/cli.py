"""Command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .builder import build_bundle
from .config import Settings
from .extractors import extract_text
from .llm import extract_stix

console = Console()


@click.command()
@click.argument("source")
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Where to write the STIX bundle JSON (default: ./<name>.stix.json).",
)
@click.option("--author", default="AI STIX Mapper", help="Name for the author Identity.")
@click.option(
    "--push-opencti",
    is_flag=True,
    help="Also import the bundle into OpenCTI as a draft for review.",
)
def main(source: str, output: Path | None, author: str, push_opencti: bool) -> None:
    """Map a PDF or web page (SOURCE) into a STIX 2.1 bundle for OpenCTI.

    SOURCE may be a local .pdf path or an http(s) URL.
    """
    try:
        settings = Settings.load()
    except RuntimeError as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        sys.exit(1)

    with console.status("[bold]Extracting source text…"):
        text, label = extract_text(source)
    console.print(f"Read [cyan]{len(text):,}[/cyan] chars from [dim]{label}[/dim]")

    with console.status("[bold]Asking the model for STIX structure…"):
        extraction = extract_stix(text, settings)
    _print_summary(extraction)

    bundle = build_bundle(extraction, author_name=author)
    bundle_json = bundle.serialize(pretty=True)

    out_path = output or Path(f"{_slug(extraction.report_name)}.stix.json")
    out_path.write_text(bundle_json, encoding="utf-8")
    console.print(f"[green]Wrote bundle:[/green] {out_path}")

    if push_opencti:
        _push(bundle_json, settings, extraction.report_name)


def _push(bundle_json: str, settings: Settings, report_name: str) -> None:
    from .opencti_client import import_as_draft

    if not settings.opencti_url or not settings.opencti_token:
        console.print("[red]OPENCTI_URL / OPENCTI_TOKEN not set; cannot push.[/red]")
        sys.exit(1)
    with console.status("[bold]Importing into OpenCTI as a draft…"):
        draft_id = import_as_draft(
            bundle_json,
            url=settings.opencti_url,
            token=settings.opencti_token,
            draft_name=f"AI STIX Mapper: {report_name}",
        )
    console.print(f"[green]Imported as draft[/green] (id: {draft_id}). Review it in OpenCTI.")


def _print_summary(extraction) -> None:
    table = Table(title=extraction.report_name, show_header=True, header_style="bold")
    table.add_column("Kind")
    table.add_column("Count", justify="right")
    table.add_row("Entities", str(len(extraction.entities)))
    table.add_row("Indicators (IOCs)", str(len(extraction.indicators)))
    table.add_row("Relationships", str(len(extraction.relationships)))
    console.print(table)


def _slug(name: str) -> str:
    keep = [c.lower() if c.isalnum() else "-" for c in name]
    slug = "".join(keep).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "bundle"


if __name__ == "__main__":
    main()
