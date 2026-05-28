"""General-purpose utilities."""
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()


def print_banner():
    console.print("""
[bold cyan]
  ___  ____  ____  _   _  _____     _    ____  _____ _   _ _____
 / _ \/ ___|_ _  \| \ | ||_   _|   / \  / ___|| ____| \ | |_   _|
| | | \___ \ | | |  \| |  | |    / _ \| |  _ |  _| |  \| | | |
| |_| |___) || |_|| |\  |  | |   / ___ \ |_| || |___| |\  | | |
 \___/|____/|____/|_| \_|  |_|  /_/   \_\____|_____|_| \_| |_|
[/bold cyan]
[dim]Open Source Intelligence Agent | Authorized use only[/dim]
""")


def print_section(title: str):
    console.rule(f"[bold yellow]{title}[/bold yellow]")


def log_info(msg: str):
    console.print(f"[cyan][*][/cyan] {msg}")


def log_success(msg: str):
    console.print(f"[green][+][/green] {msg}")


def log_warn(msg: str):
    console.print(f"[yellow][!][/yellow] {msg}")


def log_error(msg: str):
    console.print(f"[red][✗][/red] {msg}")


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_json_loads(value: str) -> list:
    try:
        return json.loads(value) if value else []
    except (json.JSONDecodeError, TypeError):
        return []


def render_table(title: str, columns: list[str], rows: list[tuple]):
    table = Table(title=title, show_lines=True)
    for col in columns:
        table.add_column(col, style="cyan")
    for row in rows:
        table.add_row(*[str(c) for c in row])
    console.print(table)
