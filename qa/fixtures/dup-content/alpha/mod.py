"""Duplicate-content fixture module for per-file cache shard disambiguation."""


class DuplicateShape:
    """Fixture shape carried identically across sibling module directories."""

    value: int
    scale: int


def duplicate_probe(value: int) -> int:
    """Compute a deterministic probe value for duplicate-content QA checks."""
    return (value * 2) + 1


def duplicate_helper(item: DuplicateShape) -> int:
    """Secondary function exercising same-file call resolution in duplicate modules."""
    return duplicate_probe(item.value) + item.scale
