"""One module per package registry (0.1.9, wave 2; the interface of `specs/lazaret-registry-module-interface-2026-10-03.md`).

`base.py` holds what the modules and `repo.py` share: the errors, `Resolution`, the checked fetch seam and the
`Ecosystem` class a module fills in. A module never imports `repo.py` and never opens a URL itself.

`ECOSYSTEMS` maps an ecosystem's id (the string in specs, store rows, reports and rule hits) to its instance.
Nothing registers here by import: `repo.py` registers the modules it routes through (X-2's last step), and a test
registers the one it checks, so importing this package costs nothing and reaches nothing."""

ECOSYSTEMS = {}


def register(eco):
    """Add `eco` (an `Ecosystem` instance) under its id; -> `eco`. A second module with the same id is an error."""
    if not getattr(eco, "id", ""):
        raise ValueError("an ecosystem needs an id")
    if eco.id in ECOSYSTEMS and ECOSYSTEMS[eco.id] is not eco:
        raise ValueError(f"ecosystem {eco.id!r} is already registered")
    ECOSYSTEMS[eco.id] = eco
    return eco


def get(eco_id):
    """The module for `eco_id`, or None."""
    return ECOSYSTEMS.get(eco_id)
