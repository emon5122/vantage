"""
vantage.plugins — a small, explicit plugin system.

Vantage is extensible along three observation-only seams:

  * ``serialization``  — register a decoder for a payload format the core does
                         not handle (e.g. Protobuf, FlatBuffers, a custom TLV).
  * ``classifier``     — contribute category keywords / trusted-namespace rules
                         to the managed-class classifier.
  * ``kb_importer``    — register a new artifact type for the knowledge base.

A plugin is any importable module exposing a ``PLUGIN`` dict and a ``register``
callable::

    PLUGIN = {"name": "protobuf-decoder", "description": "...", "version": "1.0"}

    def register(registry):
        registry.add_serialization("protobuf", decode_protobuf)

Plugins are discovered from (1) the ``vantage.plugins`` entry-point group and
(2) any ``*.py`` under ``$VANTAGE_PLUGINS_DIR`` (defaults to ``./plugins``).
Plugins MUST remain observation-only: decoders read bytes, they never emit or
mutate traffic. The registry rejects nothing at import time, but the project's
CONTRIBUTING guidelines and CI forbid offensive capability.
"""
import importlib.util
import os
import sys


class Registry:
    def __init__(self):
        self.serialization = {}
        self.classifier_rules = []
        self.kb_importers = {}

    def add_serialization(self, name, decode_fn):
        self.serialization[name] = decode_fn

    def add_classifier_rule(self, rule):
        self.classifier_rules.append(rule)

    def add_kb_importer(self, name, import_fn):
        self.kb_importers[name] = import_fn


def _load_from_path(path):
    name = "vantage_plugin_" + os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _iter_plugin_modules():
    # entry points
    try:
        from importlib.metadata import entry_points
        eps = entry_points()
        group = eps.select(group="vantage.plugins") if hasattr(eps, "select") else eps.get("vantage.plugins", [])
        for ep in group:
            try:
                yield ep.load()
            except Exception:
                continue
    except Exception:
        pass
    # directory
    pdir = os.environ.get("VANTAGE_PLUGINS_DIR", os.path.join(os.getcwd(), "plugins"))
    if os.path.isdir(pdir):
        for fn in sorted(os.listdir(pdir)):
            if fn.endswith(".py") and not fn.startswith("_"):
                try:
                    yield _load_from_path(os.path.join(pdir, fn))
                except Exception:
                    continue


def discover():
    """Return metadata for all discoverable plugins (does not register them)."""
    out = []
    for mod in _iter_plugin_modules():
        meta = getattr(mod, "PLUGIN", None)
        if isinstance(meta, dict) and meta.get("name"):
            out.append(meta)
    return out


def load(registry=None):
    """Discover and register all plugins into a Registry."""
    registry = registry or Registry()
    for mod in _iter_plugin_modules():
        reg = getattr(mod, "register", None)
        if callable(reg):
            try:
                reg(registry)
            except Exception:
                continue
    return registry
