"""
Example Vantage plugin — classifier rules.

Demonstrates the plugin API by contributing extra category keywords to the
managed-class classifier (e.g. teaching it about a project-specific "Economy"
subsystem). This is a read-only, observation-only extension: it only influences
how already-recovered class NAMES are categorised. Copy this file into your
`plugins/` directory (or ship it as a `vantage.plugins` entry point) to activate.
"""

PLUGIN = {
    "name": "example-classifier-rules",
    "description": "Adds an 'Economy' category to the managed-class classifier.",
    "version": "1.0.0",
    "observation_only": True,
}


def register(registry):
    registry.add_classifier_rule({
        "category": "Economy",
        "strong": ["shop", "store", "purchase", "wallet", "currency", "billing", "iap"],
        "weak": ["price", "coin", "gem"],
    })
