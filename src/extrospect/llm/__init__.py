"""Layered LLM pipeline (Engine mode). Importing this package never imports litellm;
only :mod:`extrospect.llm.client` does, lazily, when a model is actually called."""
