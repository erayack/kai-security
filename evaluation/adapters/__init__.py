"""Benchmark adapters for the evaluation harness.

Each adapter implements ``BenchAdapter`` from :mod:`evaluation.adapters.base`
and is responsible for materialising tasks on disk, deciding what extra
prompt context the pipeline should see, and scoring the pipeline output
against the benchmark's oracle.
"""

from evaluation.adapters.base import BenchAdapter, register_adapter, resolve_adapter

__all__ = ["BenchAdapter", "register_adapter", "resolve_adapter"]
