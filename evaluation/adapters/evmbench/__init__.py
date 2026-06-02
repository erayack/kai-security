"""EVMbench DETECT-mode benchmark adapter (Paradigm + OpenAI).

EVMbench (https://github.com/paradigmxyz/evmbench, Apache-2.0) is a
Solidity smart-contract vulnerability benchmark. The detect split has
40 audits across 2023-2025, each with one or more `H-XX` / `M-XX` /
`L-XX` findings. This adapter targets DETECT mode: kai inspects the
audit codebase, emits one or more candidate exploits, and we score by
counting how many ground-truth findings the agent's hypotheses match.
"""
