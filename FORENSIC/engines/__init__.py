"""Query engine package with lazy, optional imports.

Avoid importing heavy optional modules (like FAISS/RAG) at package import time.
This keeps startup stable even when optional dependencies are unavailable.
"""

from importlib import import_module

__all__ = [
    "NaturalLanguageUFDR",
    "EnhancedNaturalLanguageUFDR",
    "SimplifiedNLQueryEngine",
    "AIUFDRRetrievalEngine",
    "UFDRRAGEngine",
    "smart_analyzer",
]

_LAZY_IMPORTS = {
    "NaturalLanguageUFDR": (".nl_query_engine", "NaturalLanguageUFDR"),
    "EnhancedNaturalLanguageUFDR": (".enhanced_nl_query_engine", "EnhancedNaturalLanguageUFDR"),
    "SimplifiedNLQueryEngine": (".simplified_nl_query_engine", "SimplifiedNLQueryEngine"),
    "AIUFDRRetrievalEngine": (".ai_ufdr_retrieval_engine", "AIUFDRRetrievalEngine"),
    "UFDRRAGEngine": (".rag_engine", "UFDRRAGEngine"),
    "smart_analyzer": (".smart_analyzer", "smart_analyzer"),
}


def __getattr__(name):
    target = _LAZY_IMPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = target
    module = import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value

