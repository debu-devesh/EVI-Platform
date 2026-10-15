#!/usr/bin/env python3
"""
Lightweight RAG engine for UFDR data.
Builds an embedding index over messages, contacts, calls, files, and device info,
and answers NL queries by retrieving top-k relevant chunks with metadata.
"""

import re
import json
from typing import Any, Dict, List, Tuple

try:
    import numpy as np
    HAS_NUMPY = True
except Exception as e:
    HAS_NUMPY = False
    NUMPY_ERROR = str(e)

try:
    import faiss
    HAS_FAISS = True
except Exception as e:
    HAS_FAISS = False
    FAISS_ERROR = str(e)

try:
    from sentence_transformers import SentenceTransformer
    HAS_ST = True
except Exception as e:
    HAS_ST = False
    ST_ERROR = str(e)


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False)[:1000]
        except Exception:
            return str(value)[:1000]
    return str(value)[:1000]


class UFDRRAGEngine:
    def __init__(self):
        import logging
        logger = logging.getLogger(__name__)
        
        self.model = None
        self.index = None
        self.chunks: List[Dict[str, Any]] = []
        self.dim = 384  # all-MiniLM-L6-v2
        self.available = HAS_NUMPY and HAS_ST and HAS_FAISS
        self._embed_cache: Dict[str, Any] = {}
        self._query_cache: Dict[Tuple[str, int], Dict[str, Any]] = {}
        
        # Log dependency status
        if not self.available:
            missing = []
            if not HAS_NUMPY:
                missing.append(f"numpy (error: {NUMPY_ERROR if 'NUMPY_ERROR' in globals() else 'not installed'})")
            if not HAS_FAISS:
                missing.append(f"faiss-cpu or faiss-gpu (error: {FAISS_ERROR if 'FAISS_ERROR' in globals() else 'not installed'})")
            if not HAS_ST:
                missing.append(f"sentence-transformers (error: {ST_ERROR if 'ST_ERROR' in globals() else 'not installed'})")
            logger.warning(f"⚠️ RAG engine dependencies missing: {', '.join(missing)}")
            logger.warning(f"⚠️ Install with: pip install numpy faiss-cpu sentence-transformers")
        else:
            try:
                self.model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
                logger.info("✅ RAG engine initialized successfully with all dependencies")
            except Exception as e:
                self.available = False
                logger.error(f"❌ Failed to load SentenceTransformer model: {e}")
                logger.error(f"❌ RAG engine will fall back to keyword-based extraction")

    def _iter_records(self, data: Dict[str, Dict[str, Any]]):
        for file_key, file_data in (data or {}).items():
            # Messages
            for msg in file_data.get('messages', []) or []:
                text = _safe_text(msg.get('text') or msg.get('content'))
                if text:
                    yield {
                        'text': text,
                        'type': 'message',
                        'timestamp': msg.get('timestamp'),
                        'from': msg.get('from') or msg.get('sender'),
                        'to': msg.get('to') or msg.get('receiver'),
                        'source_file': file_key
                    }
            # Contacts
            for c in file_data.get('contacts', []) or []:
                name = _safe_text(c.get('name'))
                phone = _safe_text(c.get('phone'))
                text = (name + ' ' + phone).strip()
                if text:
                    yield {
                        'text': text,
                        'type': 'contact',
                        'name': c.get('name'),
                        'phone': c.get('phone'),
                        'source_file': file_key
                    }
            # Calls
            for call in file_data.get('call_logs', []) or []:
                parts = [call.get('from') or call.get('caller'), call.get('to') or call.get('receiver'), _safe_text(call.get('timestamp'))]
                text = ' '.join([_safe_text(p) for p in parts if p])
                if text:
                    yield {
                        'text': text,
                        'type': 'call',
                        'timestamp': call.get('timestamp'),
                        'from': call.get('from') or call.get('caller'),
                        'to': call.get('to') or call.get('receiver'),
                        'duration': call.get('duration') or call.get('duration_seconds'),
                        'source_file': file_key
                    }
            # Files
            for f in file_data.get('files', []) or []:
                text = _safe_text(f.get('filename')) + ' ' + _safe_text(f.get('path'))
                text = text.strip()
                if text:
                    yield {
                        'text': text,
                        'type': 'file',
                        'filename': f.get('filename'),
                        'path': f.get('path'),
                        'source_file': file_key
                    }
            # Device
            dev = file_data.get('device') or {}
            if isinstance(dev, dict) and dev:
                fields = ['owner_name', 'phone_number', 'device_make', 'device_model', 'imei']
                dev_text = ' '.join([_safe_text(dev.get(k)) for k in fields if dev.get(k)])
                if dev_text:
                    yield {
                        'text': dev_text,
                        'type': 'device',
                        'device_info': dev,
                        'source_file': file_key
                    }

    def build_index(self, data: Dict[str, Dict[str, Any]]):
        import logging
        logger = logging.getLogger(__name__)
        
        self.chunks = list(self._iter_records(data))
        if not self.available:
            logger.warning(f"⚠️ Cannot build RAG index: dependencies missing (numpy, faiss, or sentence-transformers)")
            self.index = None
            return False
        if not self.chunks:
            logger.warning(f"⚠️ Cannot build RAG index: no data chunks found")
            self.index = None
            return False
        
        try:
            self._embed_cache.clear()
            self._query_cache.clear()
            texts = [c['text'] for c in self.chunks]
            logger.info(f"🔨 Building RAG index with {len(self.chunks)} chunks...")
            embeddings = self.model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
            self.dim = embeddings.shape[1]
            self.index = faiss.IndexFlatIP(self.dim)
            self.index.add(embeddings.astype('float32'))
            logger.info(f"✅ RAG index built successfully: {len(self.chunks)} chunks indexed")
            return True
        except Exception as e:
            logger.error(f"❌ Error building RAG index: {e}", exc_info=True)
            self.index = None
            return False

    def is_ready(self) -> bool:
        return self.index is not None and len(self.chunks) > 0

    def query(self, question: str, k: int = 6) -> Dict[str, Any]:
        if not question or not self.is_ready() or not self.available:
            return {
                'ready': False,
                'matches': [],
                'summary': 'RAG index unavailable',
                'used_rag': False
            }
        key = (question.strip().lower(), k)
        if key in self._query_cache:
            return self._query_cache[key]

        if question in self._embed_cache:
            q = self._embed_cache[question]
        else:
            q = self.model.encode([question], normalize_embeddings=True, convert_to_numpy=True).astype('float32')
            self._embed_cache[question] = q
        distances, indices = self.index.search(q, min(k, len(self.chunks)))
        hits = []
        for score, idx in zip(distances[0].tolist(), indices[0].tolist()):
            if idx == -1:
                continue
            meta = dict(self.chunks[idx])
            meta['score'] = float(score)
            # truncate text for faster transport/rendering
            if isinstance(meta.get('text'), str) and len(meta['text']) > 220:
                meta['text'] = meta['text'][:220] + '...'
            hits.append(meta)
        summary = self._summarize(question, hits)
        out = {
            'ready': True,
            'matches': hits,
            'summary': summary,
            'used_rag': True
        }
        self._query_cache[key] = out
        # simple LRU bound
        if len(self._query_cache) > 64:
            self._query_cache.pop(next(iter(self._query_cache)))
        return out

    def _summarize(self, question: str, hits: List[Dict[str, Any]]) -> str:
        if not hits:
            return "No directly relevant evidence found."
        types = {}
        for h in hits[:10]:
            t = h.get('type', 'unknown')
            types[t] = types.get(t, 0) + 1
        parts = [f"Top evidence types: {', '.join(f'{v} {k}' for k, v in sorted(types.items(), key=lambda x: -x[1]))}."]
        first_file = hits[0].get('source_file')
        if first_file:
            parts.append(f"Most relevant file: {first_file}.")
        return ' '.join(parts)


