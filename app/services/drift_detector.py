"""
Semantic Role Drift Detector — TF-IDF + 余弦距离 + 注入起点识别
"""
from __future__ import annotations

import hashlib
import logging
import math
from collections import Counter
from typing import Dict, List, Any

logger = logging.getLogger("agent_system")

_DRIFT_THRESHOLD = 0.65
_CONSECUTIVE_HITS = 3
_BASELINE_ROUNDS = 5


class DriftDetector:

    def __init__(self):
        self._baselines: Dict[str, List[float]] = {}

    def analyze(self, texts: List[str], agent_id: str = "unknown") -> Dict[str, Any]:
        if len(texts) < 2:
            return {"drift_detected": False, "drift_score": 0.0, "injection_turn_index": None, "distance_series": []}

        vectors = self._tfidf_vectorize(texts)
        if len(vectors) < 2:
            return {"drift_detected": False, "drift_score": 0.0, "injection_turn_index": None, "distance_series": []}

        baseline_end = min(_BASELINE_ROUNDS, len(vectors))
        centroid = self._compute_centroid(vectors[:baseline_end])

        distance_series = []
        for v in vectors:
            dist = self._cosine_distance(centroid, v)
            distance_series.append(round(dist, 4))

        drift_detected = False
        injection_turn_index = None
        consecutive = 0
        for i, d in enumerate(distance_series[baseline_end:], start=baseline_end):
            if d > _DRIFT_THRESHOLD:
                consecutive += 1
                if consecutive >= _CONSECUTIVE_HITS:
                    drift_detected = True
                    injection_turn_index = i - consecutive + 1
                    break
            else:
                consecutive = 0

        if not drift_detected:
            for i in range(1, len(distance_series)):
                if distance_series[i] - distance_series[i-1] > 0.3 and distance_series[i] > _DRIFT_THRESHOLD:
                    drift_detected = True
                    injection_turn_index = i
                    break

        max_drift = max(distance_series) if distance_series else 0.0

        if drift_detected and injection_turn_index is not None:
            self._log_drift(agent_id, injection_turn_index, distance_series, texts)

        return {
            "drift_detected": drift_detected,
            "drift_score": round(max_drift, 4),
            "injection_turn_index": injection_turn_index,
            "distance_series": distance_series,
        }

    def _tfidf_vectorize(self, texts: List[str]) -> List[Dict[str, float]]:
        tokenized = [self._tokenize(t) for t in texts]
        doc_freq = Counter()
        for tokens in tokenized:
            unique = set(tokens)
            for t in unique:
                doc_freq[t] += 1
        n_docs = len(tokenized)

        vectors = []
        for tokens in tokenized:
            tf = Counter(tokens)
            total = len(tokens) or 1
            vec = {}
            for t, c in tf.items():
                idf = math.log(n_docs / (doc_freq[t] + 1)) + 1.0
                vec[t] = (c / total) * idf
            vectors.append(vec)
        return vectors

    def _tokenize(self, text: str) -> List[str]:
        tokens = []
        for word in text.lower().split():
            cleaned = "".join(c for c in word if c.isalnum() or c in "一二三四五六七八九十")
            if cleaned:
                tokens.append(cleaned)
        for i in range(len(text) - 1):
            if text[i].isalpha() and text[i+1].isalpha():
                tokens.append(text[i:i+2].lower())
        return tokens

    def _compute_centroid(self, vectors: List[Dict[str, float]]) -> Dict[str, float]:
        if not vectors:
            return {}
        centroid = {}
        for v in vectors:
            for k, val in v.items():
                centroid[k] = centroid.get(k, 0.0) + val
        n = len(vectors)
        return {k: v / n for k, v in centroid.items()}

    def _cosine_distance(self, a: Dict[str, float], b: Dict[str, float]) -> float:
        all_keys = set(a.keys()) | set(b.keys())
        dot = sum(a.get(k, 0.0) * b.get(k, 0.0) for k in all_keys)
        mag_a = math.sqrt(sum(v * v for v in a.values()))
        mag_b = math.sqrt(sum(v * v for v in b.values()))
        if mag_a < 1e-10 or mag_b < 1e-10:
            return 1.0
        similarity = dot / (mag_a * mag_b)
        similarity = max(-1.0, min(1.0, similarity))
        return 1.0 - similarity

    def _log_drift(self, agent_id: str, turn_index: int,
                   distance_series: List[float], texts: List[str]):
        try:
            from app import audit
            msg_hash = hashlib.sha256(texts[turn_index].encode()).hexdigest() if turn_index < len(texts) else "unknown"
            audit.log_event(
                agent_id=agent_id,
                action="drift_detected",
                resource="semantic_baseline",
                decision="deny",
                reason=f"Role drift detected at turn {turn_index}, max distance {max(distance_series):.3f}",
                context={"injection_turn": turn_index, "msg_hash": msg_hash, "distance_series": distance_series[-10:]},
            )
        except Exception as e:
            logger.debug("drift audit log failed: %s", e)
