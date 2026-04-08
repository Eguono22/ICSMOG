"""
Sentiment Analysis Tools.

Monitors social media and public sentiment using Natural Language Processing
(NLP) techniques to gauge customer and market perception.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from src.time_utils import utc_now


class SentimentLabel(Enum):
    VERY_NEGATIVE = "very_negative"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"
    POSITIVE = "positive"
    VERY_POSITIVE = "very_positive"


class DataSource(Enum):
    TWITTER = "twitter"
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    NEWS = "news"
    REVIEWS = "reviews"
    SURVEY = "survey"
    OTHER = "other"


@dataclass
class SocialPost:
    post_id: str
    source: DataSource
    content: str
    author: str
    topic: str
    timestamp: datetime.datetime = field(default_factory=utc_now)
    metadata: Dict = field(default_factory=dict)


@dataclass
class SentimentResult:
    post_id: str
    label: SentimentLabel
    score: float  # -1.0 (very negative) to +1.0 (very positive)
    confidence: float  # 0.0 to 1.0
    analyzed_at: datetime.datetime = field(default_factory=utc_now)


class SentimentAnalyzer:
    """
    Lexicon-based sentiment analyzer that classifies social media posts and
    news content to provide an overall market sentiment view.

    This implementation uses a lightweight keyword-based approach suitable for
    demonstrating the concept without external ML model dependencies.
    """

    _POSITIVE_WORDS = {
        "great", "good", "excellent", "amazing", "outstanding", "love", "best",
        "fantastic", "wonderful", "superb", "awesome", "perfect", "happy",
        "pleased", "satisfied", "recommend", "impressive", "innovative",
    }
    _NEGATIVE_WORDS = {
        "bad", "terrible", "awful", "horrible", "poor", "worst", "hate",
        "disappoint", "disappointing", "disappointed", "slow", "broken",
        "fail", "failure", "issue", "problem", "wrong", "useless", "refund",
    }

    def __init__(self, brand: str) -> None:
        self.brand = brand
        self._posts: List[SocialPost] = []
        self._results: Dict[str, SentimentResult] = {}

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze_post(self, post: SocialPost) -> SentimentResult:
        """Analyze a single post and cache the result."""
        self._posts.append(post)
        score, confidence = self._score_text(post.content)
        label = self._label_from_score(score)
        result = SentimentResult(
            post_id=post.post_id,
            label=label,
            score=score,
            confidence=confidence,
        )
        self._results[post.post_id] = result
        return result

    def analyze_posts(self, posts: List[SocialPost]) -> List[SentimentResult]:
        return [self.analyze_post(p) for p in posts]

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def topic_sentiment(self, topic: str) -> Dict:
        """Return average sentiment statistics for a specific topic."""
        scores = [
            self._results[p.post_id].score
            for p in self._posts
            if p.topic == topic and p.post_id in self._results
        ]
        if not scores:
            return {"topic": topic, "count": 0, "avg_score": None}
        avg = sum(scores) / len(scores)
        return {
            "topic": topic,
            "count": len(scores),
            "avg_score": avg,
            "label": self._label_from_score(avg).value,
        }

    def source_breakdown(self) -> Dict[str, Dict]:
        """Return sentiment breakdown per source channel."""
        breakdown: Dict[str, List[float]] = {}
        for post in self._posts:
            if post.post_id in self._results:
                key = post.source.value
                breakdown.setdefault(key, []).append(self._results[post.post_id].score)
        return {
            source: {
                "count": len(scores),
                "avg_score": sum(scores) / len(scores),
                "label": self._label_from_score(sum(scores) / len(scores)).value,
            }
            for source, scores in breakdown.items()
        }

    def get_dashboard(self) -> Dict:
        all_scores = [r.score for r in self._results.values()]
        label_counts: Dict[str, int] = {label.value: 0 for label in SentimentLabel}
        for result in self._results.values():
            label_counts[result.label.value] += 1
        avg_score = sum(all_scores) / len(all_scores) if all_scores else None
        return {
            "brand": self.brand,
            "total_posts_analyzed": len(self._results),
            "avg_sentiment_score": avg_score,
            "overall_label": self._label_from_score(avg_score).value if avg_score is not None else None,
            "label_breakdown": label_counts,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _score_text(self, text: str) -> tuple:
        """Return (score, confidence) based on keyword matching."""
        words = set(re.findall(r"[a-z]+", text.lower()))
        pos = len(words & self._POSITIVE_WORDS)
        neg = len(words & self._NEGATIVE_WORDS)
        total = pos + neg
        if total == 0:
            return 0.0, 0.5
        score = (pos - neg) / total
        confidence = min(total / 5, 1.0)
        return score, confidence

    @staticmethod
    def _label_from_score(score: Optional[float]) -> SentimentLabel:
        if score is None:
            return SentimentLabel.NEUTRAL
        if score >= 0.6:
            return SentimentLabel.VERY_POSITIVE
        if score >= 0.2:
            return SentimentLabel.POSITIVE
        if score > -0.2:
            return SentimentLabel.NEUTRAL
        if score > -0.6:
            return SentimentLabel.NEGATIVE
        return SentimentLabel.VERY_NEGATIVE
