"""Tests for the Customer and Market Monitoring modules."""

import pytest

from src.customer.crm import (
    Customer,
    CustomerRelationshipManagement,
    CustomerStage,
    Interaction,
    InteractionType,
)
from src.customer.sentiment import (
    DataSource,
    SentimentAnalyzer,
    SentimentLabel,
    SocialPost,
)


# ---------------------------------------------------------------------------
# CRM tests
# ---------------------------------------------------------------------------

def _make_customer(cid="C-001", stage=CustomerStage.LEAD, value=0.0) -> Customer:
    return Customer(customer_id=cid, name="Test Customer", email="test@example.com",
                    stage=stage, account_value=value)


class TestCRM:
    def setup_method(self):
        self.crm = CustomerRelationshipManagement("Test Company")

    def test_add_and_retrieve_customer(self):
        self.crm.add_customer(_make_customer())
        customer = self.crm.get_customer("C-001")
        assert customer.customer_id == "C-001"

    def test_get_unknown_customer_raises(self):
        with pytest.raises(KeyError):
            self.crm.get_customer("NONEXISTENT")

    def test_customer_stage_advance(self):
        customer = _make_customer(stage=CustomerStage.LEAD)
        customer.advance_stage()
        assert customer.stage == CustomerStage.PROSPECT
        customer.advance_stage()
        assert customer.stage == CustomerStage.CUSTOMER
        # No transition from CUSTOMER
        customer.advance_stage()
        assert customer.stage == CustomerStage.CUSTOMER

    def test_update_stage(self):
        self.crm.add_customer(_make_customer())
        self.crm.update_stage("C-001", CustomerStage.CUSTOMER)
        assert self.crm.get_customer("C-001").stage == CustomerStage.CUSTOMER

    def test_get_customers_by_stage(self):
        self.crm.add_customer(_make_customer("C-001", CustomerStage.LEAD))
        self.crm.add_customer(_make_customer("C-002", CustomerStage.CUSTOMER))
        leads = self.crm.get_customers_by_stage(CustomerStage.LEAD)
        assert len(leads) == 1

    def test_log_interaction(self):
        self.crm.add_customer(_make_customer())
        interaction = Interaction("C-001", InteractionType.CALL, "Discovery call", "agent1")
        self.crm.log_interaction(interaction)
        interactions = self.crm.get_customer_interactions("C-001")
        assert len(interactions) == 1

    def test_log_interaction_unknown_customer_raises(self):
        with pytest.raises(KeyError):
            self.crm.log_interaction(Interaction("NONEXISTENT", InteractionType.EMAIL, "test", "agent"))

    def test_pipeline_summary(self):
        self.crm.add_customer(_make_customer("C-001", CustomerStage.LEAD, 10000.0))
        self.crm.add_customer(_make_customer("C-002", CustomerStage.CUSTOMER, 50000.0))
        summary = self.crm.pipeline_summary()
        assert summary["total_customers"] == 2
        assert summary["stage_values"]["customer"] == 50000.0


# ---------------------------------------------------------------------------
# Sentiment analysis tests
# ---------------------------------------------------------------------------

def _make_post(pid, content, topic="product", source=DataSource.TWITTER) -> SocialPost:
    return SocialPost(post_id=pid, source=source, content=content,
                      author="test_user", topic=topic)


class TestSentimentAnalyzer:
    def setup_method(self):
        self.analyzer = SentimentAnalyzer("Test Brand")

    def test_positive_post(self):
        result = self.analyzer.analyze_post(_make_post("P1", "amazing great excellent product"))
        assert result.label in {SentimentLabel.POSITIVE, SentimentLabel.VERY_POSITIVE}
        assert result.score > 0

    def test_negative_post(self):
        result = self.analyzer.analyze_post(_make_post("P2", "terrible awful broken product"))
        assert result.label in {SentimentLabel.NEGATIVE, SentimentLabel.VERY_NEGATIVE}
        assert result.score < 0

    def test_neutral_post(self):
        result = self.analyzer.analyze_post(_make_post("P3", "the product was delivered today"))
        assert result.label == SentimentLabel.NEUTRAL
        assert result.score == 0.0

    def test_analyze_multiple_posts(self):
        posts = [_make_post(f"P{i}", "good product") for i in range(3)]
        results = self.analyzer.analyze_posts(posts)
        assert len(results) == 3

    def test_topic_sentiment(self):
        self.analyzer.analyze_post(_make_post("P1", "love this great product", topic="product"))
        self.analyzer.analyze_post(_make_post("P2", "wonderful excellent product", topic="product"))
        sentiment = self.analyzer.topic_sentiment("product")
        assert sentiment["count"] == 2
        assert sentiment["avg_score"] > 0

    def test_topic_sentiment_no_data(self):
        sentiment = self.analyzer.topic_sentiment("unknown_topic")
        assert sentiment["count"] == 0
        assert sentiment["avg_score"] is None

    def test_source_breakdown(self):
        self.analyzer.analyze_post(_make_post("P1", "great", source=DataSource.TWITTER))
        self.analyzer.analyze_post(_make_post("P2", "good", source=DataSource.REVIEWS))
        breakdown = self.analyzer.source_breakdown()
        assert "twitter" in breakdown
        assert "reviews" in breakdown

    def test_dashboard(self):
        self.analyzer.analyze_post(_make_post("P1", "great product love it"))
        dashboard = self.analyzer.get_dashboard()
        assert dashboard["total_posts_analyzed"] == 1
        assert dashboard["brand"] == "Test Brand"

    def test_empty_dashboard(self):
        dashboard = self.analyzer.get_dashboard()
        assert dashboard["total_posts_analyzed"] == 0
        assert dashboard["avg_sentiment_score"] is None

    def test_score_range(self):
        result = self.analyzer.analyze_post(_make_post("P1", "amazing wonderful excellent best great outstanding"))
        assert -1.0 <= result.score <= 1.0
        assert 0.0 <= result.confidence <= 1.0
