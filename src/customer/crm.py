"""
Customer Relationship Management (CRM).

Tracks customer interactions, feedback, and the sales pipeline, mirroring
platforms like Salesforce.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from src.time_utils import utc_now


class CustomerStage(Enum):
    LEAD = "lead"
    PROSPECT = "prospect"
    CUSTOMER = "customer"
    CHURNED = "churned"


class InteractionType(Enum):
    CALL = "call"
    EMAIL = "email"
    MEETING = "meeting"
    SUPPORT_TICKET = "support_ticket"
    PURCHASE = "purchase"
    FEEDBACK = "feedback"


@dataclass
class Customer:
    customer_id: str
    name: str
    email: str
    stage: CustomerStage = CustomerStage.LEAD
    account_value: float = 0.0
    created_at: datetime.datetime = field(default_factory=utc_now)
    metadata: Dict = field(default_factory=dict)

    def advance_stage(self) -> None:
        transitions = {
            CustomerStage.LEAD: CustomerStage.PROSPECT,
            CustomerStage.PROSPECT: CustomerStage.CUSTOMER,
        }
        if self.stage in transitions:
            self.stage = transitions[self.stage]


@dataclass
class Interaction:
    customer_id: str
    interaction_type: InteractionType
    summary: str
    agent: str
    timestamp: datetime.datetime = field(default_factory=utc_now)
    outcome: str = ""


class CustomerRelationshipManagement:
    """
    CRM system for managing customers, sales pipeline, and customer interactions.
    """

    def __init__(self, company: str) -> None:
        self.company = company
        self._customers: Dict[str, Customer] = {}
        self._interactions: List[Interaction] = []

    # ------------------------------------------------------------------
    # Customer management
    # ------------------------------------------------------------------

    def add_customer(self, customer: Customer) -> None:
        self._customers[customer.customer_id] = customer

    def get_customer(self, customer_id: str) -> Customer:
        if customer_id not in self._customers:
            raise KeyError(f"Customer '{customer_id}' not found")
        return self._customers[customer_id]

    def update_stage(self, customer_id: str, stage: CustomerStage) -> None:
        self.get_customer(customer_id).stage = stage

    def get_customers_by_stage(self, stage: CustomerStage) -> List[Customer]:
        return [c for c in self._customers.values() if c.stage == stage]

    # ------------------------------------------------------------------
    # Interactions
    # ------------------------------------------------------------------

    def log_interaction(self, interaction: Interaction) -> None:
        if interaction.customer_id not in self._customers:
            raise KeyError(f"Customer '{interaction.customer_id}' not found")
        self._interactions.append(interaction)

    def get_customer_interactions(self, customer_id: str) -> List[Interaction]:
        return [i for i in self._interactions if i.customer_id == customer_id]

    # ------------------------------------------------------------------
    # Pipeline analytics
    # ------------------------------------------------------------------

    def pipeline_summary(self) -> Dict:
        stage_counts: Dict[str, int] = {s.value: 0 for s in CustomerStage}
        stage_value: Dict[str, float] = {s.value: 0.0 for s in CustomerStage}
        for customer in self._customers.values():
            stage_counts[customer.stage.value] += 1
            stage_value[customer.stage.value] += customer.account_value
        return {
            "company": self.company,
            "total_customers": len(self._customers),
            "stage_counts": stage_counts,
            "stage_values": stage_value,
            "total_interactions": len(self._interactions),
        }

    def get_dashboard(self) -> Dict:
        return self.pipeline_summary()
