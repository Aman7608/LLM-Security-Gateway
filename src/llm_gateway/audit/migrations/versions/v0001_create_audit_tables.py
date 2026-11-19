"""Create the four audit tables.

Revision ID: 0001
Revises: (none, this is the first one)
Created: 20 November 2026
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "api_client",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("key_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("role", sa.String(10), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "policy_version",
        sa.Column("version", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=False),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("policy_yaml", sa.Text(), nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
    )
    op.create_table(
        "audit_event",
        sa.Column("request_id", sa.String(64), primary_key=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("client_id", sa.String(64), sa.ForeignKey("api_client.id")),
        sa.Column(
            "policy_version", sa.Integer(), sa.ForeignKey("policy_version.version")
        ),
        sa.Column("provider", sa.String(30)),
        sa.Column("model", sa.String(100)),
        sa.Column("input_action", sa.String(10), nullable=False),
        sa.Column("output_action", sa.String(10)),
        sa.Column("risk_level", sa.String(10), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("input_chars", sa.Integer(), nullable=False),
        sa.Column("output_chars", sa.Integer(), nullable=False),
        sa.Column("scan_ms", sa.Float(), nullable=False),
        sa.Column("provider_ms", sa.Float(), nullable=False),
        sa.Column("total_ms", sa.Float(), nullable=False),
        sa.Column("redacted_prompt", sa.Text()),
    )
    # Indexes make the dashboard filters fast (section 8.2 of the architecture)
    op.create_index("ix_audit_event_timestamp", "audit_event", ["timestamp"])
    op.create_index("ix_audit_event_risk_level", "audit_event", ["risk_level"])
    op.create_index("ix_audit_event_client_id", "audit_event", ["client_id"])
    op.create_table(
        "finding_record",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "request_id",
            sa.String(64),
            sa.ForeignKey("audit_event.request_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("direction", sa.String(10), nullable=False),
        sa.Column("detector", sa.String(30), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("entity_type", sa.String(50)),
        sa.Column("rule_id", sa.String(100)),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("span_start", sa.Integer(), nullable=False),
        sa.Column("span_end", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(32)),
    )
    op.create_index("ix_finding_record_request_id", "finding_record", ["request_id"])
    op.create_index("ix_finding_record_fingerprint", "finding_record", ["fingerprint"])


def downgrade() -> None:
    op.drop_table("finding_record")
    op.drop_table("audit_event")
    op.drop_table("policy_version")
    op.drop_table("api_client")
