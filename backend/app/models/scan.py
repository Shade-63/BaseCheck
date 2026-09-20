import uuid
import secrets
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Float, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.app.database import Base

def generate_public_id() -> str:
    #generates a clean 16-char URL-safe string for shareable report links
    return secrets.token_urlsafe(12)

class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False)
    public_id = Column(
        String(32),
        unique=True,
        index=True,
        nullable=False,
        default=generate_public_id,
    )
    status = Column(String(50), default="pending", nullable=False)

    # denormalized overzall results (calculated once all 4 checks complete)
    overall_grade = Column(String(2), nullable=True)
    overall_score = Column(Float, nullable=True)

    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    created_at = Column(
            DateTime(timezone=True),
            default=lambda: datetime.now(timezone.utc),
            nullable=False,
        )

    #relationships
    user = relationship("User", back_populates="scans")
    results = relationship(
        "ScanResult",
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
