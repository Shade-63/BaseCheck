import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Boolean, DateTime, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from backend.app.database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    __table_args__ = (
        CheckConstraint(
            "check_type IN ('tls', 'headers','exposed_files','dns')",
            name= "check_scan_result_check_type",
        ),
        CheckConstraint(
            "grade IN ('A','B','C','D','F')",
            name= "check_scan_result_grade",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    check_type = Column(String(50), nullable=False)
    grade = Column(String(2), nullable=False)
    score = Column(Float, nullable=False)
    passed = Column(Boolean, nullable=False)
    details_json = Column(JSONB, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    #relationship back to scan
    scan = relationship("Scan", back_populates="results")