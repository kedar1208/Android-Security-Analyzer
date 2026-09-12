"""
SQLite-backed persistence layer for scan history and findings.
"""
from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, ForeignKey, create_engine
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

DATABASE_URL = "sqlite:///./analyzer.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    package_name = Column(String, nullable=True)
    app_name = Column(String, nullable=True)
    version_name = Column(String, nullable=True)
    min_sdk = Column(Integer, nullable=True)
    target_sdk = Column(Integer, nullable=True)
    sha256 = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    risk_score = Column(Float, default=0.0)
    risk_rating = Column(String, default="Unknown")
    dynamic_analysis_run = Column(Integer, default=0)  # 0/1 boolean flag
    status = Column(String, default="completed")  # completed | failed | running
    exported_components_json = Column(Text, nullable=True)

    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    category = Column(String, nullable=False)   # manifest | secrets | nsc | storage | dynamic
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)   # Critical | High | Medium | Low | Info
    weight = Column(Float, default=0.0)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    cwe = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="findings")


def init_db():
    Base.metadata.create_all(bind=engine)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
