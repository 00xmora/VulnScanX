import logging
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint, JSON, create_engine, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.exc import IntegrityError


logger = logging.getLogger(__name__)
Base = declarative_base()

class ScanHistory(Base):
    __tablename__ = 'scan_history'
    id = Column(Integer, primary_key=True)
    domain = Column(String, unique=True, nullable=False)
    scan_date = Column(DateTime, default=func.now())

    recon_data = relationship("ReconResult", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

class ReconResult(Base):
    __tablename__ = 'recon_results'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'))
    data_type = Column(String)  # e.g., "subdomain", "ip"
    value = Column(String)

    __table_args__ = (UniqueConstraint('scan_id', 'data_type', 'value', name='unique_recon_result'),)

    scan = relationship("ScanHistory", back_populates="recon_data")

class Endpoint(Base):
    __tablename__ = 'endpoints'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'))
    url = Column(String, nullable=False)
    method = Column(String, nullable=False)
    body_params = Column(JSON)
    extra_headers = Column(JSON)

    __table_args__ = (UniqueConstraint('scan_id', 'url', 'method', name='unique_endpoint_per_scan'),)

    scan = relationship("ScanHistory", back_populates="endpoints")

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'))
    vulnerability_data = Column(JSON)
    vulnerability_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    url = Column(String, nullable=False)

    __table_args__ = (UniqueConstraint('scan_id', 'vulnerability_type', 'severity', 'url', name='unique_vulnerability_per_scan'),)

    scan = relationship("ScanHistory", back_populates="vulnerabilities")

# Functions to Init & Use DB
def init_db(db_path='sqlite:///vulnscanx.db'):
    engine = create_engine(db_path)
    Base.metadata.create_all(engine)
    return engine

def get_session(engine):
    Session = sessionmaker(bind=engine)
    return Session()

# Query Function
def get_scan_results_by_domain(session, domain):
    scan = session.query(ScanHistory).filter_by(domain=domain).first()
    if not scan:
        return None

    recon_results = [
        {"type": r.data_type, "value": r.value}
        for r in scan.recon_data
    ]

    endpoints_data = [
        {"url": e.url, "method": e.method, "body_params": e.body_params, "extra_headers": e.extra_headers}
        for e in scan.endpoints
    ]

    vulnerabilities = scan.vulnerabilities

    return {
        "domain": scan.domain,
        "scan_date": scan.scan_date,
        "recon": recon_results,
        "endpoints": endpoints_data,
        "vulnerabilities": [v.vulnerability_data for v in vulnerabilities]
    }


def try_save_vulnerability(vuln_data, session, scan_id):
    """
    Saves a vulnerability to the database with error handling.
    Avoids duplicates and logs any issues.
    """
    try:
        new_vulnerability = Vulnerability(
            scan_id=scan_id,
            vulnerability_data=vuln_data,
            vulnerability_type=vuln_data["vulnerability"],
            severity=vuln_data["severity"],
            url=vuln_data["url"]
        )
        session.add(new_vulnerability)
        session.commit()
        logger.info(f"[DB] Saved: {vuln_data['vulnerability']} at {vuln_data['url']}")
    except IntegrityError:
        session.rollback()
        logger.info(f"[DB] Duplicate skipped: {vuln_data.get('vulnerability')} at {vuln_data.get('url')}")
    except Exception as db_e:
        session.rollback()
        logger.error(f"[DB] Error saving vulnerability: {db_e}")