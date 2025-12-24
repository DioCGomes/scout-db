import os
import json
import sqlite3
import logging
from typing import Optional

# Configuration
REPO_DIR = os.environ.get("SCOUT_REPO_DIR", "advisory-database")
BATCH_SIZE = 1000  # Commit every N records for better performance

# Advisory directories in GitHub Advisory Database
REVIEWED_DIR = "advisories/github-reviewed"
UNREVIEWED_DIR = "advisories/unreviewed"

# Ecosystem normalization mapping
ECOSYSTEM_MAPPING = {
    "Packagist": "composer",
    "PyPI": "pip",
    "Maven": "maven",
    "RubyGems": "gem",
    "npm": "npm",
    "Go": "go",
    "crates.io": "cargo",
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def setup_database(db_file: str) -> sqlite3.Connection:
    """Initialize the database connection and create tables if needed."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS advisories (
                        id TEXT PRIMARY KEY,
                        package TEXT,
                        version_range TEXT,
                        first_patched_version TEXT,
                        ecosystem TEXT,
                        severity TEXT,
                        summary TEXT,
                        details TEXT,
                        cve TEXT,
                        "references" TEXT
                    )''')
    conn.commit()
    return conn


def extract_severity(data: dict) -> str:
    # Try database_specific first
    db_specific = data.get("database_specific", {})
    if "severity" in db_specific:
        return db_specific["severity"]

    # Try severity array (CVSS format)
    severity_list = data.get("severity", [])
    if isinstance(severity_list, list) and severity_list:
        # Prefer CVSS_V3, then CVSS_V4, then any available
        for preferred_type in ["CVSS_V3", "CVSS_V4"]:
            for sev_entry in severity_list:
                if sev_entry.get("type") == preferred_type:
                    return sev_entry.get("score", "Unknown")
        # Fallback to first available score
        return severity_list[0].get("score", "Unknown")

    return "Unknown"


def build_version_range(introduced: Optional[str], fixed: Optional[str], 
                        last_affected: Optional[str]) -> Optional[str]:
    if introduced and last_affected:
        return f">={introduced} <={last_affected}"
    elif introduced and fixed:
        return f">={introduced} <{fixed}"
    elif introduced:
        if introduced == "0":
            return f"<={last_affected}" if last_affected else "all versions"
        range_str = f">={introduced}"
        if last_affected:
            range_str += f" <={last_affected}"
        return range_str
    elif fixed:
        return f"<{fixed}"
    elif last_affected:
        return f"<={last_affected}"
    return None


def process_affected_entry(affected: dict, consolidated: dict, ecosystem_mapping: dict) -> None:
    package = affected.get("package", {}).get("name")
    ecosystem = affected.get("package", {}).get("ecosystem")

    if not package:
        return

    # Normalize ecosystem values
    ecosystem = ecosystem_mapping.get(ecosystem, ecosystem)
    package_key = f"{package}|{ecosystem}"

    # Initialize entry if not exists
    if package_key not in consolidated:
        consolidated[package_key] = {
            "package": package,
            "ecosystem": ecosystem,
            "version_ranges": [],
            "first_patched_versions": []
        }

    entry = consolidated[package_key]

    # Handle direct versions array
    if "versions" in affected and isinstance(affected["versions"], list):
        for version in affected["versions"]:
            version_range = f"={version}"
            if version_range not in entry["version_ranges"]:
                entry["version_ranges"].append(version_range)
        return

    # Handle ranges format with events
    for range_data in affected.get("ranges", []):
        introduced_version = None
        fixed_version = None
        last_affected_version = None

        for event in range_data.get("events", []):
            if "introduced" in event:
                introduced_version = event["introduced"]
            if "fixed" in event:
                fixed_version = event["fixed"]
                if fixed_version and fixed_version not in entry["first_patched_versions"]:
                    entry["first_patched_versions"].append(fixed_version)
            if "last_affected" in event:
                last_affected_version = event["last_affected"]
                next_version = f"{last_affected_version}+"
                if next_version not in entry["first_patched_versions"]:
                    entry["first_patched_versions"].append(next_version)

        range_str = build_version_range(introduced_version, fixed_version, last_affected_version)
        if range_str and range_str not in entry["version_ranges"]:
            entry["version_ranges"].append(range_str)


def generate_composite_id(advisory_id: str, package: Optional[str], ecosystem: Optional[str]) -> str:
    if package and ecosystem:
        return f"{advisory_id}:{ecosystem}:{package}"
    return advisory_id


def process_advisory_file(file_path: str) -> list[tuple]:
    records = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.warning(f"Skipping malformed JSON file {file_path}: {e}")
        return records
    except IOError as e:
        logger.warning(f"Error reading file {file_path}: {e}")
        return records

    advisory_id = data.get("id")
    if not advisory_id:
        logger.warning(f"Skipping file without advisory ID: {file_path}")
        return records

    summary = data.get("summary")
    details = data.get("details")
    severity = extract_severity(data)
    cve = data.get("aliases", [None])[0] if data.get("aliases") else None
    references = json.dumps(data.get("references", []))

    # Consolidate affected entries by package and ecosystem
    consolidated_entries = {}
    affected_list = data.get("affected", [])

    if isinstance(affected_list, list) and affected_list:
        for affected in affected_list:
            process_affected_entry(affected, consolidated_entries, ECOSYSTEM_MAPPING)

    # Generate records for each affected package
    if consolidated_entries:
        for package_key, entry in consolidated_entries.items():
            version_range = " OR ".join(entry["version_ranges"]) if entry["version_ranges"] else None
            first_patched = ", ".join(entry["first_patched_versions"]) if entry["first_patched_versions"] else None

            # Use composite ID to prevent overwriting multi-package advisories
            composite_id = generate_composite_id(advisory_id, entry["package"], entry["ecosystem"])

            records.append((
                composite_id, entry["package"], entry["ecosystem"], severity,
                summary, details, cve, version_range, first_patched, references
            ))
    else:
        # Fallback for advisories without proper affected entries
        records.append((
            advisory_id, None, None, severity, summary, details, cve, None, None, references
        ))

    return records


def extract_advisories(conn: sqlite3.Connection, advisory_dirs: list[str], repo_dir: str = REPO_DIR) -> int:
    cursor = conn.cursor()
    total_processed = 0
    total_records = 0
    pending_records = []

    for advisory_dir in advisory_dirs:
        full_path = os.path.join(repo_dir, advisory_dir)
        if not os.path.exists(full_path):
            logger.warning(f"Advisory directory not found: {full_path}")
            continue

        logger.info(f"Processing directory: {advisory_dir}")

        for root, _, files in os.walk(full_path):
            json_files = [f for f in files if f.endswith(".json")]

            for file in json_files:
                file_path = os.path.join(root, file)
                records = process_advisory_file(file_path)
                pending_records.extend(records)
                total_processed += 1

                # Batch insert for better performance
                if len(pending_records) >= BATCH_SIZE:
                    cursor.executemany('''INSERT OR REPLACE INTO advisories (
                                           id, package, ecosystem, severity, summary, details, cve,
                                           version_range, first_patched_version, "references"
                                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', pending_records)
                    conn.commit()
                    total_records += len(pending_records)
                    logger.info(f"Processed {total_processed} files, inserted {total_records} records...")
                    pending_records = []

    # Insert remaining records
    if pending_records:
        cursor.executemany('''INSERT OR REPLACE INTO advisories (
                               id, package, ecosystem, severity, summary, details, cve,
                               version_range, first_patched_version, "references"
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', pending_records)
        conn.commit()
        total_records += len(pending_records)

    logger.info(f"Completed: {total_processed} files processed, {total_records} records inserted")
    return total_records


def build_database(db_file: str, advisory_dirs: list[str], repo_dir: str = REPO_DIR) -> int:
    logger.info(f"Building database: {db_file}")
    
    # Remove existing database to start fresh
    if os.path.exists(db_file):
        os.remove(db_file)
    
    conn = setup_database(db_file)
    try:
        total = extract_advisories(conn, advisory_dirs, repo_dir)
        logger.info(f"Database {db_file} built successfully with {total} records")
        return total
    finally:
        conn.close()


def main():
    logger.info("Starting advisory database build...")
    logger.info(f"Repository: {REPO_DIR}")
    
    try:
        # Build reviewed-only database
        build_database(
            "scout-reviewed.db",
            [REVIEWED_DIR],
            REPO_DIR
        )
        
        # Build all-advisories database (reviewed + unreviewed)
        build_database(
            "scout.db",
            [REVIEWED_DIR, UNREVIEWED_DIR],
            REPO_DIR
        )
        
        logger.info("All databases built successfully!")
        
    except Exception as e:
        logger.error(f"Failed to build databases: {e}")
        raise


if __name__ == "__main__":
    main()