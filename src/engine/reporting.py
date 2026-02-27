import json
import hashlib
from typing import Dict

def generate_secure_report(report_data: Dict, output_filepath: str) -> None:
    """
    Takes the JSON report, serializes it, computes SHA-256 chain,
    and writes to disk.
    """
    # Serialize the JSON report
    serialized_report = json.dumps(report_data, indent=4, sort_keys=True)
    
    # Generate SHA-256 chain/hash
    hash_obj = hashlib.sha256()
    hash_obj.update(serialized_report.encode('utf-8'))
    report_hash = hash_obj.hexdigest()

    # Append the hash to the document root safely
    secure_report_data = {
        "integrity_hash_sha256": report_hash,
        "content": report_data
    }

    final_json = json.dumps(secure_report_data, indent=4)
    
    with open(output_filepath, 'w') as f:
        f.write(final_json)
    
    print(f"[+] Secure report saved to: {output_filepath}")
    print(f"[+] Report SHA-256: {report_hash}")
