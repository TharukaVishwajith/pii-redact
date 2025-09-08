#!/usr/bin/env python3
"""
Script to redact speaker_sentence fields in JSON conversation files
using the existing PII redaction system.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any

# Import the redaction functionality from app.py
from app import redact_text, load_spacy

def process_json_file(input_path: str, output_path: str, strategy: str = "hash", salt: str = "pii-redact-salt") -> bool:
    """
    Process a single JSON file and redact all speaker_sentence fields.
    
    Args:
        input_path: Path to input JSON file
        output_path: Path to save redacted JSON file
        strategy: Redaction strategy ('hash', 'label', or 'mask')
        salt: Salt for hashing
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Read the JSON file
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Check if conversation exists
        if 'conversation' not in data:
            print(f"Warning: No 'conversation' field found in {input_path}")
            return False
        
        conversation = data['conversation']
        redacted_count = 0
        
        # Process each conversation entry
        for key, entry in conversation.items():
            if isinstance(entry, dict) and 'speaker_sentence' in entry:
                original_sentence = entry['speaker_sentence']
                if original_sentence:  # Only redact non-empty sentences
                    redacted_sentence = redact_text(
                        original_sentence,
                        strategy=strategy,
                        salt=salt,
                        use_spacy_person=True
                    )
                    entry['speaker_sentence'] = redacted_sentence
                    redacted_count += 1
                    print(f"  Redacted entry {key}: '{original_sentence[:50]}...' -> '{redacted_sentence[:50]}...'")
        
        # Save the redacted data
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"Successfully processed {input_path} -> {output_path} (redacted {redacted_count} sentences)")
        return True
        
    except Exception as e:
        print(f"Error processing {input_path}: {str(e)}")
        return False

def process_directory(input_dir: str, output_dir: str, strategy: str = "hash", salt: str = "pii-redact-salt") -> None:
    """
    Process all JSON files in a directory.
    
    Args:
        input_dir: Directory containing input JSON files
        output_dir: Directory to save redacted JSON files
        strategy: Redaction strategy
        salt: Salt for hashing
    """
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    # Create output directory if it doesn't exist
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Find all JSON files
    json_files = list(input_path.glob("*.json"))
    
    if not json_files:
        print(f"No JSON files found in {input_dir}")
        return
    
    print(f"Found {len(json_files)} JSON files to process")
    
    # Process each file
    successful = 0
    failed = 0
    
    for json_file in json_files:
        output_file = output_path / json_file.name
        print(f"\nProcessing: {json_file.name}")
        
        if process_json_file(str(json_file), str(output_file), strategy, salt):
            successful += 1
        else:
            failed += 1
    
    print(f"\n=== Processing Complete ===")
    print(f"Successfully processed: {successful} files")
    print(f"Failed: {failed} files")
    print(f"Output directory: {output_dir}")

def main():
    """Main function to run the JSON processing."""
    # Try to load spaCy model for better name detection
    try:
        print("Loading spaCy model for enhanced name detection...")
        load_spacy(require_gpu=False)
        print("spaCy model loaded successfully")
    except Exception as e:
        print(f"Warning: Could not load spaCy model: {e}")
        print("Will proceed with regex-only redaction")
    
    # Default paths
    input_directory = "/Users/tharuka/rozie/ci/downloads"
    output_directory = "/Users/tharuka/rozie/ci/pii_redact/redacted_output"
    
    # Configuration
    redaction_strategy = "hash"  # Can be 'hash', 'label', or 'mask'
    redaction_salt = "secure-pii-salt-2025"
    
    print(f"Input directory: {input_directory}")
    print(f"Output directory: {output_directory}")
    print(f"Redaction strategy: {redaction_strategy}")
    print(f"Using salt: {redaction_salt}")
    print()
    
    # Process all files
    process_directory(
        input_directory,
        output_directory,
        strategy=redaction_strategy,
        salt=redaction_salt
    )

if __name__ == "__main__":
    main()
