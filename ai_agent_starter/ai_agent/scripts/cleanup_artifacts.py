#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script untuk memindahkan artifact files yang berantakan (flat) di root artifacts/
ke struktur folder yang terorganisir berdasarkan role dan bac_type.

Struktur target:
artifacts/
  ├── {role}/
  │   ├── AUTH/
  │   ├── BASELINE/
  │   ├── BOLA/
  │   ├── IDOR/
  │   └── DISCOVERY/

Usage:
    python ai_agent/scripts/cleanup_artifacts.py [--dry-run] [--verbose]
"""

import os
import sys
import json
import shutil
from pathlib import Path
import argparse

# Fix Windows console encoding for emoji/unicode
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(description="Cleanup flat artifact files into organized structure")
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without moving files')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed output')
    args = parser.parse_args()

    artifacts_root = Path("ai_agent/runs/artifacts")
    if not artifacts_root.exists():
        print(f"❌ Error: {artifacts_root} not found")
        return

    # Find all JSON files in root (not in subdirectories)
    flat_files = [f for f in artifacts_root.iterdir() if f.is_file() and f.suffix == '.json']
    
    if not flat_files:
        print("✅ No flat artifact files found in root. Already organized!")
        return

    print(f"📁 Found {len(flat_files)} flat artifact files in {artifacts_root}/")
    print()

    moved_count = 0
    skipped_count = 0
    error_count = 0

    for artifact_file in flat_files:
        try:
            # Read metadata from artifact JSON
            with open(artifact_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            metadata = data.get('metadata', {})
            role = metadata.get('role')
            bac_type = metadata.get('bac_type')
            
            if not role or not bac_type:
                # Try to infer from folder_label
                folder_label = metadata.get('folder_label', '')
                if folder_label:
                    # Format: "employee (BASELINE)" or "admin_hc (IDOR)" or " (BASELINE)"
                    if '(' in folder_label and ')' in folder_label:
                        parts = folder_label.split('(')
                        role_part = parts[0].strip()
                        bac_label = parts[1].strip(')')
                        
                        # If role_part is empty, try to infer from request URL
                        if not role_part:
                            # Try to get role from request
                            req = data.get('request', {})
                            headers = req.get('headers', {})
                            auth = headers.get('Authorization', '')
                            if 'admin' in auth.lower():
                                role = 'Admin_HC'
                            elif 'employee' in auth.lower():
                                role = 'Employee'
                            # If still can't determine, leave role as None
                            # Will be handled by the check below
                        else:
                            role = role_part
                        
                        # Map label back to bac_type
                        bac_type = {
                            'IDOR': 'horizontal',
                            'BOLA': 'vertical',
                            'AUTH': 'auth',
                            'BASELINE': 'baseline',
                            'DISCOVERY': 'discovery'
                        }.get(bac_label, 'baseline')
            
            if not role:
                # Move orphans to UNKNOWN folder instead of deleting
                target_dir = artifacts_root / "UNKNOWN" / "DISCOVERY"
                target_file = target_dir / artifact_file.name
                
                if target_file.exists():
                    if args.verbose:
                        print(f"⚠️  Skipping {artifact_file.name}: already exists in UNKNOWN/")
                    skipped_count += 1
                    continue
                
                if args.verbose or args.dry_run:
                    print(f"{'[DRY-RUN] ' if args.dry_run else ''}📦 {artifact_file.name} → UNKNOWN/DISCOVERY/")
                
                if not args.dry_run:
                    target_dir.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(artifact_file), str(target_file))
                
                moved_count += 1
                continue

            # Normalize role name
            role_folder = role.lower().replace(' ', '_').replace('-', '_')
            
            # Determine label folder
            bt = (bac_type or 'baseline').strip().lower()
            label = (
                "IDOR" if bt == "horizontal" else
                "BOLA" if bt == "vertical" else
                "AUTH" if bt == "auth" else
                "DISCOVERY" if bt == "discovery" else
                "BASELINE"
            )
            
            # Target directory
            target_dir = artifacts_root / role_folder / label
            target_file = target_dir / artifact_file.name
            
            # Check if file already exists in target
            if target_file.exists():
                if args.verbose:
                    print(f"⚠️  Skipping {artifact_file.name}: already exists at {target_file}")
                skipped_count += 1
                continue
            
            # Show what will be done
            if args.verbose or args.dry_run:
                print(f"{'[DRY-RUN] ' if args.dry_run else ''}📦 {artifact_file.name}")
                print(f"   → {target_dir.relative_to(artifacts_root)}/")
            
            if not args.dry_run:
                # Create target directory
                target_dir.mkdir(parents=True, exist_ok=True)
                
                # Move file
                shutil.move(str(artifact_file), str(target_file))
                moved_count += 1
            else:
                moved_count += 1  # Count for dry-run preview
                
        except json.JSONDecodeError:
            print(f"❌ Error: {artifact_file.name} is not valid JSON")
            error_count += 1
        except Exception as e:
            print(f"❌ Error processing {artifact_file.name}: {e}")
            error_count += 1

    # Summary
    print()
    print("="*60)
    if args.dry_run:
        print("🔍 DRY-RUN SUMMARY")
    else:
        print("✅ CLEANUP COMPLETE")
    print("="*60)
    print(f"{'Would move' if args.dry_run else 'Moved'}: {moved_count} files")
    print(f"Skipped: {skipped_count} files")
    if error_count > 0:
        print(f"Errors: {error_count} files")
    print()
    
    if args.dry_run:
        print("💡 Run without --dry-run to actually move files")
        print("   Example: python ai_agent/scripts/cleanup_artifacts.py")

if __name__ == '__main__':
    main()
