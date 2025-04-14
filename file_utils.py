import os
import hashlib
import shutil
import logging
import sqlite3
import time
from datetime import datetime
import config

# Set up logging
logging.basicConfig(level=logging.INFO, 
                  format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('file_utils')

# Database to store file checksums and status
CHECKSUM_DB = os.path.join(config.LOG_DIR, 'file_checksums.db')

def init_checksum_db():
    """Initialize the checksum database if it doesn't exist"""
    try:
        conn = sqlite3.connect(CHECKSUM_DB)
        cursor = conn.cursor()
        
        # Create table to store checksums and file status
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_checksums (
            path TEXT PRIMARY KEY,
            checksum TEXT,
            last_modified TEXT,
            deleted INTEGER DEFAULT 0,
            last_updated TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Checksum database initialized at {CHECKSUM_DB}")
        return True
    except Exception as e:
        logger.error(f"Error initializing checksum database: {e}")
        return False

def compute_checksum(file_path):
    """Compute MD5 checksum of a file"""
    try:
        if not os.path.exists(file_path):
            return None
            
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Error computing checksum for {file_path}: {e}")
        return None

def store_file_checksum(file_path, is_deleted=False):
    """Store file checksum in database"""
    try:
        # Get relative path from monitoring directory
        try:
            rel_path = os.path.relpath(file_path, config.MONITORING_DIR)
        except ValueError:
            # If file_path is not within MONITORING_DIR
            logger.warning(f"File path {file_path} is not within monitoring directory")
            return False
            
        conn = sqlite3.connect(CHECKSUM_DB)
        cursor = conn.cursor()
        
        current_time = datetime.now().isoformat()
        
        if is_deleted:
            # Mark file as deleted
            cursor.execute('''
            UPDATE file_checksums
            SET deleted = 1, last_updated = ?
            WHERE path = ?
            ''', (current_time, rel_path))
            
            if cursor.rowcount == 0:
                # If file wasn't in database yet, add it as deleted
                cursor.execute('''
                INSERT OR REPLACE INTO file_checksums 
                (path, checksum, last_modified, deleted, last_updated)
                VALUES (?, ?, ?, 1, ?)
                ''', (rel_path, None, None, current_time))
                
            logger.debug(f"Marked file as deleted in DB: {rel_path}")
        else:
            # File exists - compute and store checksum
            if not os.path.exists(file_path):
                logger.warning(f"Cannot store checksum - file doesn't exist: {file_path}")
                return False
                
            checksum = compute_checksum(file_path)
            last_modified = datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
            
            cursor.execute('''
            INSERT OR REPLACE INTO file_checksums 
            (path, checksum, last_modified, deleted, last_updated)
            VALUES (?, ?, ?, 0, ?)
            ''', (rel_path, checksum, last_modified, current_time))
            
            logger.debug(f"Stored checksum for file: {rel_path}")
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error storing checksum for {file_path}: {e}")
        return False

def is_file_modified(file_path):
    """Check if a file has been modified compared to stored checksum"""
    try:
        if not os.path.exists(file_path):
            return False
            
        # Get relative path
        rel_path = os.path.relpath(file_path, config.MONITORING_DIR)
            
        conn = sqlite3.connect(CHECKSUM_DB)
        cursor = conn.cursor()
        
        # Get stored checksum
        cursor.execute('SELECT checksum, deleted FROM file_checksums WHERE path = ?', (rel_path,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            # No stored checksum means it's a new file
            logger.debug(f"No stored checksum for {rel_path} - treating as new file")
            return False
            
        stored_checksum, is_deleted = result
        
        if is_deleted == 1:
            # This file was previously deleted - treat it as modified
            logger.debug(f"File was previously deleted: {rel_path}")
            return True
            
        current_checksum = compute_checksum(file_path)
        is_modified = stored_checksum != current_checksum
        
        if is_modified:
            logger.debug(f"File has been modified: {rel_path}")
            
        return is_modified
    except Exception as e:
        logger.error(f"Error checking if file is modified {file_path}: {e}")
        return False

def backup_with_checksum(src_path, dest_path):
    """Backup a file and store its checksum"""
    try:
        # Skip if source doesn't exist
        if not os.path.exists(src_path):
            logger.warning(f"Cannot backup - source doesn't exist: {src_path}")
            return False
            
        # Create destination directory if needed
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        
        # Copy the file
        shutil.copy2(src_path, dest_path)
        
        # Store checksum in database
        store_file_checksum(src_path)
        
        logger.debug(f"Backed up file with checksum: {src_path} -> {dest_path}")
        return True
    except Exception as e:
        logger.error(f"Error backing up {src_path} to {dest_path}: {e}")
        return False

def checksum_recovery(detection_time=None):
    """Smart recovery based on checksums and deletion history
    
    Args:
        detection_time: Optional timestamp of when ransomware was detected
        
    Returns:
        Number of files restored
    """
    try:
        logger.info("Starting checksum-based recovery...")
        
        conn = sqlite3.connect(CHECKSUM_DB)
        cursor = conn.cursor()
        
        # If detection_time is provided, convert it to ISO format
        detection_time_iso = None
        if detection_time:
            try:
                detection_time_iso = datetime.fromtimestamp(detection_time).isoformat()
                logger.info(f"Using detection timestamp: {detection_time_iso}")
            except Exception as e:
                logger.error(f"Error converting detection timestamp: {e}")
        
        # Get all files in our database
        if detection_time_iso:
            # Only get files that haven't been deleted before the detection
            cursor.execute('''
            SELECT path, checksum, deleted, last_updated 
            FROM file_checksums
            WHERE (deleted = 0) OR (deleted = 1 AND last_updated > ?)
            ''', (detection_time_iso,))
        else:
            # Get all non-deleted files
            cursor.execute('''
            SELECT path, checksum, deleted, last_updated 
            FROM file_checksums
            WHERE deleted = 0
            ''')
        
        files_info = cursor.fetchall()
        conn.close()
        
        logger.info(f"Found {len(files_info)} files to check for recovery")
        
        recovered_count = 0
        skipped_count = 0
        
        # Process files with throttling
        for i, (rel_path, checksum, is_deleted, last_updated) in enumerate(files_info):
            # Skip files that were legitimately deleted before detection
            if is_deleted == 1:
                logger.debug(f"Skipping deleted file: {rel_path}")
                skipped_count += 1
                continue
            
            # Convert relative path to absolute paths
            monitored_path = os.path.join(config.MONITORING_DIR, rel_path)
            backup_path = os.path.join(config.BACKUP_DIR, rel_path)
            
            # Check if we need to restore this file
            restore_needed = False
            
            if not os.path.exists(monitored_path):
                # File is missing - restore it
                logger.info(f"File missing, restoring: {rel_path}")
                restore_needed = True
            elif checksum and compute_checksum(monitored_path) != checksum:
                # File exists but has been modified - restore it
                logger.info(f"File modified, restoring: {rel_path}")
                restore_needed = True
            else:
                logger.debug(f"File unchanged, skipping: {rel_path}")
            
            # Restore the file if needed and backup exists
            if restore_needed and os.path.exists(backup_path):
                try:
                    # Create directory if needed
                    os.makedirs(os.path.dirname(monitored_path), exist_ok=True)
                    
                    # Restore the file
                    shutil.copy2(backup_path, monitored_path)
                    recovered_count += 1
                    
                    # Update the stored checksum to match the backup
                    backup_checksum = compute_checksum(backup_path)
                    
                    conn = sqlite3.connect(CHECKSUM_DB)
                    cursor = conn.cursor()
                    cursor.execute('''
                    UPDATE file_checksums
                    SET checksum = ?, deleted = 0, last_updated = ?
                    WHERE path = ?
                    ''', (backup_checksum, datetime.now().isoformat(), rel_path))
                    conn.commit()
                    conn.close()
                    
                except Exception as e:
                    logger.error(f"Error restoring {rel_path}: {e}")
            
            # Throttle to avoid overwhelming I/O
            if i % 10 == 0:  # Every 10 files
                time.sleep(0.1)  # Add a small pause
        
        logger.info(f"Recovery complete: Restored {recovered_count} files, skipped {skipped_count} deleted files")
        return recovered_count
    except Exception as e:
        logger.error(f"Error during checksum recovery: {e}")
        return 0

def cleanup_old_checksums(days=7):
    """Remove old checksum entries for deleted files"""
    try:
        conn = sqlite3.connect(CHECKSUM_DB)
        cursor = conn.cursor()
        
        # Get cutoff date
        cutoff_date = (datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) -
                      datetime.timedelta(days=days)).isoformat()
        
        # Delete old entries for deleted files
        cursor.execute('''
        DELETE FROM file_checksums 
        WHERE deleted = 1 AND last_updated < ?
        ''', (cutoff_date,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        logger.info(f"Cleaned up {deleted_count} old checksum entries")
        return deleted_count
    except Exception as e:
        logger.error(f"Error cleaning up old checksums: {e}")
        return 0

def get_checksums_stats():
    """Get statistics about checksums database"""
    try:
        conn = sqlite3.connect(CHECKSUM_DB)
        cursor = conn.cursor()
        
        # Get total count
        cursor.execute('SELECT COUNT(*) FROM file_checksums')
        total_count = cursor.fetchone()[0]
        
        # Get active files count
        cursor.execute('SELECT COUNT(*) FROM file_checksums WHERE deleted = 0')
        active_count = cursor.fetchone()[0]
        
        # Get deleted files count
        cursor.execute('SELECT COUNT(*) FROM file_checksums WHERE deleted = 1')
        deleted_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total': total_count,
            'active': active_count,
            'deleted': deleted_count
        }
    except Exception as e:
        logger.error(f"Error getting checksum stats: {e}")
        return {'total': 0, 'active': 0, 'deleted': 0}

def test_checksum_functionality():
    """Test the checksum functionality"""
    test_dir = os.path.join(config.MONITORING_DIR, "checksum_test")
    os.makedirs(test_dir, exist_ok=True)
    
    # Create a test file
    test_file = os.path.join(test_dir, "test.txt")
    with open(test_file, "w") as f:
        f.write("Original content")
    
    # Store checksum
    store_file_checksum(test_file)
    
    # Check if modified (should be false)
    if not is_file_modified(test_file):
        print("✓ Checksum verification working correctly")
    else:
        print("× Checksum verification failed")
    
    # Modify file
    with open(test_file, "w") as f:
        f.write("Modified content")
    
    # Check if modified (should be true)
    if is_file_modified(test_file):
        print("✓ Change detection working correctly")
    else:
        print("× Change detection failed")
    
    # Test recovery
    backup_path = os.path.join(config.BACKUP_DIR, "checksum_test", "test.txt")
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    with open(backup_path, "w") as f:
        f.write("Original content")
    
    # Perform recovery
    count = checksum_recovery()
    if count > 0:
        with open(test_file, "r") as f:
            if f.read() == "Original content":
                print(f"✓ Recovery working correctly (restored {count} files)")
            else:
                print("× Recovery failed - content mismatch")
    else:
        print("× Recovery failed - no files restored")
    
    print("\nChecksum functionality tests completed")

if __name__ == "__main__":
    # Test the checksum functionality
    init_checksum_db()
    test_checksum_functionality()
