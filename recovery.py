import os
import shutil
import logging
from datetime import datetime

import config

logger = logging.getLogger('FileRecovery')

class FileRecovery:
    def __init__(self):
        """Initialize the file recovery system"""
        # Create backup directory if it doesn't exist
        self.recovery_in_progress = False
        if not os.path.exists(config.BACKUP_DIR):
            os.makedirs(config.BACKUP_DIR)
            
    def backup_file(self, source_path, relative_path):
        """Create a backup of a file"""
        try:
            # Create destination directory structure if it doesn't exist
            backup_path = os.path.join(config.BACKUP_DIR, relative_path)
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            # Copy file to backup location
            shutil.copy2(source_path, backup_path)
            logger.info(f"Backed up file: {relative_path}")
            return True
        except Exception as e:
            logger.error(f"Error backing up file {source_path}: {e}")
            return False
            
    def restore_file(self, relative_path):
        """Restore a file from backup"""
        try:
            # Source backup file
            source_path = os.path.join(config.BACKUP_DIR, relative_path)
            if not os.path.exists(source_path):
                logger.warning(f"No backup found for {relative_path}")
                return False
                
            # Destination file
            dest_path = os.path.join(config.MONITORING_DIR, relative_path)
            
            # Create destination directory if it doesn't exist
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            
            # Restore file
            shutil.copy2(source_path, dest_path)
            logger.info(f"Restored file: {relative_path}")
            return True
        except Exception as e:
            logger.error(f"Error restoring file {relative_path}: {e}")
            return False
            
    def restore_all_files(self):
        """Restore all files from backup after ransomware detection"""
        # Check if recovery is already in progress
        if self.recovery_in_progress:
            logger.info("Recovery already in progress. Skipping duplicate request.")
            return (0, 0)
            
        # Set flag and perform recovery
        self.recovery_in_progress = True
        logger.info("Starting full recovery process")
        
        try:
            # Track statistics
            restored_count = 0
            failed_count = 0
            
            # Walk through backup directory
            for root, _, files in os.walk(config.BACKUP_DIR):
                for file in files:
                    backup_path = os.path.join(root, file)
                    relative_path = os.path.relpath(backup_path, config.BACKUP_DIR)
                    
                    if self.restore_file(relative_path):
                        restored_count += 1
                    else:
                        failed_count += 1
                        
            # Log recovery results
            message = f"Recovery completed: {restored_count} files restored, {failed_count} failed"
            logger.info(message)
            
            # Send notification
            from notification import NotificationSystem
            notification = NotificationSystem()
            notification.send_alert(f"RECOVERY COMPLETE: {message}")
            
            return restored_count, failed_count
        finally:
            # Reset flag when done, even if an error occurs
            self.recovery_in_progress = False