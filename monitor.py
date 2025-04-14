import os
import time
import threading
from collections import deque, defaultdict
import math
import logging
from datetime import datetime

import config
from detection import RansomwareDetector

# Create a simple helper function to ensure directories exist
def ensure_dir_exists(directory):
    """Create directory if it doesn't exist"""
    try:
        os.makedirs(directory, exist_ok=True)
        print(f"Ensured directory exists: {directory}")
    except Exception as e:
        print(f"Error creating directory {directory}: {e}")
        raise

# Make sure all required directories exist BEFORE importing other modules
# that might try to use these directories
print("Creating necessary directories...")
for directory in [config.MONITORING_DIR, config.BACKUP_DIR, config.LOG_DIR]:
    ensure_dir_exists(directory)

# After directories exist, set up logging
print("Setting up logging...")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=os.path.join(config.LOG_DIR, 'monitor.log'),
    filemode='a'
)
logger = logging.getLogger('RansomwareMonitor')

# Now it's safe to import other modules
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from recovery import FileRecovery
from notification import NotificationSystem

class FileMonitor(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        # Initialize components
        self.detector = RansomwareDetector()
        self.recovery = FileRecovery()
        self.notification = NotificationSystem()
        
        # Recent file operations queue (timestamp, operation, file)
        self.recent_operations = deque(maxlen=200)
        
        # Track file extensions before modification
        self.file_extensions = {}
        
        # Track extension changes specifically
        self.extension_changes = 0
        self.extension_change_window = 30  # Reset count after N seconds
        self.last_extension_reset = time.time()
        
        # Track file creation and deletion for pattern recognition
        self.recent_creates = {}  # path -> timestamp
        self.recent_deletes = {}  # path -> timestamp
        self.pattern_window = 10  # Look for patterns within N seconds
        
        # Flag to indicate if in recovery mode
        self.recovery_mode = False
        
        # Scan initial directory to catalog files
        self._scan_initial_directory()
        
        # Create initial backups
        self._create_initial_backups()
        
    def _scan_initial_directory(self):
        """Scan the monitoring directory to catalog existing files"""
        for root, _, files in os.walk(config.MONITORING_DIR):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, config.MONITORING_DIR)
                _, ext = os.path.splitext(file)
                self.file_extensions[rel_path] = ext
                
    def _create_initial_backups(self):
        """Create initial backups of files in the monitoring directory"""
        for root, _, files in os.walk(config.MONITORING_DIR):
            for file in files:
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, config.MONITORING_DIR)
                self.recovery.backup_file(src_path, rel_path)
        
    def _calculate_file_entropy(self, filepath):
        """Calculate Shannon entropy of a file to detect encryption"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(4096)  # Read first 4KB for efficiency
                if not data:
                    return 0
                    
                # Count byte occurrences
                byte_counts = {}
                for byte in data:
                    if byte in byte_counts:
                        byte_counts[byte] += 1
                    else:
                        byte_counts[byte] = 1
                        
                # Calculate entropy
                entropy = 0
                for count in byte_counts.values():
                    probability = count / len(data)
                    entropy -= probability * math.log2(probability)
                    
                return entropy / 8.0  # Normalize to 0-1 range
        except Exception as e:
            logger.error(f"Error calculating entropy for {filepath}: {e}")
            return 0
    
    def set_recovery_mode(self, active):
        """Set whether we're in recovery mode to avoid false positives"""
        self.recovery_mode = active
        logger.info(f"Recovery mode set to: {active}")
    
    def _check_extension_patterns(self):
        """Check for ransomware-like extension change patterns"""
        # Clean up old entries
        now = time.time()
        
        # Reset extension changes counter after window expires
        if now - self.last_extension_reset > self.extension_change_window:
            prev_changes = self.extension_changes
            self.extension_changes = 0
            self.last_extension_reset = now
            logger.debug(f"Reset extension change counter. Was: {prev_changes}")
        
        # Clean old create/delete records
        self.recent_creates = {path: ts for path, ts in self.recent_creates.items() 
                             if now - ts <= self.pattern_window}
        self.recent_deletes = {path: ts for path, ts in self.recent_deletes.items() 
                             if now - ts <= self.pattern_window}
        
        # Look for specific ransomware patterns
        patterns_detected = 0
        
        # Pattern 1: original.txt deleted + original.txt.encrypted created
        for deleted_path in self.recent_deletes:
            base_name, ext = os.path.splitext(deleted_path)
            
            # Look for created files with same base name but different extension
            for created_path in self.recent_creates:
                if created_path.startswith(base_name) and created_path != deleted_path:
                    patterns_detected += 1
                    logger.warning(f"Ransomware pattern detected: {deleted_path} -> {created_path}")
        
        # Add to extension changes count
        if patterns_detected > 0:
            self.extension_changes += patterns_detected
            logger.warning(f"Detected {patterns_detected} extension change patterns. Total: {self.extension_changes}")
        
        return patterns_detected
    
    def _check_for_suspicious_activity(self):
        """Analyze recent file operations for suspicious patterns using improved weighted scoring"""
        if len(self.recent_operations) < 3:
            return False, "Not enough data"
            
        # Skip detection if in recovery mode
        if self.recovery_mode:
            logger.debug("Skipping threat detection during recovery")
            return False, "System in recovery mode"
            
        # Check for extension change patterns
        self._check_extension_patterns()
        
        # Calculate operation frequency (ops per second)
        now = time.time()
        recent_ops = [op for op in self.recent_operations 
                     if now - op[0] < 10]  # Last 10 seconds
        
        if len(recent_ops) < 3:
            return False, "Not enough recent operations"
            
        op_frequency = len(recent_ops) / 10.0
        
        # Use tracked extension changes count
        extension_changes = self.extension_changes
            
        # Get average entropy change for modified files
        entropy_changes = []
        for _, op, file_path in recent_ops:
            if op == "modified":
                full_path = os.path.join(config.MONITORING_DIR, file_path)
                if os.path.exists(full_path):
                    entropy = self._calculate_file_entropy(full_path)
                    entropy_changes.append(entropy)
        
        avg_entropy = sum(entropy_changes) / len(entropy_changes) if entropy_changes else 0
        
        # Collect features for ML detection
        features = [op_frequency, extension_changes, avg_entropy]
        
        # Debug log the features
        logger.debug(f"Detection features: ops={op_frequency:.1f}/s, ext_changes={extension_changes}, entropy={avg_entropy:.2f}")
        
        # Use weighted scoring system
        score = 0
        score += (op_frequency / config.FILE_OP_FREQUENCY_THRESHOLD) * (config.FREQUENCY_WEIGHT / 100.0)
        score += (extension_changes / max(1, config.EXTENSION_CHANGE_THRESHOLD)) * (config.EXTENSION_WEIGHT / 100.0)
        score += (avg_entropy / config.ENTROPY_THRESHOLD) * (config.ENTROPY_WEIGHT / 100.0)
        
        # Check if score exceeds threshold
        is_suspicious_threshold = score > config.DETECTION_THRESHOLD
        
        # Get ML prediction - pass all features for better accuracy
        is_suspicious_ml = self.detector.detect(features)
        
        # Update ML model with this data point (for future improvement)
        # If threshold detection and ML disagree, this is an interesting case to learn from
        is_suspicious = is_suspicious_threshold or is_suspicious_ml
        self.detector.update_model(features, is_suspicious)
        
        # Final decision based on configuration
        if config.REQUIRE_ML_CONFIRMATION:
            # Both threshold and ML must agree for a positive detection
            is_suspicious = is_suspicious_threshold and is_suspicious_ml
        else:
            # Either one can trigger a detection
            is_suspicious = is_suspicious_threshold or is_suspicious_ml
        
        reason = f"File operations: {op_frequency}/s, Ext changes: {extension_changes}, " \
                f"Entropy: {avg_entropy:.2f}, Score: {score:.2f}, ML detection: {'Positive' if is_suspicious_ml else 'Negative'}"
                
        return is_suspicious, reason

    def on_created(self, event):
        if event.is_directory:
            return
            
        file_path = os.path.relpath(event.src_path, config.MONITORING_DIR)
        logger.info(f"File created: {file_path}")
        
        # Add to recent operations
        self.recent_operations.append((time.time(), "created", file_path))
        
        # Update extension tracking
        _, ext = os.path.splitext(file_path)
        self.file_extensions[file_path] = ext
        
        # Add to recent creates for pattern detection
        self.recent_creates[file_path] = time.time()
        
        # Check for encryption pattern: if filename contains .encrypted
        if '.encrypted' in file_path.lower():
            # Look for original file that might have been encrypted
            possible_original = file_path.replace('.encrypted', '')
            if possible_original in self.recent_deletes:
                self.extension_changes += 1
                logger.warning(f"Encryption pattern detected: {possible_original} -> {file_path}")
        
        # Create backup of new file
        self.recovery.backup_file(event.src_path, file_path)
        
        # Check for suspicious activity
        self._handle_potential_threat()

    def on_modified(self, event):
        if event.is_directory:
            return
            
        file_path = os.path.relpath(event.src_path, config.MONITORING_DIR)
        logger.info(f"File modified: {file_path}")
        
        # Add to recent operations
        self.recent_operations.append((time.time(), "modified", file_path))
        
        # Check for extension change
        _, ext = os.path.splitext(file_path)
        if file_path in self.file_extensions and ext != self.file_extensions[file_path]:
            logger.warning(f"Extension changed for {file_path}: {self.file_extensions[file_path]} -> {ext}")
            self.extension_changes += 1
            
        # Update extension tracking
        self.file_extensions[file_path] = ext
        
        # Check for suspicious activity
        self._handle_potential_threat()

    def on_deleted(self, event):
        if event.is_directory:
            return
            
        file_path = os.path.relpath(event.src_path, config.MONITORING_DIR)
        logger.info(f"File deleted: {file_path}")
        
        # Add to recent operations
        self.recent_operations.append((time.time(), "deleted", file_path))
        
        # Add to recent deletes for pattern detection
        self.recent_deletes[file_path] = time.time()
        
        # Check for suspicious activity
        self._handle_potential_threat()
    
    def on_moved(self, event):
        """Handle file rename/move events which are critical for ransomware detection"""
        if event.is_directory:
            return
            
        src_path = os.path.relpath(event.src_path, config.MONITORING_DIR)
        dest_path = os.path.relpath(event.dest_path, config.MONITORING_DIR)
        
        logger.info(f"File renamed: {src_path} -> {dest_path}")
        
        # Add to recent operations
        self.recent_operations.append((time.time(), "renamed", f"{src_path}|{dest_path}"))
        
        # Check for extension change during rename (critical ransomware indicator)
        _, src_ext = os.path.splitext(src_path)
        _, dest_ext = os.path.splitext(dest_path)
        
        if src_ext != dest_ext:
            logger.warning(f"Extension changed during rename: {src_ext} -> {dest_ext}")
            self.extension_changes += 1
            
            # Check for ransomware patterns like adding .encrypted extension
            if ".encrypted" in dest_ext.lower() or ".locked" in dest_ext.lower() or ".crypt" in dest_ext.lower():
                logger.warning(f"Suspicious extension change detected: {src_path} -> {dest_path}")
                self.extension_changes += 1  # Count it twice as it's highly suspicious
        
        # Update extension tracking
        if src_path in self.file_extensions:
            del self.file_extensions[src_path]
        self.file_extensions[dest_path] = dest_ext
        
        # Check for suspicious activity
        self._handle_potential_threat()

    def _handle_potential_threat(self):
        """Check for ransomware activity and respond if detected"""
        is_suspicious, reason = self._check_for_suspicious_activity()
        
        if is_suspicious:
            alert_message = f"POTENTIAL RANSOMWARE ACTIVITY DETECTED!\nReason: {reason}"
            logger.warning(alert_message)
            
            # Send alert notification
            self.notification.send_alert(alert_message)
            
            # Trigger recovery if auto-recovery is enabled
            if config.AUTO_RECOVERY and not self.recovery_mode:
                # Set recovery mode flag to prevent detection during recovery
                self.set_recovery_mode(True)
                
                def recover_and_reset():
                    try:
                        # Send notification that recovery is starting
                        self.notification.send_alert(f"RECOVERY PROCESS INITIATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                        
                        # Perform recovery
                        self.recovery.restore_all_files()
                        
                        # Send notification that recovery is complete
                        self.notification.send_alert(f"RECOVERY COMPLETE: All files restored to their original state.")
                    except Exception as e:
                        self.notification.send_alert(f"RECOVERY FAILED: {str(e)}")
                        logger.error(f"Recovery failed: {e}")
                    finally:
                        # Always reset recovery mode
                        self.set_recovery_mode(False)
                
                logger.info(f"Auto-recovery scheduled in {config.RECOVERY_TIMEOUT} seconds")
                threading.Timer(config.RECOVERY_TIMEOUT, recover_and_reset).start()
                
                # Reset extension changes after scheduling recovery
                self.extension_changes = 0
                self.last_extension_reset = time.time()

# Instance accessible by other modules
file_monitor = None

def start_monitoring():
    """Start the file system monitoring"""
    global file_monitor
    file_monitor = FileMonitor()
    
    observer = Observer()
    observer.schedule(file_monitor, config.MONITORING_DIR, recursive=True)
    observer.start()
    
    try:
        logger.info(f"Starting monitoring of {config.MONITORING_DIR}")
        print(f"Monitoring directory: {config.MONITORING_DIR}")
        print(f"Press Ctrl+C to stop monitoring")
        
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()
    logger.info("Monitoring stopped")

if __name__ == "__main__":
    start_monitoring()