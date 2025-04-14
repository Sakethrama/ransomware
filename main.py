import os
import argparse
import logging
import threading
import time

import config

def setup_environment():
    """Set up the necessary directories and logging"""
    # Create required directories
    for directory in [config.MONITORING_DIR, config.BACKUP_DIR, config.LOG_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")
            
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        filename=os.path.join(config.LOG_DIR, 'ransomware_detection.log'),
        filemode='a'
    )
    
    logger = logging.getLogger('MainApp')
    logger.info("Starting Ransomware Detection System")

def test_telegram_alert():
    """Send a test Telegram alert"""
    from notification import NotificationSystem
    notification = NotificationSystem()
    notification.send_alert("Test alert from Ransomware Detection System")
    print("Test Telegram alert sent, check your Telegram for the message")

def main():
    """Main entry point for the application"""
    parser = argparse.ArgumentParser(
        description="Self-Healing Ransomware Detection System"
    )
    parser.add_argument("--simulate", choices=["normal", "ransomware", "none"], default="none",
                      help="Run a simulation along with the monitoring system")
    parser.add_argument("--delay", type=float, default=5,
                      help="Delay in seconds before running simulation")
    parser.add_argument("--count", type=int, default=10,
                      help="Number of operations/files for simulation")
    parser.add_argument("--cleanup", action="store_true", 
                      help="Clean up encrypted files before running")
    parser.add_argument("--test-telegram", action="store_true",
                      help="Send a test message to Telegram and exit")
    
    args = parser.parse_args()
    
    # Set up the environment
    from monitor import ensure_dir_exists
    
    # If test-telegram flag is provided, just test and exit
    if args.test_telegram:
        test_telegram_alert()
        return
        
    # If cleanup requested, do it first
    if args.cleanup:
        from ns_project.simulate import cleanup_encrypted_files
        cleanup_encrypted_files()
    
    # Start the monitoring in a separate thread
    from monitor import start_monitoring
    
    monitor_thread = threading.Thread(target=start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # If simulation was requested, run it after a delay
    if args.simulate != "none":
        print(f"Monitoring started. Will run {args.simulate} simulation in {args.delay} seconds...")
        time.sleep(args.delay)
        
        if args.simulate == "normal":
            from ns_project.simulate import simulate_normal_usage
            simulate_normal_usage(args.count, 0.5)
        else:
            from ns_project.simulate import simulate_ransomware
            simulate_ransomware(args.count, 0.1)
    else:
        print("Monitoring started. Press Ctrl+C to exit.")
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")

if __name__ == "__main__":
    main()