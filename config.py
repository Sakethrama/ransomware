import os

# Directory paths
MONITORING_DIR = "./test_directory"
BACKUP_DIR = "./backup_directory"
LOG_DIR = "./logs"

# Telegram settings
ENABLE_TELEGRAM_ALERTS = True
TELEGRAM_BOT_TOKEN = "7646743084:AAHSMP3gOLbqRZPtvYVz98SE6m4lVfYjetE"
TELEGRAM_CHAT_ID = -1002672215812

# Detection thresholds
FILE_OP_FREQUENCY_THRESHOLD = 10.0  
EXTENSION_CHANGE_THRESHOLD = 3      
ENTROPY_THRESHOLD = 0.8             

# Feature weights (percentage)
FREQUENCY_WEIGHT = 30.0
EXTENSION_WEIGHT = 50.0
ENTROPY_WEIGHT = 20.0

# Overall detection threshold
DETECTION_THRESHOLD = 0.6

# ML configuration
REQUIRE_ML_CONFIRMATION = True

# Recovery settings
AUTO_RECOVERY = True
RECOVERY_TIMEOUT = 10  # Seconds before initiating recovery

# Alert settings
ENABLE_CONSOLE_ALERTS = True
LOG_ALERTS = True