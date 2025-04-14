import logging
import os
from datetime import datetime, timedelta
import time
import traceback  # Added for better error tracing
import requests  # Added for direct API access
from telegram import Bot
import config

# Configure the logger
LOG_DIR = getattr(config, 'LOG_DIR', 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, 'notification.log'), encoding='utf-8')
    ]
)
logger = logging.getLogger('NotificationSystem')


class NotificationSystem:
    def __init__(self):
        """Initialize the notification system"""
        self.bot = None
        if getattr(config, 'ENABLE_TELEGRAM_ALERTS', False):
            try:
                self.bot = Bot(token=config.TELEGRAM_BOT_TOKEN)
                logger.info("✅ Telegram bot initialized successfully.")
                
                # Test the bot API directly - this will help identify problems
                self._test_bot_api()
            except Exception as e:
                logger.error(f"❌ Failed to initialize Telegram bot: {str(e)}")
                logger.debug(traceback.format_exc())  # Log the full stack trace
                self.bot = None

        self.last_alert_time = {}
        self.alert_cooldown = timedelta(seconds=60)  # 1-minute cooldown
        
        # Track seen message fingerprints to avoid duplicates
        self.message_fingerprints = set()
        # Clear fingerprints periodically (24 hours)
        self.last_cleanup_time = datetime.now()
        self.fingerprint_cleanup_interval = timedelta(hours=24)

    def _test_bot_api(self):
        """Test the Telegram Bot API directly"""
        if not self.bot:
            return
            
        # First, get bot info to confirm token is valid
        try:
            bot_info = self.bot.get_me()
            logger.info(f"✅ Bot API connection successful. Connected as: {bot_info.first_name} (@{bot_info.username})")
            
            # Next, try to send a test message to validate chat ID permission
            response = requests.get(
                f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/getChat",
                params={'chat_id': config.TELEGRAM_CHAT_ID}
            )
            
            if response.status_code == 200:
                chat_info = response.json().get('result', {})
                chat_type = chat_info.get('type', 'unknown')
                chat_title = chat_info.get('title', 'Unknown')
                logger.info(f"✅ Chat ID is valid: {chat_title} (Type: {chat_type})")
            else:
                error = response.json().get('description', 'Unknown error')
                logger.error(f"❌ Chat ID validation failed: {error}")
                logger.error(f"Response: {response.text}")
        except Exception as e:
            logger.error(f"❌ Bot API test failed: {str(e)}")
            logger.debug(traceback.format_exc())

    def _get_message_type(self, message):
        """Extract message type more intelligently"""
        # Check for specific message patterns
        if "POTENTIAL RANSOMWARE ACTIVITY DETECTED" in message:
            return "RANSOMWARE_DETECTION"
        elif "RECOVERY COMPLETE" in message:
            return "RECOVERY_COMPLETE"
        elif "Isolated process" in message:
            return "PROCESS_ISOLATION"
        elif ":" in message:
            # Fallback to original method for other messages
            return message.split(":", 1)[0]
        else:
            return message[:20]  # Use first 20 chars as type

    def _generate_message_fingerprint(self, message):
        """Generate a unique fingerprint for a message to avoid duplicates"""
        # Use first 50 chars + last 20 chars as fingerprint
        if len(message) > 70:
            return message[:50] + message[-20:]
        else:
            return message

    def send_alert(self, message):
        """Send an alert about a potential ransomware attack"""
        # Check if we should clean up old fingerprints
        current_time = datetime.now()
        if current_time - self.last_cleanup_time > self.fingerprint_cleanup_interval:
            self.message_fingerprints.clear()
            self.last_cleanup_time = current_time
            logger.debug("Cleared message fingerprint cache")
        
        # Get message type and fingerprint
        message_type = self._get_message_type(message)
        message_fingerprint = self._generate_message_fingerprint(message)
        
        # Check for duplicate messages by fingerprint
        if message_fingerprint in self.message_fingerprints:
            logger.debug(f"⏱️ Duplicate message suppressed: {message_type}")
            return False
        
        # Check if we've sent a similar type of message recently
        if message_type in self.last_alert_time and current_time - self.last_alert_time[message_type] < self.alert_cooldown:
            logger.debug(f"⏱️ Alert suppressed due to cooldown: {message_type}")
            return False
            
        # Add fingerprint to seen set
        self.message_fingerprints.add(message_fingerprint)
        
        # Update last alert time for this message type
        self.last_alert_time[message_type] = current_time
        
        # Format the alert message
        timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] ALERT: {message}"
        
        # Console output
        if getattr(config, 'ENABLE_CONSOLE_ALERTS', True):
            print("\n" + "!" * 80)
            print(formatted_message)
            print("!" * 80 + "\n")

        logger.warning(formatted_message)

        if getattr(config, 'LOG_ALERTS', True):
            alerts_file = os.path.join(LOG_DIR, "alerts.log")
            try:
                with open(alerts_file, "a", encoding="utf-8") as f:
                    f.write(formatted_message + "\n\n")
            except Exception as e:
                logger.error(f"❌ Failed to write to alert log file: {str(e)}")

        if getattr(config, 'ENABLE_TELEGRAM_ALERTS', False):
            try:
                # First try using the Bot API
                if self.bot:
                    # Add delay to avoid rate limiting
                    time.sleep(0.5)
                    
                    logger.debug(f"Sending Telegram alert via Bot API: {message_type}")
                    self.bot.send_message(
                        chat_id=config.TELEGRAM_CHAT_ID,
                        text=formatted_message
                    )
                    logger.info(f"📨 Telegram alert sent via Bot API: {message_type}")
                else:
                    # Fallback to direct API call
                    logger.debug(f"Sending Telegram alert via direct API call: {message_type}")
                    self._send_telegram_direct(formatted_message)
                    
            except Exception as e:
                logger.error(f"❌ Failed to send Telegram alert: {str(e)}")
                # Try direct API as fallback
                try:
                    logger.debug("Trying direct API call as fallback")
                    self._send_telegram_direct(formatted_message)
                except Exception as e2:
                    logger.error(f"❌ Direct API fallback also failed: {str(e2)}")
                    logger.debug(traceback.format_exc())

        return True
        
    def _send_telegram_direct(self, message):
        """Send a message directly using the Telegram API"""
        url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": config.TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        
        response = requests.post(url, json=data)
        response.raise_for_status()
        
        result = response.json()
        if not result.get('ok'):
            raise Exception(f"API error: {result.get('description', 'Unknown error')}")
            
        logger.info(f"📨 Telegram alert sent via direct API call")


def test_telegram_notification():
    """Test different alert types and notification methods"""
    notifier = NotificationSystem()
    print("🔧 Testing Telegram notification system...\n")

    # First, test with a simple message
    print("Sending test message...")
    result = notifier.send_alert("TEST ALERT: This is a test of the Telegram notification system.")
    if result:
        print("✅ Test message sent successfully via primary method")
    else:
        print("❌ Failed to send test message")
        
    # Wait a moment before trying a direct API call
    time.sleep(2)
    
    # Try a direct API call
    print("\nTesting direct API call...")
    try:
        notifier._send_telegram_direct("TEST ALERT: Direct API test message")
        print("✅ Direct API call successful")
    except Exception as e:
        print(f"❌ Direct API call failed: {e}")

    return True


if __name__ == "__main__":
    result = test_telegram_notification()
    if result:
        print("\n✅ Telegram notification test completed. Check your logs and Telegram for messages.")
    else:
        print("\n❌ Telegram notification test failed.")
