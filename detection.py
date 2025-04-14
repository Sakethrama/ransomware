import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import logging
import re
from collections import defaultdict, Counter

import config

logger = logging.getLogger('RansomwareDetector')

class RansomwareDetector:
    def __init__(self, model_path="./model.joblib", dataset_path="data/ransomware_detection_dataset.csv"):
        """Initialize the ransomware detector with a ML model"""
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.dataset_path = dataset_path
        
        # Track file operations for better detection
        self.file_operations = []
        self.file_extensions = {}
        self.extension_changes = 0
        self.operation_timestamps = []
        self.reset_time = None
        
        # Try to load existing model, or create a new one
        if os.path.exists(model_path):
            try:
                saved_data = joblib.load(model_path)
                if isinstance(saved_data, dict):
                    self.model = saved_data.get('model')
                    self.scaler = saved_data.get('scaler')
                    logger.info("Loaded existing detection model with scaler")
                else:
                    self.model = saved_data
                    self.scaler = StandardScaler()
                    logger.info("Loaded existing detection model (no scaler found)")
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                self._create_new_model()
        else:
            self._create_new_model()
            
    def _create_new_model(self):
        """Create and train a new anomaly detection model using the dataset"""
        logger.info("Creating new detection model")
        
        try:
            # Try to load dataset from file
            if os.path.exists(self.dataset_path):
                df = pd.read_csv(self.dataset_path)
                logger.info(f"Loaded dataset from {self.dataset_path} with {len(df)} samples")
                
                # Select features
                features = ['file_ops_frequency', 'extension_changes', 'entropy']
                if 'registry_ops' in df.columns:
                    features.extend(['registry_ops', 'network_connections', 'api_calls', 
                                    'dll_calls', 'files_accessed', 'files_modified'])
                
                X = df[features].values
                y = df['is_ransomware'].values
                
                # Initialize the scaler
                self.scaler = StandardScaler()
                X_scaled = self.scaler.fit_transform(X)
                
                # Calculate contamination (proportion of anomalies)
                contamination = sum(y) / len(y)
                logger.info(f"Using contamination rate of {contamination:.4f}")
                
                # Create and train model
                self.model = IsolationForest(
                    n_estimators=100,
                    contamination=contamination,
                    random_state=42
                )
                
                # Train the model on all data for better decision boundary
                self.model.fit(X_scaled)
                
                logger.info("Model trained on actual dataset")
            else:
                # Fall back to synthetic data if no dataset found
                logger.warning(f"Dataset not found at {self.dataset_path}, using synthetic data")
                self._train_on_synthetic_data()
                
        except Exception as e:
            logger.error(f"Error training model with dataset: {e}")
            logger.warning("Falling back to synthetic data")
            self._train_on_synthetic_data()
        
        # Save the model and scaler
        try:
            joblib.dump({'model': self.model, 'scaler': self.scaler}, self.model_path)
            logger.info("Model created and saved")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def _train_on_synthetic_data(self):
        """Train on synthetic data as fallback"""
        logger.info("Training on synthetic data")
        
        # Create an Isolation Forest model for anomaly detection
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        
        # Generate improved training data with better separation between normal and abnormal
        # [file_op_frequency, extension_changes, avg_entropy]
        X_train = np.array([
            # Normal file operations (more realistic patterns)
            [1.2, 0, 0.3],   # Low activity
            [0.8, 0, 0.2],   # Low activity
            [2.1, 0, 0.4],   # Low activity
            [5.0, 0, 0.5],   # Medium activity, no extension changes
            [8.0, 1, 0.6],   # Higher activity, one extension change
            [10.0, 0, 0.7],  # High activity, no extension changes
            [3.5, 1, 0.75],  # Medium activity, one extension change
            [7.0, 2, 0.65],  # Medium-high activity, two extension changes
            [4.0, 0, 0.55],  # Medium activity, no extension changes
            [9.0, 1, 0.7],   # High activity, one extension change
            
            # Ransomware-like operations (more distinct patterns)
            [12.0, 5, 0.85],  # High freq, many ext changes, high entropy
            [15.0, 8, 0.95],  # Very high freq, many ext changes, very high entropy 
            [20.0, 10, 0.9],  # Extreme freq, many ext changes, very high entropy
            [18.0, 7, 0.88],  # Very high freq, many ext changes, high entropy
            [14.0, 6, 0.87],  # High freq, many ext changes, high entropy
        ])
        
        # Initialize the scaler
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Train the model
        self.model.fit(X_train_scaled)
        
        logger.info("Model trained on synthetic data")
    
    def track_file_operation(self, event_type, file_path, new_path=None):
        """Track file operations to detect extension changes and operation frequency"""
        import time
        current_time = time.time()
        
        # Clean old timestamps (older than 10 seconds)
        self.operation_timestamps = [ts for ts in self.operation_timestamps if current_time - ts <= 10]
        self.operation_timestamps.append(current_time)
        
        # Reset extension change counter after 30 seconds of inactivity
        if self.reset_time is None or current_time - self.reset_time > 30:
            self.file_extensions = {}
            self.extension_changes = 0
            self.reset_time = current_time
        
        # Extract file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # Track the file's extension
        if event_type in ['created', 'modified']:
            self.file_extensions[file_path] = ext
        
        # Check for extension changes (renamed files)
        if event_type == 'renamed' and new_path:
            old_ext = self.file_extensions.get(file_path, '')
            new_ext = os.path.splitext(new_path)[1].lower()
            
            # Update extension for the new path
            self.file_extensions[new_path] = new_ext
            
            # Count extension changes
            if old_ext != new_ext:
                self.extension_changes += 1
                logger.debug(f"Extension change detected: {old_ext} -> {new_ext}")
        
        # Look for encryption patterns in file operations
        if event_type == 'created' and '.encrypted' in file_path.lower():
            original_path = file_path.replace('.encrypted', '')
            if original_path in self.file_extensions:
                self.extension_changes += 1
                logger.debug(f"Potential encryption detected: {original_path} -> {file_path}")
                
        # Handle deletion after encryption
        if event_type == 'deleted' and file_path in self.file_extensions:
            if '.encrypted' in file_path.lower():
                # This might indicate the end of an encryption operation
                logger.debug(f"Deleted encrypted file: {file_path}")
    
    def get_current_features(self, entropy_value=0.0):
        """Get current feature values based on tracked operations"""
        import time
        current_time = time.time()
        
        # Calculate operations per second over the last 10 seconds
        recent_timestamps = [ts for ts in self.operation_timestamps if current_time - ts <= 10]
        if len(recent_timestamps) > 1:
            timespan = max(current_time - min(recent_timestamps), 1)  # Avoid division by zero
            ops_per_second = len(recent_timestamps) / timespan
        else:
            ops_per_second = 0
            
        # Get current extension change count
        ext_changes = self.extension_changes
        
        return [ops_per_second, ext_changes, entropy_value]
    
    def detect(self, features):
        """Detect if the given features represent ransomware activity"""
        if not self.model:
            logger.error("No detection model available")
            return False
            
        # Convert features to numpy array
        X = np.array([features])
        
        # Handle feature dimension mismatch
        if self.scaler and hasattr(self.scaler, 'n_features_in_'):
            expected_features = self.scaler.n_features_in_
            
            # If we have fewer features than expected, pad with zeros
            if X.shape[1] < expected_features:
                padding = np.zeros((X.shape[0], expected_features - X.shape[1]))
                X = np.hstack([X, padding])
                logger.debug(f"Padded features from {len(features)} to {expected_features}")
            # If we have more features than expected, truncate
            elif X.shape[1] > expected_features:
                X = X[:, :expected_features]
                logger.debug(f"Truncated features from {len(features)} to {expected_features}")
        
        # Scale the features if scaler is available
        if self.scaler:
            try:
                X = self.scaler.transform(X)
            except ValueError as e:
                logger.error(f"Feature scaling error: {e}")
                # Fall back to unscaled detection
                pass
        
        # Get decision score (negative values indicate anomalies)
        try:
            decision_score = self.model.decision_function(X)[0]
            logger.debug(f"Decision score: {decision_score:.4f}")
        except Exception as e:
            logger.error(f"Error getting decision score: {e}")
            return False
        
        # Predict using the model (-1 for anomalies, 1 for normal data)
        result = self.model.predict(X)[0]
        
        # Get the individual features for rule-based detection (using only the first 3)
        file_ops = features[0] if len(features) > 0 else 0
        ext_changes = features[1] if len(features) > 1 else 0
        entropy = features[2] if len(features) > 2 else 0
        
        # Enhanced rule-based detection logic
        rule_based_detection = (
            (ext_changes >= 5) or  # Many extension changes is highly suspicious
            (file_ops >= 12.0 and ext_changes >= 3) or  # High ops + some ext changes
            (file_ops >= 12.0 and entropy >= 0.8) or  # High ops + high entropy
            (ext_changes >= 3 and entropy >= 0.85)  # Some ext changes + very high entropy
        )
        
        # Final decision combines ML and rule-based approaches
        is_ransomware = (result == -1) or rule_based_detection
        
        if is_ransomware:
            confidence = self.get_confidence(features[:3]) if hasattr(self, 'get_confidence') else 95.0
            logger.info(f"Ransomware detected! ML={result == -1}, Rule-based={rule_based_detection}, Confidence={confidence:.2f}%")
            logger.info(f"Features: ops={file_ops:.1f}/s, ext_changes={ext_changes}, entropy={entropy:.2f}")
        
        return is_ransomware
        
    def update_model(self, features, is_ransomware):
        """Update the model with new data for future retraining"""
        if not self.model:
            return
            
        # Log the new data point
        logger.info(f"Model update data: features={features}, is_ransomware={is_ransomware}")
        
        # Update extension change tracking if this is ransomware
        if is_ransomware and len(features) >= 2 and features[1] > 0:
            self.extension_changes = max(self.extension_changes, int(features[1]))
        
        # In a real implementation:
        # 1. Collect this data in a database or append to CSV
        # 2. Periodically retrain the model with the accumulated data
        try:
            # Append to the dataset if it exists
            if os.path.exists(self.dataset_path):
                df = pd.read_csv(self.dataset_path)
                
                # Create new row - handle variable length features
                new_row = {
                    'file_ops_frequency': features[0],
                    'extension_changes': features[1],
                    'entropy': features[2],
                    'is_ransomware': 1 if is_ransomware else 0,
                    'label': 'Ransomware' if is_ransomware else 'Benign'
                }
                
                # Add additional features if available
                if len(features) > 3 and len(df.columns) > len(new_row):
                    feature_names = ['registry_ops', 'network_connections', 
                                    'api_calls', 'dll_calls', 'files_accessed', 'files_modified']
                    
                    for i, name in enumerate(feature_names):
                        if i + 3 < len(features) and name in df.columns:
                            new_row[name] = features[i + 3]
                
                # Append to dataframe and save
                df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
                df.to_csv(self.dataset_path, index=False)
                logger.info(f"Added new data point to dataset: {new_row}")
            
        except Exception as e:
            logger.error(f"Error updating dataset: {e}")
    
    def get_confidence(self, features):
        """Get confidence score for ransomware detection (0-100%)"""
        if not self.model or not self.scaler:
            return 0.0
            
        # Ensure features is the right format and length
        if len(features) > 3:
            main_features = features[:3]
        else:
            main_features = features
            
        # Scale the features
        X = np.array([main_features])
        X_scaled = self.scaler.transform(X)
        
        # Get decision function value (more negative = more anomalous)
        decision = self.model.decision_function(X_scaled)[0]
        
        # Extension changes are a strong indicator, increase confidence if present
        _, ext_changes, entropy = main_features
        ext_bonus = min(30, ext_changes * 10)  # Up to 30% bonus for extension changes
        
        # Convert to confidence percentage (0-100%)
        # For anomalies (decision < 0), confidence increases as decision gets more negative
        # For normal data (decision >= 0), confidence is low
        if decision < 0:
            # Map from decision to confidence:
            # decision = -0.2 → low confidence (about 60%)
            # decision = -0.8 → high confidence (about 90%)
            confidence = min(100, 50 + abs(decision) * 50 + ext_bonus)
        else:
            # For positive decisions (normal data), confidence is inversely related
            # but still consider extension changes as a factor
            confidence = max(0, min(100, 50 - decision * 25 + ext_bonus))
            
        return confidence
        
    def process_file_event(self, event_type, file_path, new_path=None):
        """Process a file event and check for ransomware behavior"""
        # Track this file operation
        self.track_file_operation(event_type, file_path, new_path)
        
        # Calculate entropy if possible
        entropy = 0.0
        if event_type in ['created', 'modified'] and os.path.exists(file_path):
            try:
                entropy = self._calculate_file_entropy(file_path)
            except Exception as e:
                logger.error(f"Error calculating entropy for {file_path}: {e}")
        
        # Get current features
        features = self.get_current_features(entropy)
        
        # Detect ransomware
        return self.detect(features)
        
    def _calculate_file_entropy(self, file_path, sample_size=4096):
        """Calculate Shannon entropy of a file"""
        try:
            # Read file in binary mode, sampling first N bytes
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
                
            if not data:
                return 0.0
                
            # Count byte occurrences
            byte_counts = Counter(data)
            file_size = len(data)
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / file_size
                entropy -= probability * np.log2(probability)
                
            # Normalize to 0-1 range
            max_entropy = np.log2(256)  # Maximum entropy for byte values
            normalized_entropy = entropy / max_entropy
            
            return normalized_entropy
            
        except Exception as e:
            logger.error(f"Error calculating entropy for {file_path}: {e}")
            return 0.0
