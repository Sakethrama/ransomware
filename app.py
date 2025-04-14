import os
import subprocess
import threading
import time
from flask import Flask, render_template, jsonify, request, send_from_directory
import config
import json
from datetime import datetime

app = Flask(__name__, static_folder='static')
simulation_running = False
simulation_logs = []
system_status = {
    'monitoring_active': False,
    'detection_events': 0,
    'recovery_events': 0,
    'isolated_processes': 0,
    'monitor_pid': None
}


@app.route('/')
def index():
    """Render the main dashboard page"""
    return render_template('index.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/api/status')
def get_status():
    """Get current system status"""
    # Check if monitoring is active by checking the specific process ID
    if 'monitor_pid' in system_status and system_status['monitor_pid']:
        try:
            # Check if process with saved PID exists
            if os.name == 'posix':  # Linux/Mac
                result = subprocess.run(["ps", "-p", str(system_status['monitor_pid'])], 
                                       capture_output=True, text=True)
                monitoring_active = result.returncode == 0
            else:  # Windows
                result = subprocess.run(["tasklist", "/FI", f"PID eq {system_status['monitor_pid']}"], 
                                       capture_output=True, text=True)
                monitoring_active = str(system_status['monitor_pid']) in result.stdout
            
            system_status['monitoring_active'] = monitoring_active
        except Exception as e:
            # If there's an error checking, don't change the status
            print(f"Error checking process status: {e}")
    
    # Count files in monitored and backup directories
    monitored_files = sum(len(files) for _, _, files in os.walk(config.MONITORING_DIR))
    backup_files = sum(len(files) for _, _, files in os.walk(config.BACKUP_DIR))
    
    return jsonify({
        'monitoring_active': system_status['monitoring_active'],
        'monitoring_dir': config.MONITORING_DIR,
        'backup_dir': config.BACKUP_DIR,
        'monitored_files': monitored_files,
        'backup_files': backup_files,
        'detection_events': system_status['detection_events'],
        'recovery_events': system_status['recovery_events'],
        'isolated_processes': system_status['isolated_processes'],
        'auto_recovery': config.AUTO_RECOVERY,
        'simulation_running': simulation_running,
        'telegram_enabled': config.ENABLE_TELEGRAM_ALERTS
    })

@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start the ransomware detection monitoring system"""
    global system_status
    
    if system_status['monitoring_active']:
        return jsonify({'success': False, 'message': 'Monitoring is already active'})
    
    try:
        # Start the monitoring system in a separate process
        process = subprocess.Popen(["python", "main.py"], 
                       stdout=subprocess.PIPE, 
                       stderr=subprocess.STDOUT)
        
        # Save the process ID
        system_status['monitor_pid'] = process.pid
        system_status['monitoring_active'] = True
        return jsonify({'success': True, 'message': 'Monitoring started successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to start monitoring: {str(e)}'})

@app.route('/api/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop the ransomware detection monitoring system"""
    global system_status
    
    if not system_status['monitoring_active']:
        return jsonify({'success': False, 'message': 'Monitoring is not active'})
    
    try:
        # Find and kill the monitoring process
        if 'monitor_pid' in system_status and system_status['monitor_pid']:
            if os.name == 'posix':  # Linux/Mac
                os.kill(system_status['monitor_pid'], 9)  # SIGKILL
            else:  # Windows
                subprocess.run(["taskkill", "/F", "/PID", str(system_status['monitor_pid'])])
        else:
            # Fallback to previous method
            if os.name == 'posix':  # Linux/Mac
                subprocess.run(["pkill", "-f", "python.*main.py"])
            else:  # Windows
                subprocess.run(["taskkill", "/F", "/FI", "IMAGENAME eq python.exe", "/FI", "WINDOWTITLE eq *main.py*"])
        
        # Clear process tracking
        system_status['monitor_pid'] = None
        system_status['monitoring_active'] = False
        return jsonify({'success': True, 'message': 'Monitoring stopped successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to stop monitoring: {str(e)}'})



@app.route('/api/run_simulation', methods=['POST'])
def run_simulation():
    """Run a simulation based on user parameters"""
    global simulation_running, simulation_logs, system_status
    
    if simulation_running:
        return jsonify({'success': False, 'message': 'Simulation already running'})
    
    simulation_type = request.json.get('type', 'normal')
    file_count = request.json.get('count', 10)
    
    try:
        # First mark as running
        simulation_running = True
        # Clear simulation logs completely
        simulation_logs = []
        # Add initial header just once
        if simulation_type == 'normal':
            simulation_logs.append({
                'time': time.time(), 
                'message': f"Simulating {file_count} normal file operations",
                'type': 'info'
            })
        else:
            simulation_logs.append({
                'time': time.time(), 
                'message': f"Simulating {file_count} ransomware file operations",
                'type': 'warning'
            })
        
        # Record simulation start time
        simulation_start_time = time.time()
        
        # Run simulation in a separate thread
        def run_sim():
            global simulation_running, simulation_logs
            try:
                # Run the simulation
                cmd = ["python", "simulate.py", "--mode", simulation_type, "--count", str(file_count)]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                
                # Track operations - ONLY show file operations in logs
                seen_operations = set()  # Use a set to track what we've already processed
                
                # Capture output
                for line in process.stdout:
                    stripped_line = line.strip()
                    print(f"Debug: Processing line: '{stripped_line}'")  # Debug output
                    
                    # Skip header/footer lines to avoid duplicates
                    if stripped_line.startswith(("Simulating", "Starting", "simulation completed")):
                        continue
                    
                    # Only process legitimate file operations, not headers or footers
                    if (stripped_line.startswith(("Created:", "Modified:", "Deleted:", "Encrypted:")) and 
                        stripped_line not in seen_operations):
                        seen_operations.add(stripped_line)
                        print(f"Debug: Adding to log: '{stripped_line}'")  # Debug output
                        simulation_logs.append({'time': time.time(), 'message': stripped_line})
                
                # Wait for completion
                process.wait()
                
                # Add completion message (only once)
                if simulation_type == 'normal':
                    simulation_logs.append({'time': time.time(), 'message': "Normal simulation completed", 'type': 'success'})
                else:
                    simulation_logs.append({'time': time.time(), 'message': "Ransomware simulation completed", 'type': 'warning'})
                    
                    # Update detection counters but don't show in logs
                    time.sleep(2)  # Give detection time to run
                    update_detection_counters(simulation_start_time)
            finally:
                simulation_running = False


        thread = threading.Thread(target=run_sim)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True, 
            'message': f'Started {simulation_type} simulation with {file_count} files'
        })
        
    except Exception as e:
        simulation_running = False
        return jsonify({'success': False, 'message': str(e)})

# Helper function to check for detection events but not add them to logs
def update_detection_counters(start_time):
    """Update detection counters without adding to logs"""
    global system_status
    
    alerts_file = os.path.join(config.LOG_DIR, "alerts.log")
    
    if os.path.exists(alerts_file):
        try:
            with open(alerts_file, "r", encoding="utf-8") as f:
                content = f.read()
                entries = content.split("\n\n")
                
                # Process alerts from newest to oldest
                recent_alerts = [e.strip() for e in entries if e.strip()]
                recent_alerts.reverse()  # Newest first
                
                # To avoid counting alerts multiple times
                detection_found = False
                recovery_found = False
                isolation_found = False
                
                # Find detection and recovery events
                for alert in recent_alerts:
                    # Try to extract timestamp from alert
                    try:
                        # Extract timestamp in format [YYYY-MM-DD HH:MM:SS]
                        timestamp_str = alert.split(']')[0].strip('[')
                        alert_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        alert_time = alert_time.timestamp()
                        
                        # Only process alerts that occurred after simulation started
                        if alert_time >= start_time - 1:  # Very tight timing window
                            if "POTENTIAL RANSOMWARE ACTIVITY DETECTED" in alert and not detection_found:
                                system_status['detection_events'] += 1
                                detection_found = True
                            
                            elif "RECOVERY COMPLETE" in alert and not recovery_found:
                                system_status['recovery_events'] += 1
                                recovery_found = True
                            
                            elif "Isolated process" in alert and not isolation_found:
                                system_status['isolated_processes'] += 1
                                isolation_found = True
                            
                            # Once we've found all three event types, we can stop
                            if detection_found and recovery_found and isolation_found:
                                break
                                
                    except Exception as e:
                        # Continue to next alert on error
                        continue
                    
        except Exception as e:
            print(f"Error reading alerts: {e}")

@app.route('/api/simulation/logs')
def get_simulation_logs():
    """Get latest simulation logs"""
    return jsonify(simulation_logs)

@app.route('/api/cleanup', methods=['POST'])
def cleanup():
    """Clean up encrypted files"""
    global simulation_running
    
    if simulation_running:
        return jsonify({'success': False, 'message': 'Cannot cleanup while simulation is running'})
    
    try:
        # Run cleanup
        result = subprocess.run(
            ["python", "simulate.py", "--mode", "cleanup"], 
            capture_output=True, 
            text=True
        )
        
        return jsonify({
            'success': True,
            'message': 'Cleanup completed',
            'output': result.stdout
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/recent_alerts')
def get_recent_alerts():
    """Get recent alert logs"""
    alerts = []
    log_path = os.path.join(config.LOG_DIR, 'alerts.log')
    
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
                entries = content.split("\n\n")
                alerts = [{'time': time.time(), 'message': entry.strip()} 
                         for entry in entries[-10:] if entry.strip()]  # Last 10 alerts
        except Exception as e:
            alerts = [{'time': time.time(), 'message': f"Error reading alert log: {str(e)}"}]
    
    return jsonify(alerts)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
