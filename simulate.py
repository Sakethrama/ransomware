import os
import random
import time
import string
import argparse
import sys

import config

def simulate_normal_usage(num_operations=20, delay=1):
    """Simulate normal file operations"""
    delay=1
    print(f"Simulating {num_operations} normal file operations with {delay}s delay between operations")
    
    for i in range(num_operations):
        operation = random.choice(["create", "modify", "delete"])
        
        if operation == "create":
            # Create a random text file
            filename = f"normal_file_{i}_{random.randint(1000, 9999)}.txt"
            filepath = os.path.join(config.MONITORING_DIR, filename)
            
            with open(filepath, "w") as f:
                # Write some random text
                text = ''.join(random.choice(string.ascii_letters + string.digits + " ") 
                              for _ in range(random.randint(100, 500)))
                f.write(text)
            print(f"Created: {filename}")
            
        elif operation == "modify":
            # Find an existing file to modify
            files = [f for f in os.listdir(config.MONITORING_DIR) 
                    if os.path.isfile(os.path.join(config.MONITORING_DIR, f))]
            
            if not files:
                continue
                
            filename = random.choice(files)
            filepath = os.path.join(config.MONITORING_DIR, filename)
            
            with open(filepath, "a") as f:
                # Append some text
                text = '\n' + ''.join(random.choice(string.ascii_letters + string.digits + " ") 
                                    for _ in range(random.randint(50, 200)))
                f.write(text)
            print(f"Modified: {filename}")
            
        elif operation == "delete":
            # Find an existing file to delete
            files = [f for f in os.listdir(config.MONITORING_DIR) 
                    if os.path.isfile(os.path.join(config.MONITORING_DIR, f)) 
                    and "important" not in f]  # Don't delete important files
            
            if not files:
                continue
                
            filename = random.choice(files)
            filepath = os.path.join(config.MONITORING_DIR, filename)
            
            os.remove(filepath)
            print(f"Deleted: {filename}")
            
        # Wait before next operation
        time.sleep(delay)
        
    print("Normal simulation completed")

def simulate_ransomware(num_files=10, delay=0.01):
    """Simulate ransomware encryption behavior"""
    # print(f"Simulating ransomware encryption on {num_files} files with {delay}s delay")
    
    encrypted_count = 0
    
    # Create some files if directory is empty
    files = [f for f in os.listdir(config.MONITORING_DIR) 
            if os.path.isfile(os.path.join(config.MONITORING_DIR, f))]
    
    # First pass: Find only non-encrypted files
    non_encrypted_files = []
    for f in files:
        if not f.endswith('.encrypted') and not f == "RANSOM_NOTE.txt":
            non_encrypted_files.append(f)
    print(len(non_encrypted_files))
    
    # If not enough non-encrypted files, create some test files
    if len(non_encrypted_files) < num_files:
        print("Creating some test files first...")
        files_needed = max(5, num_files - len(non_encrypted_files))
        for i in range(files_needed):
            filename = f"test_file_{i}.txt"
            filepath = os.path.join(config.MONITORING_DIR, filename)
            if not os.path.exists(filepath):  # Only create if doesn't exist
                with open(filepath, "w") as f:
                    f.write(f"This is test file {i} content.")
                non_encrypted_files.append(filename)
    
    # "Encrypt" files by renaming and modifying content
    files_to_encrypt = min(num_files, len(non_encrypted_files))
    if files_to_encrypt == 0:
        print("No files available to encrypt. Try removing .encrypted files first.")
        return 0
        
    for i in range(files_to_encrypt):
        if non_encrypted_files:
            filename = random.choice(non_encrypted_files)
            non_encrypted_files.remove(filename)  # Don't select the same file again
            
            filepath = os.path.join(config.MONITORING_DIR, filename)
            name, ext = os.path.splitext(filename)
            encrypted_name = f"{name}.encrypted"
            encrypted_path = os.path.join(config.MONITORING_DIR, encrypted_name)
            
            try:
                # Read the original content
                with open(filepath, "rb") as f:
                    content = f.read()
                    
                # "Encrypt" by XORing with a simple key
                key = 42
                encrypted_content = bytes([b ^ key for b in content])
                
                # Write the "encrypted" content
                with open(filepath, "wb") as f:
                    f.write(encrypted_content)
                    
                # Remove destination file if it already exists
                if os.path.exists(encrypted_path):
                    os.remove(encrypted_path)
                    
                # Rename the file
                os.rename(filepath, encrypted_path)
                
                print(f"Encrypted: {filename} -> {encrypted_name}")
                encrypted_count += 1
            except Exception as e:
                print(f"Error encrypting {filename}: {e}")
            
            # Small delay between operations
            time.sleep(delay)
    
    print(f"Ransomware simulation completed: {encrypted_count} files encrypted")
    
    # Create ransom note if not already present
    ransom_note_path = os.path.join(config.MONITORING_DIR, "RANSOM_NOTE.txt")
    if not os.path.exists(ransom_note_path):
        with open(ransom_note_path, "w") as f:
            f.write("""
            YOUR FILES HAVE BEEN ENCRYPTED!
            
            This is a simulated ransomware attack for educational purposes only.
            No actual harm has been done to your files.
            
            The detection system should have detected this activity and recovered your files.
            """)
    
    return encrypted_count

def cleanup_encrypted_files():
    """Remove encrypted files and restore original ones for fresh testing"""
    print("Cleaning up encrypted files...")
    
    count = 0
    for file in os.listdir(config.MONITORING_DIR):
        if file.endswith(".encrypted"):
            original_name = os.path.splitext(file)[0] + ".txt"
            encrypted_path = os.path.join(config.MONITORING_DIR, file)
            
            try:
                os.remove(encrypted_path)
                count += 1
            except Exception as e:
                print(f"Error removing {file}: {e}")
                
    if os.path.exists(os.path.join(config.MONITORING_DIR, "RANSOM_NOTE.txt")):
        try:
            os.remove(os.path.join(config.MONITORING_DIR, "RANSOM_NOTE.txt"))
            count += 1
        except:
            pass
            
    print(f"Cleanup completed: {count} files removed")
    return count

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate file operations for testing ransomware detection")
    parser.add_argument("--mode", choices=["normal", "ransomware", "cleanup"], required=True,
                      help="Simulation mode: normal usage, ransomware attack, or cleanup")
    parser.add_argument("--count", type=int, default=10,
                      help="Number of operations/files to process")
    parser.add_argument("--delay", type=float, default=0.5,
                      help="Delay between operations in seconds")
    
    args = parser.parse_args()
    
    # Make sure the monitoring directory exists
    if not os.path.exists(config.MONITORING_DIR):
        os.makedirs(config.MONITORING_DIR)
        print(f"Created monitoring directory: {config.MONITORING_DIR}")
    
    # Run the selected simulation
    if args.mode == "normal":
        simulate_normal_usage(args.count, args.delay)
    elif args.mode == "ransomware":
        simulate_ransomware(args.count, args.delay)
    else:
        cleanup_encrypted_files()