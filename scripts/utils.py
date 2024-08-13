# utils.py
import hashlib
import json
import os
import psutil
import subprocess
import time

# Helper Functions
def md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Step 2: Firmware Integrity Verification
def create_firmware_baseline(firmware_path):
    firmware_hash = md5(firmware_path)
    with open(r'C:\Users\ASUS\Desktop\rootkit_detection\baselines\firmware_baseline.json', 'w') as f:
        json.dump({"firmware": firmware_hash}, f)

def load_firmware_baseline():
    with open(r'C:\Users\ASUS\Desktop\rootkit_detection\baselines\firmware_baseline.json', 'r') as f:
        return json.load(f)

def verify_firmware_integrity(firmware_path):
    baseline = load_firmware_baseline()
    current_hash = md5(firmware_path)
    if current_hash != baseline["firmware"]:
        print("Firmware integrity violation detected.")
    else:
        print("Firmware integrity intact.")

# Step 3: Behavioral Analysis
def monitor_firmware_behavior(timeout=60):
    suspicious_behaviors = []
    start_time = time.time()
    while time.time() - start_time < timeout:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                pinfo = proc.info
                if is_firmware_suspicious(pinfo):
                    suspicious_behaviors.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        time.sleep(5)
    return suspicious_behaviors  # Return if there are any suspicious behaviors detected

def is_firmware_suspicious(pinfo):
    suspicious_processes = ['malicious_process_name', 'another_malicious_process']
    eicar_test_string = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    if pinfo['name'] in suspicious_processes:
        return True

    if 'cmdline' in pinfo and pinfo['cmdline'] is not None and isinstance(pinfo['cmdline'], list):
        if any(eicar_test_string in arg for arg in pinfo['cmdline']):
            return True

    return False

# Step 4: Integrity Checking
def create_baseline(directories):
    baseline = {}
    for directory in directories:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = md5(file_path)
                baseline[file_path] = file_hash
    with open(r'C:\Users\ASUS\Desktop\rootkit_detection\baselines\system_baseline.json', 'w') as f:
        json.dump(baseline, f)

def load_baseline():
    with open(r'C:\Users\ASUS\Desktop\rootkit_detection\baselines\system_baseline.json', 'r') as f:
        return json.load(f)

def verify_integrity(baseline):
    for file_path, original_hash in baseline.items():
        if os.path.exists(file_path):
            current_hash = md5(file_path)
            if current_hash != original_hash:
                print(f"Integrity violation detected: {file_path}")
        else:
            print(f"File missing: {file_path}")

# Step 5: Kernel Object Verification
def check_kernel_objects():
    trusted_baseline = {
        "driver1.sys": "expected_hash_value_1",
        "driver2.sys": "expected_hash_value_2",
    }

    # Use 'driverquery' to list drivers
    result = subprocess.run(["driverquery", "/FO", "CSV"], capture_output=True, text=True)
    lines = result.stdout.splitlines()

    for driver in trusted_baseline.keys():
        for line in lines:
            if driver in line:
                parts = line.split(',')
                # Assuming the second part contains the path
                driver_path = parts[2].strip('"')
                current_hash = md5(driver_path)
                if current_hash != trusted_baseline[driver]:
                    print(f"Kernel module integrity violation: {driver}")
                else:
                    print(f"Kernel module {driver} is intact.")
                break
        else:
            print(f"Kernel module missing: {driver}")

# Step 6: Firmware Configuration Verification
def create_configuration_baseline():
    current_config = get_current_firmware_config()
    with open(r'C:\Users\ASUS\Desktop\rootkit_detection\baselines\config_baseline.json', 'w') as f:
        json.dump(current_config, f)

def get_current_firmware_config():
    return {
        "boot_order": ["HDD", "USB", "Network"],
        "secure_boot": True,
    }

def load_configuration_baseline():
    with open(r'C:\Users\ASUS\Desktop\rootkit_detection\baselines\config_baseline.json', 'r') as f:
        return json.load(f)

def verify_configuration():
    baseline = load_configuration_baseline()
    current_config = get_current_firmware_config()
    if current_config != baseline:
        print("Firmware configuration deviation detected.")
    else:
        print("Firmware configuration intact.")

# Step 7: Signature-Based Detection
def load_signatures():
    with open(r'C:\Users\ASUS\Desktop\rootkit_detection\signatures\signatures.json', 'r') as f:
        return json.load(f)

def scan_files(directory, signatures):
    matches = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = md5(file_path)
            if file_hash in signatures.values():
                matches.append((file, file_hash))
    return matches
