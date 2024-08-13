# rootkit_detection.py
from utils import (
    verify_firmware_integrity,
    monitor_firmware_behavior,
    load_baseline,
    verify_integrity,
    check_kernel_objects,
    verify_configuration,
    load_signatures,
    scan_files
)

if __name__ == "__main__":
    print("Starting SMSFRD...")

    # Step 2: Firmware Integrity Verification
    print("Verifying firmware integrity...")
    verify_firmware_integrity(r"D:\firmware.bin.txt")

    # Step 3: Behavioral Analysis of Firmware
    print("Monitoring firmware behavior...")
    suspicious_behaviors = monitor_firmware_behavior(timeout=60)  # Set timeout to 60 seconds
    if suspicious_behaviors:
        print("Suspicious firmware behaviors detected:", suspicious_behaviors)
    else:
        print("No suspicious firmware behaviors detected.")

    # Step 4: Integrity Checking
    print("Verifying system integrity...")
    directories = [r"D:\\"]  # Path to your pendrive
    baseline = load_baseline()
    verify_integrity(baseline)

    # Step 5: Kernel Object Verification
    print("Verifying kernel objects...")
    check_kernel_objects()

    # Step 6: Firmware Configuration Verification
    print("Verifying firmware configuration...")
    verify_configuration()

    # Step 7: Signature-Based Detection
    print("Scanning for known firmware rootkits...")
    signatures = load_signatures()
    matches = scan_files(r"D:\\", signatures["firmware_rootkits"])  # Fixed path issue
    if matches:
        print("Firmware rootkits detected:", matches)
    else:
        print("No firmware rootkits detected.")

    print("SMSFRD completed.")
