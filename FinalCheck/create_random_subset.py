import os
import shutil
import random

SRC_DIR = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled"
DST_DIR = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/FinalCheck/Dataset300"

os.makedirs(DST_DIR, exist_ok=True)

target_total = 300
target_benign = 150
target_attack = 150

copied_benign = 0
copied_attack = 0

days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']

# Create iterators for each day
iterators = {}
for day in days:
    day_path = os.path.join(SRC_DIR, day)
    if os.path.isdir(day_path):
        iterators[day] = os.scandir(day_path)

print("Starting to sample 300 random streams...")

while copied_benign < target_benign or copied_attack < target_attack:
    # Pick a random day that still has an active iterator
    active_days = list(iterators.keys())
    if not active_days:
        print("No more directories to search!")
        break
    
    day = random.choice(active_days)
    iterator = iterators[day]
    
    try:
        # Skip a random number of items to increase internal randomness
        skip = random.randint(0, 100)
        for _ in range(skip):
            entry = next(iterator)
        
        entry = next(iterator)
        if not entry.is_dir():
            continue
            
        folder_name = entry.name
        is_benign = "BENIGN" in folder_name
        is_attack = not is_benign
        
        if is_benign and copied_benign < target_benign:
            src = os.path.join(SRC_DIR, day, folder_name)
            dst = os.path.join(DST_DIR, f"{day}_{folder_name}")
            if not os.path.exists(dst):
                shutil.copytree(src, dst)
                copied_benign += 1
                if copied_benign % 10 == 0:
                    print(f"[{copied_benign}/{target_benign} BENIGN] Copied {folder_name} from {day}")
            
        elif is_attack and copied_attack < target_attack:
            src = os.path.join(SRC_DIR, day, folder_name)
            dst = os.path.join(DST_DIR, f"{day}_{folder_name}")
            if not os.path.exists(dst):
                shutil.copytree(src, dst)
                copied_attack += 1
                if copied_attack % 10 == 0:
                    print(f"[{copied_attack}/{target_attack} ATTACK] Copied {folder_name} from {day}")
            
    except StopIteration:
        # Iterator exhausted for this day
        del iterators[day]
        print(f"Finished searching all entries in {day}")
    except Exception as e:
        print(f"Error reading or copying: {e}")

print(f"Done! Copied {copied_benign} BENIGN and {copied_attack} ATTACK streams to {DST_DIR}")
