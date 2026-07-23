import csv
import random
from datetime import datetime, timedelta

def generate_ip(location):
    if location == "Tokyo":
        return f"126.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    elif location == "Japan":
        return f"133.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(1, 100)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_baseline(num_entries=100):
    data = []
    start_time = datetime(2026, 3, 20, 7, 0, 0)
    username = "admin_user"
    
    current_time = start_time
    for _ in range(num_entries):
        # Time: 7 AM - 10 PM
        if current_time.hour < 7 or current_time.hour >= 22:
            current_time = current_time.replace(hour=7, minute=random.randint(0, 59))
        
        # Location distribution
        rand = random.random()
        if rand < 0.45:
            ip = generate_ip("Tokyo")
        elif rand < 0.67:
            ip = generate_ip("Japan")
        else:
            ip = generate_ip("Foreign")
            
        # Success rate 90%
        status = "Success" if random.random() < 0.90 else "Failure"
        
        data.append([current_time.strftime("%Y-%m-%d %H:%M:%S"), ip, username, status])
        
        # Average interval ~1 hour 7 mins
        current_time += timedelta(minutes=random.randint(40, 90))
        
    return data

def inject_anomalies(data):
    username = "admin_user"
    last_time = datetime.strptime(data[-1][0], "%Y-%m-%d %H:%M:%S")
    
    # 1. Brute Force Simulation: 5 consecutive failures within 2 mins
    bf_time = last_time + timedelta(hours=2)
    for i in range(5):
        data.append([(bf_time + timedelta(seconds=i*20)).strftime("%Y-%m-%d %H:%M:%S"), 
                     generate_ip("Tokyo"), username, "Failure"])
    
    # 2. Automation / Bot Simulation: 10 rapid attempts within 1 min
    bot_time = bf_time + timedelta(hours=5)
    for i in range(10):
        data.append([(bot_time + timedelta(seconds=i*5)).strftime("%Y-%m-%d %H:%M:%S"), 
                     generate_ip("Japan"), username, "Success" if i % 2 == 0 else "Failure"])

    # 3. Location + Time Anomaly: Foreign IP at 3 AM
    anomaly_time = (bot_time + timedelta(days=1)).replace(hour=3, minute=15)
    data.append([anomaly_time.strftime("%Y-%m-%d %H:%M:%S"), 
                 generate_ip("Foreign"), username, "Success"])

    # 4. Combined Attack: 8 attempts within 2 mins at 2 AM from Foreign IP
    combined_time = (anomaly_time + timedelta(days=1)).replace(hour=2, minute=10)
    for i in range(8):
        data.append([(combined_time + timedelta(seconds=i*15)).strftime("%Y-%m-%d %H:%M:%S"), 
                     generate_ip("Foreign"), username, "Failure"])

    return data

def main():
    header = ["Timestamp", "IP_Address", "Username", "Status"]
    baseline_data = generate_baseline()
    full_data = inject_anomalies(baseline_data)
    
    with open("../data/login_logs.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(full_data)
    print("Data generated successfully in ../data/login_logs.csv")

if __name__ == "__main__":
    main()
