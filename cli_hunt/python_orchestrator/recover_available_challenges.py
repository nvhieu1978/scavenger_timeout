import json

# === CONFIGURATION ===
CHALLENGES_FILE = "challenges-list.json"  # File containing the list of challenges
ADDRESSES_FILE = "challenges.json"  # File containing the addresses with their queues

# === LOAD CHALLENGES ===
with open(CHALLENGES_FILE, "r", encoding="utf-8") as f:
    challenges = json.load(f)

with open(ADDRESSES_FILE, "r", encoding="utf-8") as f:
    addresses = json.load(f)

# === PROCESS ===
for addr, data in addresses.items():
    queue = data.get("challenge_queue", [])

    # Build a set of existing challenge IDs for quick lookup
    existing_ids = {c["challengeId"] for c in queue if "challengeId" in c}

    # Add missing challenges
    for challenge in challenges:
        if challenge["challengeId"] not in existing_ids:
            queue.append(challenge)

    # Update queue in the data structure
    data["challenge_queue"] = queue

# === SAVE RESULT ===
with open(ADDRESSES_FILE, "w", encoding="utf-8") as f:
    json.dump(addresses, f, indent=2, ensure_ascii=False)

print(f"✅ Challenges merged successfully! Updated data written to '{ADDRESSES_FILE}'.")
