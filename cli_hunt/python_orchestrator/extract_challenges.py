import json

# Input and output file paths
INPUT_FILE = "challenges.json"
OUTPUT_FILE = "challenges-list.json"

# Fields to remove
FIELDS_TO_REMOVE = [
    "solvedAt",
    "validatedAt",
    "submittedAt",
    "salt",
    "hash",
    "cryptoReceipt",
]


def main():
    # Load the input JSON
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    all_challenges = []

    # Iterate through each address and extract its challenge queue
    for addr, content in data.items():
        queue = content.get("challenge_queue", [])
        all_challenges.extend(queue)

    # Deduplicate challenges by challengeId
    deduped = {}
    for ch in all_challenges:
        ch_id = ch.get("challengeId")
        if not ch_id:
            continue
        # Reset status to "available"
        ch["status"] = "available"
        # Remove unwanted fields if present
        for field in FIELDS_TO_REMOVE:
            ch.pop(field, None)
        deduped[ch_id] = ch

    # Convert deduped challenges back to a list
    cleaned_challenges = list(deduped.values())

    # Sort challenges by challengeId
    cleaned_challenges.sort(key=lambda x: x.get("challengeId"))

    # Save result to a new JSON file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned_challenges, f, indent=4, ensure_ascii=False)

    print(f"✅ Extracted {len(cleaned_challenges)} unique challenges to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
