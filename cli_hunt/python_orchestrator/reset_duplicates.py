import json
import os
from collections import defaultdict

DB_FILE = "challenges.json"


def reset_duplicated_challenges(db_file):
    if not os.path.exists(db_file):
        print(f"Error: Database file not found at {db_file}")
        return

    try:
        with open(db_file, "r") as f:
            db = json.load(f)
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {db_file}")
        return
    except Exception as e:
        print(f"An unexpected error occurred while reading {db_file}: {e}")
        return

    receipt_to_challenge_map = defaultdict(list)
    challenges_to_reset = []

    # First pass: Collect all challenges with cryptoReceipts and map them
    for address, data in db.items():
        if "challenge_queue" in data:
            for challenge in data["challenge_queue"]:
                if "cryptoReceipt" in challenge and challenge["cryptoReceipt"]:
                    receipt = challenge["cryptoReceipt"]
                    # Assuming the 'signature' is what identifies a unique receipt
                    # You might need to adjust this key if the receipt structure is different
                    signature = receipt.get("signature")
                    if signature:
                        receipt_to_challenge_map[signature].append((address, challenge))

    # Second pass: Identify duplicated challenges
    for signature, challenge_list in receipt_to_challenge_map.items():
        if len(challenge_list) > 1:
            print(f"Detected duplicate receipt signature: {signature}")
            # For duplicates, we reset all but the first encountered challenge.
            # This logic assumes you want one instance to remain "solved" and the others reset.
            # If you want to reset ALL duplicates, including the first one,
            # then change the slice to `challenge_list[:]`
            for address, challenge in challenge_list[1:]:  # Skip the first instance
                challenges_to_reset.append((address, challenge["challengeId"]))
                print(
                    f"  - Marking challenge {challenge['challengeId']} for address {address[:10]}... for reset."
                )

    if not challenges_to_reset:
        print("No duplicated challenges with crypto receipts found.")
        return

    # Apply resets
    reset_count = 0
    for address, challenge_id in challenges_to_reset:
        for challenge in db[address]["challenge_queue"]:
            if challenge["challengeId"] == challenge_id:
                challenge["status"] = "available"
                challenge.pop("solvedAt", None)
                challenge.pop("submittedAt", None)
                challenge.pop("validatedAt", None)
                challenge.pop("salt", None)
                challenge.pop("cryptoReceipt", None)
                reset_count += 1
                print(f"Reset challenge {challenge_id} for address {address[:10]}...")
                break

    # Save the modified database
    try:
        with open(db_file, "w") as f:
            json.dump(db, f, indent=4)
        print(
            f"\nSuccessfully reset {reset_count} duplicated challenges and saved to {db_file}."
        )
    except Exception as e:
        print(f"Error: Could not save modified database to {db_file}: {e}")


if __name__ == "__main__":
    reset_duplicated_challenges(DB_FILE)
