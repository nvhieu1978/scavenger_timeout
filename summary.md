Here is a detailed summary of how the Scavenger Hunt technically works and how you could implement a command-line program to participate.

### Scavenger Hunt: Technical Workflow

The Scavenger Hunt is a proof-of-work competition where participants solve cryptographic challenges to earn rewards. The process is managed via a web API and utilizes a custom ASIC-resistant hashing algorithm called AshMaize.

#### 1. Registration

Before participating, each Cardano address you want to use must be registered. This is a one-time process.

*   **Fetch Terms & Conditions (T&C):** Make a `GET` request to the `/TandC` endpoint. The response contains a message that must be signed.
*   **Sign the T&C Message:** Using the private key associated with your Cardano address, create a CIP-8 or CIP-30 signature of the exact T&C message.
*   **Register:** Make a `POST` request to `/register/{address}/{signature}/{pubkey}` with your Cardano address, the signature, and the corresponding public key.

#### 2. The Mining Loop

Once an address is registered, it can participate in the mining loop.

*   **Fetch the Challenge:** A new challenge is available every hour. Fetch the current challenge details by making a `GET` request to the `/challenge` endpoint. The key fields in the response are:
    *   `challenge_id`: A unique identifier for the current challenge.
    *   `difficulty`: A 4-byte hex string representing a bitmask. Your solution's hash must have at least as many leading zero bits as this mask.
    *   `no_pre_mine`: A daily seed used to initialize the AshMaize hashing environment.
    *   `no_pre_mine_hour`: An hourly seed used as part of the data to be hashed.
    *   `latest_submission`: The timestamp by which the solution must be submitted.

*   **Solve the Challenge (Proof-of-Work):** This is the most computationally intensive part. The goal is to find a `nonce` that, when combined with other challenge data and hashed, produces a result that meets the difficulty requirement.

    1.  **Initialize AshMaize ROM:** The AshMaize algorithm requires a large (~1GB) read-only memory (ROM) to be initialized.
        *   This ROM is generated using the `no_pre_mine` value from the challenge.
        *   The ROM only needs to be regenerated when the `no_pre_mine` value changes (i.e., once a day).
        *   The specific configuration parameters for AshMaize are detailed in the whitepaper and `SPECS.md`:
            *   `nbLoops`: 8
            *   `nblnstrs`: 256
            *   `pre_size`: 16777216
            *   `mixing_numbers`: 4
            *   `rom_size`: 1073741824

    2.  **Construct the Preimage:** The data to be hashed (the "preimage") is a specific concatenation of the following string values:
        *   A 64-bit `nonce`, hex-encoded (16 characters).
        *   Your registered Cardano `address`.
        *   The `challenge_id`.
        *   The `difficulty` string.
        *   The `no_pre_mine` string.
        *   The `latest_submission` timestamp.
        *   The `no_pre_mine_hour` string.

    3.  **Find a Valid Nonce:**
        *   Start with a random 64-bit integer for your `nonce`.
        *   Construct the preimage string as described above.
        *   Hash the preimage using the initialized AshMaize algorithm.
        *   Check if the resulting hash satisfies the `difficulty` (i.e., has enough leading zero bits).
        *   If it does, you have found a valid solution.
        *   If not, increment your `nonce` and repeat the process.

*   **Submit the Solution:** Once a valid `nonce` is found, submit it immediately by making a `POST` request to `/solution/{address}/{challenge_id}/{nonce}`. The server will validate your solution.

#### 3. Managing Multiple Addresses

The process is identical for each address. To participate with multiple addresses, you would run the mining loop for each one. A command-line tool can do this in parallel to maximize efficiency.

#### 4. Consolidating Rewards (Optional)

If you are participating with multiple addresses, you can consolidate the rewards into a single address.

*   **Create Signature:** The owner of the `original_address` (the one donating the rewards) must sign the message: `"Assign accumulated Scavenger rights to: <destination_address>"`.
*   **Donate:** Make a `POST` request to `/donate_to/{destination_address}/{original_address}/{signature}`.

### Implementing a Command-Line Tool

A command-line tool to automate this process can be structured with a clear separation between orchestration and computation, and between challenge fetching and solving. This allows for flexibility and efficiency. The user is assumed to have already registered their addresses.

**1. Architecture Overview**

*   **Orchestrator (Python):** A Python-based CLI application that manages the overall workflow. It handles configuration, calls the API, manages a database of challenges, and orchestrates the solving process. Python is ideal for its flexibility and rich ecosystem for CLI development and HTTP requests.
*   **Compute/Solver (Rust):** A small, dedicated Rust executable that performs the computationally expensive AshMaize hashing. It will be called by the Python orchestrator. This leverages the performance of Rust and the existing `ashmaize` crate.

**2. State Management**

*   A local database (e.g., a JSON file or a simple SQLite database) will be used to store the state. For each address, it will keep track of fetched challenges that are yet to be solved.

**3. Logical Components & Workflow**

The tool would have two main, distinct modes of operation, likely implemented as subcommands (e.g., `scavenger-cli fetch` and `scavenger-cli solve`).

**A. Challenge Fetching (`fetch` command)**

*   **Purpose:** To continuously gather challenges for all registered addresses.
*   **Implementation:**
    *   This command runs a lightweight, long-running process.
    *   It reads the list of user-provided Cardano addresses from a configuration file.
    *   On a regular interval (e.g., every hour), it iterates through each address and makes a `GET` request to the `/challenge` API endpoint.
    *   If a new, unsolved challenge is found, it is added to the local challenge database, associated with the respective address.

**B. Problem Solving (`solve` command)**

*   **Purpose:** To solve the challenges that have been previously fetched. This is the compute-intensive part.
*   **Implementation:**
    *   This command is run manually by the user, for example, once or twice a day.
    *   It reads the challenge database to find all unsolved challenges.
    *   For each challenge, it invokes the Rust solver executable as a subprocess.
    *   **Data Passing:** The Python orchestrator passes all the necessary preimage components (address, challenge_id, difficulty, etc.) to the Rust solver via command-line arguments or standard input.
    *   **The Rust Solver:**
        *   Initializes the AshMaize ROM based on the `no_pre_mine` value (caching it if it's the same as the last run).
        *   Performs the proof-of-work by iterating through nonces until a solution is found.
        *   Prints the successful `nonce` to standard output.
    *   **Submission:** The Python orchestrator captures the `nonce` from the solver's output and makes a `POST` request to the `/solution/{address}/{challenge_id}/{nonce}` endpoint.
    *   Upon successful submission, the challenge is marked as "solved" in the local database.

This decoupled architecture provides several advantages:
*   **Efficiency:** The heavy computation is done in a compiled, high-performance language (Rust). The challenge fetching is done by a lightweight script.
*   **Flexibility:** The user can control when to run the resource-intensive solving process, without missing any challenges.
*   **Simplicity:** The tool does not need to manage any private keys or signing operations, enhancing security and simplifying the design.