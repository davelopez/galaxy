# Crypt4GH Feature Demo Guide for Galaxy

This guide walks you through using the **Crypt4GH** feature in Galaxy for end-to-end encrypted data workflows.

## Overview

**Crypt4GH** in Galaxy provides:

- **User Data Encryption**: Files are encrypted with the user's public key and stored encrypted
- **Transparent Staging**: Tools receive decrypted data from a staging directory during job execution
- **Header Re-encryption**: The re-encryptor service re-wraps crypt4gh headers so the compute key can access files
- **Local Payload Decryption**: Payload decryption happens on the compute node using a locally-deployed compute private key, so the re-encryptor service never handles private keys or plaintext bytes
- **Secure Re-encryption**: For each job, output files are re-encrypted for the user via the re-encryptor service
- **External Service Architecture**: A companion re-encryptor service (external to Galaxy) handles header re-wrapping; private-key operations stay on the compute node

---

## Part 1: Service Initialization

### Step 1.1: Activate the Python Environment

**Important:** The re-encryptor service must run with the Galaxy Python environment active.

```bash
# Navigate to the Galaxy project
cd /path/to/galaxy

# Activate the virtual environment (required for all re-encryptor commands)
source .venv/bin/activate
```

### Step 1.2: Initialize the Service

Initialize the service with a compute keypair and create user keypairs. The user email you specify should match a Galaxy user that will use the crypt4gh feature.

```bash
# Initialize with default settings (simplest setup)
python -m scripts.crypt4gh_reencryptor init --user-email demo@example.com
```

**What this does:**

- Generates a **compute keypair** (used by the re-encryptor service) in `.crypt4gh-reencryptor/`
- Generates a **user keypair** for user `demo@example.com` in `.crypt4gh-reencryptor/`

Optionally, customize the keys directory:

```bash
python -m scripts.crypt4gh_reencryptor init --keys-dir /custom/path/for/keys --user-email demo@example.com
```

### Step 1.3: Verify Generated Keys

```bash
ls -la .crypt4gh-reencryptor/
```

You should see:

```
compute.sec
compute.pub
user_demo_at_example_com.sec
user_demo_at_example_com.pub
```

**Note:** If you want to de-register a user you can simply delete their keypair files from the keys directory and restart the service.

### Step 1.4: Start the Re-encryptor Service

In a **separate terminal** (with `.venv` also activated), start the service:

```bash
# From the same Galaxy project directory with .venv activated
python -m scripts.crypt4gh_reencryptor serve
```

You should see output indicating the service is running on `http://127.0.0.1:47419` (default port).

The service is now ready to handle encryption/decryption operations for Galaxy jobs.

---

## Part 2: Galaxy Configuration

### Step 2.1: Configure Galaxy for Crypt4GH

Edit your Galaxy configuration file (e.g., `config/galaxy.yml`) and add the crypt4gh settings:

```yaml
# Crypt4GH configuration
enable_crypt4gh_transparent_staging: true
crypt4gh_reencryption_service_url: http://127.0.0.1:47419
crypt4gh_compute_private_key_path: .crypt4gh-reencryptor/compute.sec
```

**Configuration options:**

- `enable_crypt4gh_transparent_staging` — Enable transparent encrypted data handling in job execution
- `crypt4gh_reencryption_service_url` — URL of the re-encryptor service (must match where you started it in Step 1.4)
- `crypt4gh_compute_private_key_path` — Worker-local path to the compute private key used for transparent Crypt4GH plaintext input staging. This value is exported to job staging helpers via the `GALAXY_CRYPT4GH_COMPUTE_PRIVATE_KEY` environment variable. The path must be valid on the compute node (including Pulsar workers). TODO: In the future, we may support other methods of providing the compute private key to workers (e.g., via a secret store or direct API calls to the service).

Restart Galaxy for the configuration to take effect.

---

## Part 3: Add More Users (Optional)

The demo user was already registered during service initialization. To add more users:

```bash
# Ensure .venv is activated
source .venv/bin/activate

# Register an additional user (generates new keypair)
python -m scripts.crypt4gh_reencryptor register-user --user-email another.user@example.com
```

This will generate new keys for the user in `.crypt4gh-reencryptor/` and register them with the running service.

---

## Part 4: Create and Encrypt Test Data

### Step 4.1: Create a Simple Test File

```bash
# Create a sample plaintext dataset
cat > /tmp/test_data.txt <<'EOF'
sample_id	value1	value2
sample_A	10	20
sample_B	15	25
sample_C	20	30
EOF

# Verify the file exists
file /tmp/test_data.txt
```

### Step 4.2: Encrypt the Test File

Use the CLI to encrypt the file with the user's public key (ensure `.venv` is activated):

```bash
source .venv/bin/activate

python -m scripts.crypt4gh_reencryptor encrypt-dataset \
  --input /tmp/test_data.txt \
  --user-email demo@example.com \
  --output /tmp/test_data.txt.crypt4gh
```

**Response:**

```
✓ Encrypting test_data.txt...
✓ Encrypted dataset: /tmp/test_data.txt.crypt4gh
```

### Step 4.3: Verify Encryption (Optional)

```bash
# The encrypted file is binary and starts with the "crypt4gh" magic bytes
hexdump -C /tmp/test_data.txt.crypt4gh | head -2
```

Should show:

```
00000000  63 72 79 70 74 34 67 68  ...  |crypt4gh|
```

---

## Part 5: Import Encrypted File into Galaxy

### Step 5.1: Upload to Galaxy

**Via Web Interface:**

1. Log into Galaxy with the user account matching your email (`demo@example.com` if you used the demo setup)
2. Click **Upload**
3. Select the encrypted file: `/tmp/test_data.txt.crypt4gh`
4. Import into a history

**Important:** The Galaxy user email must match the email used to generate the user keypair in the re-encryptor service.

### Step 5.2: Verify Upload

Once uploaded, Galaxy will:

1. Detect the **crypt4gh** datatype (from the magic bytes `crypt4gh`)
2. Extract and store the **crypt4gh header** in dataset metadata
3. Display the file as encrypted in the history

---

## Part 6: Run a Tool on Encrypted Data

### Step 6.1: Run a Tool

1. Select a simple tool (e.g., **Text Processing** → **Head/Tail**)
2. Set the input to the encrypted dataset uploaded in Step 5
3. Run the tool

Galaxy will:

1. **Detect** encrypted input (crypt4gh datatype)
2. **Pre-commands:**
   - Call the re-encryptor service to re-wrap the input header for the compute key
   - Decrypt the payload locally on the compute node using the compute private key
3. **Run tool** with access to decrypted data from the staging directory
4. **Collect output** from the tool
5. **Post-commands:** Re-encrypt output with the user's public key via the re-encryptor service

### Step 6.2: Verify Output

Check the output dataset:

- Output will have `.crypt4gh` extension (indicating it's encrypted)
- Metadata will include the crypt4gh header
- Users can download or use as input for downstream tools

---

## Part 7: Advanced: Decrypt a File Locally (Optional)

If you want to verify encryption/decryption locally:

### Step 7.1: Decrypt the File

```bash
# Ensure .venv is activated
source .venv/bin/activate

# Use the CLI to decrypt the file with the user's private key
python -m scripts.crypt4gh_reencryptor decrypt-dataset \
  --input /tmp/test_data.txt.crypt4gh \
  --user-email demo@example.com \
  --output /tmp/test_data.decrypted.txt

# By default (without --output), the .crypt4gh suffix is stripped and
# the output is written to /tmp/test_data.txt

# Verify the decrypted content matches the original
diff /tmp/test_data.txt /tmp/test_data.decrypted.txt
# Should show no differences
```

---

## Troubleshooting

### Issue: "Re-encryptor service unreachable"

**Cause:** The service is not running or the configured URL is incorrect.

**Solution:**

```bash
# Check if service is running
curl http://127.0.0.1:47419/health

# If it fails, verify .venv is activated and start the service
source .venv/bin/activate
python -m scripts.crypt4gh_reencryptor serve
```

### Issue: "No registered users found"

**Cause:** The user keypair wasn't generated during service initialization.

**Solution:**

```bash
source .venv/bin/activate

python -m scripts.crypt4gh_reencryptor register-user \
  --user-email your.email@example.com
```

### Issue: Galaxy user email doesn't match re-encryptor registered email

**Cause:** The Galaxy user email must match a registered key in the re-encryptor service.

**Solution:**

- Create a Galaxy user with the same email as the one registered in the re-encryptor
- Or register a new user in the re-encryptor matching your Galaxy user email

### Issue: Tool fails with "stage-inputs failed"

**Cause:** The re-encryptor service URL is not configured correctly in Galaxy, or the service is unreachable.

**Solution:**

- Verify `crypt4gh_reencryption_service_url` in `config/galaxy.yml` matches where the service is running
- Restart Galaxy after changing config
- Check that the re-encryptor service is running and accessible

### Issue: "GALAXY_CRYPT4GH_COMPUTE_PRIVATE_KEY is not configured"

**Cause:** The `crypt4gh_compute_private_key_path` config option is not set, or the path points to a file that doesn't exist on the compute node.

**Solution:**

- Add `crypt4gh_compute_private_key_path` to `config/galaxy.yml` pointing to the compute private key file (e.g., `.crypt4gh-reencryptor/compute.sec`)
- Ensure the key file exists at that path **on the compute node** (including Pulsar workers if using a remote cluster)
- The key file should be readable by the Galaxy job process
- Restart Galaxy after changing config

---

## Quick Reference: Command Summary

```bash
# Activate environment (always required)
source .venv/bin/activate

# Initialize service and first user
python -m scripts.crypt4gh_reencryptor init \
  --user-email demo@example.com \
  --non-interactive

# Start the service (in separate terminal with .venv active)
python -m scripts.crypt4gh_reencryptor serve

# Register an additional user
python -m scripts.crypt4gh_reencryptor register-user \
  --user-email another.user@example.com

# Encrypt a test file
python -m scripts.crypt4gh_reencryptor encrypt-dataset \
  --input plaintext.txt \
  --user-email demo@example.com

# Decrypt a file locally
python -m scripts.crypt4gh_reencryptor decrypt-dataset \
  --input file.crypt4gh --user-email demo@example.com
```

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────┐
│ Galaxy Web                                                 │
│  - User uploads plaintext or encrypted file               │
│  - User email must match re-encryptor registered email    │
└──────────────────────┬─────────────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │ Galaxy Job Preparation       │
        │ - Detect encrypted input     │
        │ - Generate staging manifest  │
        │ - Export compute key path    │
        └──────────┬───────────────────┘
                   │
                   ▼
    ┌──────────────────────────────┐
    │ Compute Node (Job Execution) │
    │ - Pre-commands:              │
    │   1. Re-encrypt headers via  │
    │      re-encryptor service    │───────┐
    │   2. Decrypt payload locally │       │
    │      using compute private   │       │
    │      key (GALAXY_CRYPT4GH_   │       │
    │       COMPUTE_PRIVATE_KEY)   │       │
    │ - Run tool with plaintext    │       │
    │   data from staging dir      │       │
    │ - Collect plaintext outputs  │       │
    │ - Post-commands: Encrypt     │       │
    │   outputs via service ───────┼───────┘
    └──────────┬───────────────────┘
               │
               ▼
    ┌──────────────────────────────┐
    │ Re-encryptor Service (FastAPI)│
    │ - Re-wrap headers for        │
    │   compute key (pre-commands) │
    │ - Re-encrypt outputs for     │
    │   user key (post-commands)   │
    │ (no private-key payload ops) │
    └──────────────────────────────┘
```

---

## Key Concepts

### Crypt4GH Header

The **header** is a small, encrypted metadata structure at the beginning of each crypt4gh file. It contains:

- Encryption algorithm metadata
- Session key (encrypted for the recipient's public key)
- Version information

**Important:** Headers can be read/validated without the private key. Only decryption requires the private key.

### Re-encryption vs. Decryption

- **Decryption:** Convert ciphertext back to plaintext (requires private key)
- **Re-encryption:** Transform a header from one recipient key to another (requires both old and new recipient's public keys)

The re-encryptor service performs **header re-encryption** only — it re-wraps file headers so the compute node's key can open them, and later re-wraps output headers for the user's key. **Payload decryption happens on the compute node** using the locally-deployed compute private key (configured via `crypt4gh_compute_private_key_path`), so the re-encryptor service never handles private keys or plaintext payload bytes.

### Transparent Staging

When `enable_crypt4gh_transparent_staging` is true, Galaxy automatically:

1. **Pre-commands (before tool runs):**
   - Calls the re-encryptor service to re-wrap each input's crypt4gh header for the compute key
   - Overwrites the file header with the re-wrapped version (so the compute key can decrypt it)
   - Decrypts the payload **locally on the compute node** using the compute private key (`crypt4gh_compute_private_key_path`)
   - The tool receives plaintext data from the staging directory
2. **Runs the tool** with access to decrypted data from the staging directory
3. **Post-commands (after tool runs):**
   - Encrypts output files via the re-encryptor service with the user's public key

Tools run unmodified and don't need to know about encryption.
