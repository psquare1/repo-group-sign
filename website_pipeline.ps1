$ErrorActionPreference = "Stop"

# Step 1: Compile the circom circuit
Write-Host "Step 1: Compiling the circom circuit..."
circom --r1cs --wasm --c --sym --inspect circuit.circom 
if ($LASTEXITCODE -ne 0) { Write-Host "Error: circom failed."; exit 1 }
Write-Host "Step 1 completed."

# Step 2: Setup Groth16 proving system
Write-Host "Step 2: Running snarkjs groth16 setup..."
if ($args.Count -lt 1) {
    Write-Host "Error: Please provide the .ptau filename as a CLI argument."
    exit 1
}
$ptauFile = $args[0]
snarkjs groth16 setup circuit.r1cs $ptauFile circuit_0003.zkey
if ($LASTEXITCODE -ne 0) { Write-Host "Error: snarkjs groth16 setup failed."; exit 1 }
Write-Host "Step 2 completed."

# Step 3: Apply a beacon for randomness
Write-Host "Step 3: Applying beacon to randomize zkey"
snarkjs zkey beacon circuit_0003.zkey circuit_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"
if ($LASTEXITCODE -ne 0) { Write-Host "Error: snarkjs zkey beacon failed."; exit 1 }
Write-Host "Step 3 completed."

# Step 4: Export the verification key
Write-Host "Step 4: Exporting verification key..."
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
if ($LASTEXITCODE -ne 0) { Write-Host "Error: snarkjs zkey export verificationkey failed."; exit 1 }
Write-Host "Step 4 completed."

# Step 5: Open browser
Write-Host "Step 5: Opening http://localhost:3000 in your browser..."
Start-Process "http://localhost:3000"
if ($LASTEXITCODE -ne 0) { Write-Host "Error: Start-Process failed."; exit 1 }

# Step 6: Start the Node.js server
Write-Host "Step 6: Starting Node.js server..."
node server.js
if ($LASTEXITCODE -ne 0) { Write-Host "Error: node server.js failed."; exit 1 }

# Final message
Write-Host "All steps completed. The server is now running at http://localhost:3000"
