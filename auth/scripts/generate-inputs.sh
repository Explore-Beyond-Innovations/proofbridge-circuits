
#!/bin/bash

input_file="./scripts/inputs.txt"
output_file="Prover.toml"

# Extract only the value inside quotes for a given key
extract_value() {
    local key=$1
    # Extract the part inside quotes after the equals sign
    grep "^$key\s*=" "$input_file" | sed -E 's/^[^=]+= *"(.*)"/\1/'
}

# Convert hex string (without 0x) to quoted decimal byte array
hex_to_dec_quoted_array() {
    local hexstr=$1
    local len=${#hexstr}
    local arr=()
    for (( i=0; i<len; i+=2 )); do
        # Extract two hex digits
        local hexbyte="${hexstr:i:2}"
        # Convert hex to decimal number
        local dec=$((16#$hexbyte))
        # Add decimal number as quoted string
        arr+=("\"$dec\"")
    done
    echo "["$(IFS=,; echo "${arr[*]}")"]"
}

# Hash the nullifier based on the ad_contract key
function hash_nullifier() {
    local ad_contract="$1"
    local ad_creator_sig="$2"
    local bridger_sig="$3"

    local sig_arg

    if [[ "$ad_contract" == "true" ]]; then
        sig_arg="$bridger_sig"
    else
        sig_arg="$ad_creator_sig"
    fi

    local result
    result=$(npx tsx ./scripts/hash.ts "$sig_arg")

    echo "$result"
}

function to_prover_bool() {
  local flag="$1"
  if [[ "$flag" == "true" ]]; then
    echo 1   # true -> 1
  else
    echo 0   # false -> 0
  fi
}

# Read values from file
ad_creator=$(extract_value ad_creator)
ad_creator_pub_key=$(extract_value ad_creator_pub_key)
ad_creator_sig=$(extract_value ad_creator_sig)
bridger=$(extract_value bridger)
bridger_pub_key=$(extract_value bridger_pub_key)
bridger_sig=$(extract_value bridger_sig)
ad_contract=$(extract_value ad_contract)
msg_hash=$(extract_value msg_hash)
nullifier_hash=$(hash_nullifier "$ad_contract" "$ad_creator_sig" "$bridger_sig")

# Strip 0x from everything except expected_address
ad_creator_pub_key=${ad_creator_pub_key#0x}
ad_creator_sig=${ad_creator_sig#0x}
bridger_pub_key=${bridger_pub_key#0x}
bridger_sig=${bridger_sig#0x}
msg_hash=${msg_hash#0x}

# Strip last byte (2 hex chars) from signature to remove v
ad_creator_sig=${ad_creator_sig:0:${#ad_creator_sig}-2}
bridger_sig=${bridger_sig:0:${#bridger_sig}-2}

# Convert hex strings to decimal quoted arrays
ad_creator_pub_key_arr=$(hex_to_dec_quoted_array "$ad_creator_pub_key")
ad_creator_sig_arr=$(hex_to_dec_quoted_array "$ad_creator_sig")
bridger_pub_key_arr=$(hex_to_dec_quoted_array "$bridger_pub_key")
bridger_sig_arr=$(hex_to_dec_quoted_array "$bridger_sig")
msg_hash_arr=$(hex_to_dec_quoted_array "$msg_hash")
prover_bool=$(to_prover_bool "$ad_contract")

# Write output
cat > "$output_file" <<EOF
ad_creator = "$ad_creator"
ad_creator_pub_key = $ad_creator_pub_key_arr
ad_creator_sig = $ad_creator_sig_arr
bridger = "$bridger"
bridger_pub_key = $bridger_pub_key_arr
bridger_sig = $bridger_sig_arr
ad_contract = "$prover_bool"
msg_hash = $msg_hash_arr
nullifier_hash = "$nullifier_hash"
EOF

echo "Wrote $output_file"
