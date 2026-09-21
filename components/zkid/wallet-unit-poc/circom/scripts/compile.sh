#!/bin/bash

usage() {
  echo "Usage: $0 {jwt|jwt_1k|jwt_2k|jwt_4k|jwt_8k|show|ecdsa|mdoc|swiyu_age25_jwt|swiyu_age18_status_2k|swiyu_age18_status_compact|swiyu_age18_prepare_compact|swiyu_age18_show_split|swiyu_age18_show_packed_chunk_v2|swiyu_canton_prepare_compact|swiyu_canton_show_split|swiyu_residence_prepare_compact|swiyu_residence_combined_prepare_compact|swiyu_residence_show_split|swiyu_residence_show_packed_chunk_v2|swiyu_nullifier_prepare|swiyu_nullifier_show|swiyu_nullifier_age18_prepare|swiyu_nullifier_age18_show|swiyu_nullifier_age18_show_packed_chunk_v2|swiyu_status_dense_17_bench|swiyu_status_binary_17_core_bench|swiyu_status_ternary_11_core_bench|swiyu_status_packed_chunk_v2_core_bench|swiyu_status_sparse_64_bench|all}"
  echo "  jwt:    Compile the default JWT circuit."
  echo "  jwt_1k: Compile JWT circuit (1KB - maxMsg=1280)."
  echo "  jwt_2k: Compile JWT circuit (2KB - maxMsg=2048)."
  echo "  jwt_4k: Compile JWT circuit (4KB - maxMsg=4096)."
  echo "  jwt_8k: Compile JWT circuit (8KB - maxMsg=8192)."
  echo "  show:   Compile Show circuit."
  echo "  ecdsa:  Compile ECDSA circuit."
  echo "  mdoc:   Compile MDOC circuit."
  echo "  swiyu_age25_jwt: Compile the OpenAC shared age-25 holder-challenge circuit (no status)."
  echo "  swiyu_age18_status_2k: Compile the fixed swiyu Prototype A+B circuit."
  echo "  swiyu_age18_status_compact: Compile the same relation with a 14-block issuer envelope."
  echo "  swiyu_age18_prepare_compact: Compile the reusable credential-authentication stage."
  echo "  swiyu_age18_show_split: Compile the challenge/status/predicate presentation stage."
  echo "  swiyu_age18_show_packed_chunk_v2: Compile the versioned packed-status age Show A/B."
  echo "  swiyu_residence_prepare_compact: Compile authoritative residence credential authentication."
  echo "  swiyu_residence_combined_prepare_compact: Compile optimized combined-disclosure residence authentication."
  echo "  swiyu_residence_show_split: Compile residence area/duration presentation with ternary status."
  echo "  swiyu_residence_show_packed_chunk_v2: Compile the packed-status residence Show A/B."
  echo "  swiyu_nullifier_prepare: Compile the isolated authenticated nullifier Prepare core."
  echo "  swiyu_nullifier_show: Compile the isolated scoped-nullifier Show decorator."
  echo "  swiyu_nullifier_age18_prepare: Compile integrated age/nullifier Prepare."
  echo "  swiyu_nullifier_age18_show: Compile integrated age/nullifier Show."
  echo "  swiyu_nullifier_age18_show_packed_chunk_v2: Compile packed-status integrated age/nullifier Show."
  echo "  swiyu_status_dense_17_bench: Compile the isolated Prototype B dense benchmark."
  echo "  swiyu_status_binary_17_core_bench: Compile the binary status core control."
  echo "  swiyu_status_ternary_11_core_bench: Compile the ternary status core experiment."
  echo "  swiyu_status_packed_chunk_v2_core_bench: Compile the packed-status v2 core experiment."
  echo "  swiyu_status_sparse_64_bench: Compile the isolated Prototype B sparse benchmark."
  echo "  all:    Compile everything — jwt + jwt_1k/2k/4k/8k + show + ecdsa + mdoc."
  exit 1
}

if [ -z "$1" ]; then
  echo "Error: No option provided."
  usage
fi

# Generic compile function for any named circuit
compile_circuit() {
  local name="$1"
  echo "Compiling circuit: $name"
  if [ "$name" = "swiyu_age25_jwt" ] ||
     [ "$name" = "swiyu_age18_status_2k" ] ||
     [ "$name" = "swiyu_age18_status_compact" ] ||
     [ "$name" = "swiyu_age18_prepare_compact" ] ||
     [ "$name" = "swiyu_age18_show_split" ] ||
     [ "$name" = "swiyu_age18_show_packed_chunk_v2" ] ||
     [ "$name" = "swiyu_canton_prepare_compact" ] ||
     [ "$name" = "swiyu_canton_show_split" ] ||
     [ "$name" = "swiyu_residence_prepare_compact" ] ||
     [ "$name" = "swiyu_residence_combined_prepare_compact" ] ||
     [ "$name" = "swiyu_residence_show_split" ] ||
     [ "$name" = "swiyu_residence_show_packed_chunk_v2" ] ||
     [ "$name" = "swiyu_nullifier_prepare" ] ||
     [ "$name" = "swiyu_nullifier_show" ] ||
     [ "$name" = "swiyu_nullifier_age18_prepare" ] ||
     [ "$name" = "swiyu_nullifier_age18_show" ] ||
     [ "$name" = "swiyu_nullifier_age18_show_packed_chunk_v2" ] ||
     [ "$name" = "swiyu_status_dense_17_bench" ] ||
     [ "$name" = "swiyu_status_binary_17_core_bench" ] ||
     [ "$name" = "swiyu_status_ternary_11_core_bench" ] ||
     [ "$name" = "swiyu_status_packed_chunk_v2_core_bench" ] ||
     [ "$name" = "swiyu_status_sparse_64_bench" ]; then
    # The fixed swiyu relation has millions of constraints. Circomkit always
    # requests `--inspect`/`.sym`, which makes Node buffer gigabytes of label
    # output and can exhaust both memory and disk. The wallet uses the JS/WASM
    # witness generator and the native CLI consumes `.wtns`, so this profile
    # needs only R1CS plus witness WASM (not a duplicate C++ witness engine).
    mkdir -p "build/$name"
    circom "circuits/main/$name.circom" \
      --r1cs --wasm --O2 --prime secq256r1 \
      -l node_modules -o "build/$name" \
      || { echo "Error: Failed to compile $name."; exit 1; }
  else
    npx circomkit compile "$name" || { echo "Error: Failed to compile $name."; exit 1; }
  fi
  cd "build/$name/" || { echo "Error: 'build/$name/' directory not found."; exit 1; }
  if [ "$name" = "swiyu_age25_jwt" ] ||
     [ "$name" = "swiyu_age18_status_2k" ] ||
     [ "$name" = "swiyu_age18_status_compact" ] ||
     [ "$name" = "swiyu_age18_prepare_compact" ] ||
     [ "$name" = "swiyu_age18_show_split" ] ||
     [ "$name" = "swiyu_age18_show_packed_chunk_v2" ] ||
     [ "$name" = "swiyu_canton_prepare_compact" ] ||
     [ "$name" = "swiyu_canton_show_split" ] ||
     [ "$name" = "swiyu_residence_prepare_compact" ] ||
     [ "$name" = "swiyu_residence_combined_prepare_compact" ] ||
     [ "$name" = "swiyu_residence_show_split" ] ||
     [ "$name" = "swiyu_residence_show_packed_chunk_v2" ] ||
     [ "$name" = "swiyu_nullifier_prepare" ] ||
     [ "$name" = "swiyu_nullifier_show" ] ||
     [ "$name" = "swiyu_nullifier_age18_prepare" ] ||
     [ "$name" = "swiyu_nullifier_age18_show" ] ||
     [ "$name" = "swiyu_nullifier_age18_show_packed_chunk_v2" ] ||
     [ "$name" = "swiyu_status_dense_17_bench" ] ||
     [ "$name" = "swiyu_status_binary_17_core_bench" ] ||
     [ "$name" = "swiyu_status_ternary_11_core_bench" ] ||
     [ "$name" = "swiyu_status_packed_chunk_v2_core_bench" ] ||
     [ "$name" = "swiyu_status_sparse_64_bench" ]; then
    # Keep the conventional JS path without consuming a second gigabyte.
    ln -f "$name.r1cs" "${name}_js/$name.r1cs" || { echo "Error: Failed to link $name.r1cs."; exit 1; }
  else
    cp "$name.r1cs" "${name}_js/" || { echo "Error: Failed to copy $name.r1cs."; exit 1; }
  fi
  cd ../.. || exit 1
  if [ "$name" != "swiyu_age25_jwt" ] &&
     [ "$name" != "swiyu_age18_status_2k" ] &&
     [ "$name" != "swiyu_age18_status_compact" ] &&
     [ "$name" != "swiyu_age18_prepare_compact" ] &&
     [ "$name" != "swiyu_age18_show_split" ] &&
     [ "$name" != "swiyu_age18_show_packed_chunk_v2" ] &&
     [ "$name" != "swiyu_canton_prepare_compact" ] &&
     [ "$name" != "swiyu_canton_show_split" ] &&
     [ "$name" != "swiyu_residence_prepare_compact" ] &&
     [ "$name" != "swiyu_residence_combined_prepare_compact" ] &&
     [ "$name" != "swiyu_residence_show_split" ] &&
     [ "$name" != "swiyu_residence_show_packed_chunk_v2" ] &&
     [ "$name" != "swiyu_nullifier_prepare" ] &&
     [ "$name" != "swiyu_nullifier_show" ] &&
     [ "$name" != "swiyu_nullifier_age18_prepare" ] &&
     [ "$name" != "swiyu_nullifier_age18_show" ] &&
     [ "$name" != "swiyu_nullifier_age18_show_packed_chunk_v2" ] &&
     [ "$name" != "swiyu_status_dense_17_bench" ] &&
     [ "$name" != "swiyu_status_binary_17_core_bench" ] &&
     [ "$name" != "swiyu_status_ternary_11_core_bench" ] &&
     [ "$name" != "swiyu_status_packed_chunk_v2_core_bench" ] &&
     [ "$name" != "swiyu_status_sparse_64_bench" ]; then
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    # Always overwrite so build/cpp/ stays in sync with freshly compiled
    # native-witness circuits.
    cp "build/$name/${name}_cpp/$name.cpp" build/cpp/ || { echo "Error: Failed to copy $name.cpp."; exit 1; }
    cp "build/$name/${name}_cpp/$name.dat" build/cpp/ || { echo "Error: Failed to copy $name.dat."; exit 1; }
  fi
  echo "$name compilation complete."
}

case "$1" in
  jwt|jwt_1k|jwt_2k|jwt_4k|jwt_8k|show|ecdsa|mdoc|swiyu_age25_jwt|swiyu_age18_status_2k|swiyu_age18_status_compact|swiyu_age18_prepare_compact|swiyu_age18_show_split|swiyu_age18_show_packed_chunk_v2|swiyu_canton_prepare_compact|swiyu_canton_show_split|swiyu_residence_prepare_compact|swiyu_residence_combined_prepare_compact|swiyu_residence_show_split|swiyu_residence_show_packed_chunk_v2|swiyu_nullifier_prepare|swiyu_nullifier_show|swiyu_nullifier_age18_prepare|swiyu_nullifier_age18_show|swiyu_nullifier_age18_show_packed_chunk_v2|swiyu_status_dense_17_bench|swiyu_status_binary_17_core_bench|swiyu_status_ternary_11_core_bench|swiyu_status_packed_chunk_v2_core_bench|swiyu_status_sparse_64_bench)
    compile_circuit "$1"
    ;;
  all)
    echo "Compiling all circuits (jwt + jwt_1k/2k/4k/8k + show + ecdsa)..."
    compile_circuit jwt
    compile_circuit jwt_1k
    compile_circuit jwt_2k
    compile_circuit jwt_4k
    compile_circuit jwt_8k
    compile_circuit show
    compile_circuit ecdsa
    compile_circuit mdoc
    compile_circuit swiyu_age18_status_2k
    echo "All circuits compiled successfully."
    ;;
  *)
    echo "Error: Invalid option '$1'."
    usage
    ;;
esac
