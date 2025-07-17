#!/bin/bash
BASE=${PWD}
URL=$1
NAME=$2
SUBDIR=${3:-"problem"}


# Check if required args are provided
if [ -z "$URL" ] || [ -z "$NAME" ]; then
    echo "Usage: $0 <url> <name> [subdir (default: problem)]"
    exit 1
fi
NAME=$(echo "$NAME" | tr '[:upper:]' '[:lower:]')

GDBNAME="gdb$NAME"
PROJECT_DIR="$BASE/$NAME"

# Check if the directory already exists
if [ -d "$PROJECT_DIR" ]; then
    echo "[-] Directory $PROJECT_DIR already exists. Please remove it or choose a different name."
    exit 1
fi

mkdir -p "$PROJECT_DIR"

PROBLEM_DIR="$PROJECT_DIR/$SUBDIR"
TMP_ZIP="$PROJECT_DIR/temp.zip"


# Copy pwntools
cp "$BASE/pwn_template.py" "$PROJECT_DIR/solution.py"

# Create subdirectory
mkdir -p "$PROBLEM_DIR"

# Download and unzip
echo "[+] Downloading problem from the URL..."
curl -L "$URL" -o "$TMP_ZIP"
if ! [ -f "$TMP_ZIP" ]; then
    echo "[-] Download failed. Aborting..."
    rm -rf $PROJECT_DIR
    exit 1
fi
if unzip -q "$TMP_ZIP" -d "$PROBLEM_DIR"; then
    echo "[+] Unzipped successfully to $PROBLEM_DIR"
else
    echo "[-] Unzip failed. Please check the URL or the zip file."
    echo "[-] Aborting..."
    rm -rf $PROJECT_DIR
    exit 1
fi
rm -f "$TMP_ZIP"


# Setup environment
if [ -f "$PROBLEM_DIR/Dockerfile" ]; then
    echo "[+] Dockerfile found in $PROBLEM_DIR, setting up Docker environment..."


    # Setup debug environment
    echo "[+] Setting up debug environment..."
    cp "$BASE/SetupDocker" "$PROBLEM_DIR/gdbDockerfile"


    # Create run script for debugging
    cat > "$PROJECT_DIR/debug.sh" <<EOF
#!/usr/bin/env bash
HOST_PORT=7000
CONTAINER_PORT=7000
NAME=${GDBNAME}

# 기존에 존재하는(실행 중이든 아니든) 컨테이너가 있으면 강제 삭제
if docker ps -a -q -f name="^/\${NAME}$" >/dev/null; then
  echo "Removing existing container '\${NAME}'..."
  docker rm -f "\${NAME}"
fi

docker run -it \
  -p "\${HOST_PORT}:\${CONTAINER_PORT}" \
  --cap-add SYS_PTRACE \
  --security-opt seccomp=unconfined \
  --name "\${NAME}" \
  "\${NAME}"
EOF
    chmod +x "$PROJECT_DIR/debug.sh"
    echo "[+] Debug environment set up successfully."


    # Create build script
    echo "[+] Creating build script..."
    cat > "$PROJECT_DIR/build.sh" <<EOF
#!/usr/bin/env bash
docker build -t "$NAME" -f "$PROBLEM_DIR/Dockerfile" "$PROBLEM_DIR"
docker build -t "$GDBNAME" -f "$PROBLEM_DIR/gdbDockerfile" "$PROBLEM_DIR"
EOF
    chmod +x "$PROJECT_DIR/build.sh"
    echo "[+] Build script created at $PROJECT_DIR/build.sh."


    # Build Docker image
    echo "[+] Building Docker image..."
    if docker build "$PROBLEM_DIR" -f "$PROBLEM_DIR/Dockerfile" -t "$NAME"; then
        echo "[+] Docker image $NAME built successfully."
    else
        echo "[-] Failed to build Docker image $NAME."
    fi


    # Create run script
    cat > "$PROJECT_DIR/run.sh" <<EOF
#!/usr/bin/env bash
HOST_PORT=7138
CONTAINER_PORT=7138
NAME=${NAME}

# 기존에 존재하는(실행 중이든 아니든) 컨테이너가 있으면 강제 삭제
if docker ps -a -q -f name="^/\${NAME}$" >/dev/null; then
  echo "Removing existing container '\${NAME}'..."
  docker rm -f "\${NAME}"
fi

docker run -d -p \$HOST_PORT:\$CONTAINER_PORT --name \${NAME} \${NAME}
EOF
    chmod +x "$PROJECT_DIR/run.sh"
    echo "[+] Run script created at $PROJECT_DIR/run.sh."

    
    echo "[+] Docker setup completed successfully."
else
    echo "[+] No Dockerfile found in $PROBLEM_DIR, skipping Docker setup."
fi

echo "[+] Creating cleanup script..."
cat > "$PROJECT_DIR/cleanup.sh" <<EOF
#!/usr/bin/env bash
# Cleanup script for $NAME
if [ -d "$PROBLEM_DIR" ]; then
    echo "Cleaning up $PROBLEM_DIR ..."
    if [ -f "$PROBLEM_DIR/Dockerfile" ]; then
        echo "Removing Docker image..."
        docker stop "$NAME" 
        docker rm "$NAME"
        docker rmi "$NAME" || echo "Docker image $NAME does not exist."
    fi
    if [ -f "$PROBLEM_DIR/gdbDockerfile" ]; then
        echo "Removing GDB Docker image..."
        docker stop "$GDBNAME"
        docker rm "$GDBNAME"
        docker rmi "$GDBNAME" || echo "Docker image $GDBNAME does not exist."
    fi
    rm -rfI "$PROBLEM_DIR"
else
    echo "Problem directory does not exist."
    echo "No cleanup needed."
fi
EOF
chmod +x "$PROJECT_DIR/cleanup.sh"
cd "$PROJECT_DIR"
echo "[+] Cleanup script created at $PROJECT_DIR/cleanup.sh."

echo "[+] All setup completed successfully."
echo "[+] You can now run the problem using '$PROJECT_DIR/run.sh' and debug it using '$PROJECT_DIR/debug.sh' after configuring $PROBLEM_DIR/gdbDockerfile."
echo "[+] To clean up, run '$PROJECT_DIR/cleanup.sh', which fill remove $PROBLEM_DIR and associated docker images."
