set -euo pipefail

if [ -d "$PRO" ]; then
    echo "Cleaning up $NAME directory..."
    if [ -d "$NAME/problem" ]; then
        echo "Removing problem directory..."
        if [ -f "$NAME/problem/Dockerfile" ]; then
            echo "Removing Docker image..."
            docker rmi "$NAME" || echo "Docker image $NAME does not exist."
        fi
        if [ -f "$NAME/problem/GdbDockerfile" ]; then
            echo "Removing Docker image..."
            docker rmi "Gdb$NAME" || echo "Docker image $NAME does not exist."
        fi
        rm -rfI "$NAME/problem"
    else
        echo "Problem directory does not exist."
    fi
else
    echo "Directory $NAME does not exist."
fi