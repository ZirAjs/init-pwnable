# init-pwnable

Download and initalize the workspace for pwnable.

The resulting directory structure will look like this:

```
name/
├── subdir/
│   ├── Dockerfile
│   ├── gdbDockerfile
│   └── <problem files>
├── soultion.py
├── build.sh
├── run.sh
├── debug.sh
└── cleanup.sh
```

## Usage

```bash
./download.sh <url> <name> [subdir (default: problem)]
```
