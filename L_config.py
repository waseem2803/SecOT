import os

def load_config(filename="config.txt"):
    """Load configuration from a text file formatted as key=value."""
    config = {}

    if not os.path.exists(filename):
        print(f"⚠ Error: {filename} not found!")
        return config

    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#"):  # Ignore empty lines and comments
                parts = line.split("=", 1)
                if len(parts) == 2:
                    key, value = parts
                    config[key.strip()] = value.strip()
                else:
                    print(f"⚠ Skipping malformed line: {line}")

    return config

# 🔹 Auto-load config and export variables dynamically
_config = load_config()
temp_path_b = _config.get("temp_path_b", "/default/path")


# Optional: Clean up internal variables
del _config, load_config
