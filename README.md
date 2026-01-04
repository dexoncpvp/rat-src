# Rat Source Code

**STATUS: DISCONTINUED**

This repository contains the complete source code for the project. Development has officially ceased, and this codebase is provided for archival and educational purposes only.

## Project Overview

This suite consists of several interconnected components designed for remote administration and monitoring:

*   **Panel**: A web-based control dashboard built with Python.
*   **Guardian**: A Go-based security and monitoring module.
*   **Loader**: A Java-based component for loading modifications.
*   **Main Mod**: The core Java client implementation.

## Installation and Usage

### Panel (`new_panel`)

The panel acts as the central command interface.

1.  Navigate to the `new_panel` directory.
2.  Ensure Python 3.10 or higher is installed.
3.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4.  Configure the application settings in `app/core/config.py` (or equivalent configuration files if present).
5.  Start the application:
    ```bash
    python app/main.py
    ```

### Guardian (`guardian`)

The Guardian module is written in Go.

1.  Navigate to the `guardian` directory.
2.  Ensure you have the Go compiler installed (version 1.20+ recommended).
3.  Compile the source code:
    ```bash
    go build -o guardian guardian_v4.go
    ```

### Java Components (`src` and `loader`)

The Java components (Main Mod and Loader) are designed to be built using Gradle.

1.  Navigate to the project root.
2.  Build the project using the Gradle wrapper:
    ```bash
    ./gradlew build
    ```
    *Note: If build scripts are missing, ensure you have a standard Fabric/Gradle environment set up for Minecraft mod development.*

## Acknowledgments

We would like to extend our sincere clarity and gratitude to the community for the support throughout the development of this project. Although valid development has ended, we hope this source code remains a valuable resource.

---
*Archived 2026*
