# Sentinel Scanner Frontend

## How to Run
This is a static HTML/JS frontend that connects to the Sentinel Scanner backend.

### Prerequisites
1.  **Backend must be running**:
    Ensure the Spring Boot application is running on port 8080.
    ```bash
    cd ../
    mvn spring-boot:run
    ```
    > **Note**: If you just updated the Java code, please restart the backend server to load the new changes.

### Opening the UI
Since the backend is configured to allow Cross-Origin (CORS) requests from any source, you have two easy options:

#### Option 1: Direct Open (Easiest)
Simply double-click `index.html` in your file explorer, or drag it into your browser.
The URL will look like `file:///C:/Users/gayat/Downloads/scanner/frontend/index.html`.

#### Option 2: VS Code Live Server (Recommended)
for a better development experience (auto-reload):
1.  Install the **Live Server** extension in VS Code (by Ritwick Dey).
2.  Right-click `index.html` and select **"Open with Live Server"**.
3.  The URL will look like `http://127.0.0.1:5500/frontend/index.html`.

## Recommended Extensions
To work with this project effectively in VS Code, we recommend installing:
-   **Live Server** (Ritwick Dey): For serving HTML files.
-   **Extension Pack for Java** (Microsoft): For backend development.
