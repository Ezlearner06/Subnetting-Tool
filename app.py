import os
import sys
from streamlit.web import cli as stcli

if __name__ == "__main__":
    # Render and other platforms set the PORT environment variable.
    # Default to 8501 for local development if PORT is not set.
    port = os.environ.get("PORT", "8501")
    
    # Configure the arguments just like running `streamlit run streamlit_app.py ...`
    sys.argv = [
        "streamlit", 
        "run", 
        "streamlit_app.py", 
        "--server.port", port, 
        "--server.address", "0.0.0.0"
    ]
    
    # Execute the Streamlit CLI
    sys.exit(stcli.main())
