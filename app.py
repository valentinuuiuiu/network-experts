from gradio_interface import create_interface
import os

# Initialize the Gradio interface
demo = create_interface()

# Configure for Hugging Face Spaces
if os.environ.get('SPACES') == '1':
    demo.launch(server_name="0.0.0.0", server_port=7860)
else:
    demo.launch()