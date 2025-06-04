import gradio as gr
import asyncio
from core.config import config
from a2a.protocol import A2AClient, A2AMessage

class GradioInterface:
    """Real-time A2A communication interface for Hugging Face Spaces"""
    
    def __init__(self):
        self.agents = {
            "Network Analyst": "agent_analyst",
            "Security Expert": "agent_security", 
            "Protocol Specialist": "agent_protocol"
        }
        self.a2a = A2AClient(config.a2a_server_url)
        
    async def send_message(self, agent, message, history):
        """Handle message sending and response processing"""
        try:
            msg = A2AMessage(
                sender="human_operator",
                recipients=[self.agents[agent]],
                content={
                    "type": "chat",
                    "text": message,
                    "interface": "gradio"
                }
            )
            response = await self.a2a.send(msg)
            history.append((message, response.content["text"]))
            return history, ""
        except Exception as e:
            return history, f"Error: {str(e)}"

def create_interface():
    """Build Gradio interface components"""
    interface = GradioInterface()
    
    with gr.Blocks(theme=gr.themes.Soft(), title="Network Experts A2A") as demo:
        gr.Markdown("## 🤖 Network Experts Communication Hub")
        gr.Markdown(f"Connected to A2A server: `{config.a2a_server_url}`")
        
        with gr.Row():
            with gr.Column(scale=1):
                agent = gr.Dropdown(
                    label="Select Expert Agent",
                    choices=list(interface.agents.keys()),
                    value="Network Analyst"
                )
                status = gr.Textbox("🟢 System Online", label="Connection Status")
            
            with gr.Column(scale=3):
                chatbot = gr.Chatbot(height=400, label="Conversation")
                msg = gr.Textbox(label="Your Message", placeholder="Type your query...")
                send = gr.Button("Send")
                clear = gr.Button("Clear History")
        
        msg.submit(
            interface.send_message,
            [agent, msg, chatbot],
            [chatbot, msg],
            queue=False
        )
        send.click(
            interface.send_message,
            [agent, msg, chatbot],
            [chatbot, msg],
            queue=False
        )
        clear.click(lambda: [], None, chatbot, queue=False)
    
    return demo

if __name__ == "__main__":
    demo = create_interface()
    demo.queue().launch(server_name="0.0.0.0", server_port=7860)