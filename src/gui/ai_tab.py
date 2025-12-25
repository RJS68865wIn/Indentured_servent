"""
AI Assistant Tab - GUI for interacting with the AI cybersecurity assistant
"""
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import json
from datetime import datetime
from typing import List, Dict, Any
import markdown
import html2text

from src.ai_assistant import AIAssistant, AIMessage
from src.utils.logger import setup_logger

class AITab:
    """AI Assistant tab for interactive cybersecurity assistance"""
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        
        # Initialize AI assistant and logger
        self.assistant = AIAssistant()
        self.logger = setup_logger("AIGUI")
        
        # Conversation state
        self.is_responding = False
        self.current_stream = ""
        
        # Create widgets
        self._create_widgets()
        
        # Display welcome message
        self._display_welcome()
    
    def _create_widgets(self):
        """Create AI assistant tab widgets"""
        # Main container with two panes
        main_paned = ttk.PanedWindow(self.frame, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left pane - Chat interface
        left_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=3)
        
        # Right pane - Info and controls
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=1)
        
        # ===== LEFT PANE - CHAT INTERFACE =====
        
        # Chat history display
        chat_frame = ttk.LabelFrame(left_frame, text="AI Assistant", padding=10)
        chat_frame.pack(fill=tk.BOTH, expand=True)
        
        # Chat text widget with scrollbar
        self.chat_text = scrolledtext.ScrolledText(
            chat_frame,
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT,
            height=20
        )
        self.chat_text.pack(fill=tk.BOTH, expand=True)
        self.chat_text.config(state=tk.DISABLED)
        
        # Configure tags for different message types
        self.chat_text.tag_config("user", foreground="#60A5FA", font=("Segoe UI", 10, "bold"))
        self.chat_text.tag_config("assistant", foreground="#34D399", font=("Segoe UI", 10))
        self.chat_text.tag_config("system", foreground="#9CA3AF", font=("Segoe UI", 9, "italic"))
        self.chat_text.tag_config("function", foreground="#FBBF24", font=("Consolas", 9))
        self.chat_text.tag_config("error", foreground="#F87171", font=("Segoe UI", 10))
        self.chat_text.tag_config("streaming", foreground="#A78BFA", font=("Segoe UI", 10))
        
        # Input area
        input_frame = ttk.Frame(left_frame)
        input_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Input field
        self.input_var = tk.StringVar()
        self.input_entry = ttk.Entry(
            input_frame,
            textvariable=self.input_var,
            font=("Segoe UI", 11)
        )
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.input_entry.bind("<Return>", lambda e: self._send_message())
        
        # Send button
        self.send_button = ttk.Button(
            input_frame,
            text="📤 Send",
            command=self._send_message,
            bootstyle="primary",
            width=10
        )
        self.send_button.pack(side=tk.RIGHT)
        
        # Quick action buttons
        quick_frame = ttk.Frame(left_frame)
        quick_frame.pack(fill=tk.X, pady=(10, 0))
        
        quick_actions = [
            ("🛡️ Quick Scan", "Run a quick security scan"),
            ("🌐 Network Scan", "Scan local network for devices"),
            ("📊 System Info", "Get system security information"),
            ("🔐 VPN Help", "Help me setup a VPN")
        ]
        
        for text, tooltip in quick_actions:
            btn = ttk.Button(
                quick_frame,
                text=text,
                command=lambda t=text: self._quick_action(t),
                bootstyle="outline",
                width=15
            )
            btn.pack(side=tk.LEFT, padx=(0, 10))
            # Tooltip would be nice but requires additional implementation
        
        # ===== RIGHT PANE - INFO AND CONTROLS =====
        
        # AI Status
        status_frame = ttk.LabelFrame(right_frame, text="AI Status", padding=15)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Ollama status
        self.status_label = ttk.Label(
            status_frame,
            text="Checking Ollama...",
            font=("Segoe UI", 10)
        )
        self.status_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Model info
        self.model_label = ttk.Label(
            status_frame,
            text=f"Model: {self.assistant.model}",
            font=("Segoe UI", 9),
            foreground="#9CA3AF"
        )
        self.model_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Status indicator
        self.status_canvas = tk.Canvas(
            status_frame,
            width=20,
            height=20,
            highlightthickness=0
        )
        self.status_canvas.pack(anchor=tk.W)
        
        # Refresh status button
        ttk.Button(
            status_frame,
            text="🔄 Refresh Status",
            command=self._refresh_ai_status,
            width=15
        ).pack(pady=(10, 0))
        
        # Available Functions
        func_frame = ttk.LabelFrame(right_frame, text="Available Functions", padding=15)
        func_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview for functions
        columns = ("Function", "Description")
        self.functions_tree = ttk.Treeview(
            func_frame,
            columns=columns,
            show="headings",
            height=8
        )
        
        # Configure columns
        self.functions_tree.heading("Function", text="Function", anchor=tk.W)
        self.functions_tree.heading("Description", text="Description", anchor=tk.W)
        self.functions_tree.column("Function", anchor=tk.W, width=100)
        self.functions_tree.column("Description", anchor=tk.W, width=200)
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(func_frame, orient=tk.VERTICAL, command=self.functions_tree.yview)
        self.functions_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack widgets
        self.functions_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load functions
        self._load_functions()
        
        # Conversation Controls
        control_frame = ttk.LabelFrame(right_frame, text="Conversation", padding=15)
        control_frame.pack(fill=tk.X)
        
        # Control buttons
        ttk.Button(
            control_frame,
            text="🗑️ Clear Chat",
            command=self._clear_chat,
            bootstyle="danger",
            width=15
        ).pack(pady=(0, 10))
        
        ttk.Button(
            control_frame,
            text="💾 Export Chat",
            command=self._export_chat,
            width=15
        ).pack(pady=(0, 10))
        
        ttk.Button(
            control_frame,
            text="📋 Copy Last",
            command=self._copy_last_response,
            width=15
        ).pack(pady=(0, 10))
        
        # Conversation stats
        stats_frame = ttk.Frame(control_frame)
        stats_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.stats_label = ttk.Label(
            stats_frame,
            text="Messages: 0 | Tokens: 0",
            font=("Segoe UI", 9),
            foreground="#9CA3AF"
        )
        self.stats_label.pack()
        
        # Initial status check
        self._refresh_ai_status()
    
    def _display_welcome(self):
        """Display welcome message in chat"""
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.delete("1.0", tk.END)
        
        # Display system message
        self._add_message("system", "AI Assistant initialized...")
        
        # Display AI welcome message from conversation history
        if self.assistant.conversation_history:
            for msg in self.assistant.conversation_history:
                if msg.role == "assistant":
                    self._add_message("assistant", msg.content)
                    break
        
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)
        
        # Update stats
        self._update_stats()
    
    def _add_message(self, role: str, content: str, streaming: bool = False):
        """Add a message to the chat display"""
        self.chat_text.config(state=tk.NORMAL)
        
        # Get current position
        position = self.chat_text.index(tk.END)
        
        # Add sender tag
        sender_map = {
            "user": "😊 You",
            "assistant": "🤖 Assistant",
            "system": "⚙️ System",
            "function": "🔧 Function",
            "error": "❌ Error"
        }
        
        sender = sender_map.get(role, role.capitalize())
        
        if streaming:
            tag = "streaming"
            sender = "🤖 Assistant (typing...)"
        else:
            tag = role
        
        self.chat_text.insert(tk.END, f"\n{sender}: ", tag)
        
        # Add content (convert markdown to plain text for display)
        if role in ["assistant", "system"]:
            # Convert markdown to plain text
            try:
                h = html2text.HTML2Text()
                h.ignore_links = False
                h.ignore_images = True
                
                # First markdown to HTML, then HTML to text
                html_content = markdown.markdown(content)
                plain_content = h.handle(html_content)
                
                # Clean up extra newlines
                plain_content = plain_content.strip()
                
                self.chat_text.insert(tk.END, plain_content + "\n")
            except:
                # Fallback to original content
                self.chat_text.insert(tk.END, content + "\n")
        else:
            self.chat_text.insert(tk.END, content + "\n")
        
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)
    
    def _update_streaming_message(self, chunk: str):
        """Update streaming message with new chunk"""
        self.current_stream += chunk
        
        # Remove old streaming message if exists
        self.chat_text.config(state=tk.NORMAL)
        
        # Find and remove previous streaming message
        lines = self.chat_text.get("1.0", tk.END).split('\n')
        for i, line in enumerate(reversed(lines)):
            if "Assistant (typing...)" in line:
                # Calculate position to delete from
                line_num = len(lines) - i
                start_pos = f"{line_num}.0"
                end_pos = f"{line_num + 1}.0"
                self.chat_text.delete(start_pos, end_pos)
                break
        
        self.chat_text.config(state=tk.DISABLED)
        
        # Add updated streaming message
        self._add_message("assistant", self.current_stream, streaming=True)
    
    def _send_message(self):
        """Send user message to AI assistant"""
        message = self.input_var.get().strip()
        if not message or self.is_responding:
            return
        
        # Clear input
        self.input_var.set("")
        
        # Display user message
        self._add_message("user", message)
        
        # Disable input during response
        self.is_responding = True
        self.send_button.config(state=tk.DISABLED)
        self.input_entry.config(state=tk.DISABLED)
        
        # Start streaming indicator
        self.current_stream = ""
        self._add_message("assistant", "", streaming=True)
        
        # Send message in background thread
        thread = threading.Thread(target=self._process_message, args=(message,), daemon=True)
        thread.start()
    
    def _process_message(self, message: str):
        """Process message in background thread"""
        try:
            # Define streaming callback
            def stream_callback(chunk: str):
                self.frame.after(0, self._update_streaming_message, chunk)
            
            # Get AI response
            result = self.assistant.chat(message, stream_callback)
            
            # Remove streaming indicator
            self.frame.after(0, self._finish_response, result)
            
        except Exception as e:
            self.logger.error(f"Message processing failed: {e}")
            self.frame.after(0, self._show_error, str(e))
    
    def _finish_response(self, result: Dict[str, Any]):
        """Finish AI response processing"""
        # Remove streaming message
        self.chat_text.config(state=tk.NORMAL)
        lines = self.chat_text.get("1.0", tk.END).split('\n')
        for i, line in enumerate(reversed(lines)):
            if "Assistant (typing...)" in line:
                line_num = len(lines) - i
                start_pos = f"{line_num}.0"
                end_pos = f"{line_num + 1}.0"
                self.chat_text.delete(start_pos, end_pos)
                break
        self.chat_text.config(state=tk.DISABLED)
        
        if result['success']:
            # Display final AI response
            self._add_message("assistant", result['response'])
            
            # Display function call results if any
            if result.get('function_calls'):
                for func_call, func_result in zip(result['function_calls'], result.get('function_results', [])):
                    if func_result.get('success'):
                        func_display = f"Called {func_call['function']}: {func_result.get('message', 'Success')}"
                        self._add_message("function", func_display)
                    else:
                        error_display = f"Failed {func_call['function']}: {func_result.get('error', 'Unknown error')}"
                        self._add_message("error", error_display)
        else:
            # Display error
            error_msg = f"Error: {result.get('error', 'Unknown error')}"
            self._add_message("error", error_msg)
        
        # Re-enable input
        self.is_responding = False
        self.send_button.config(state=tk.NORMAL)
        self.input_entry.config(state=tk.NORMAL)
        self.input_entry.focus()
        
        # Update stats
        self._update_stats()
    
    def _show_error(self, error_message: str):
        """Show error message"""
        self._add_message("error", f"Error: {error_message}")
        
        # Re-enable input
        self.is_responding = False
        self.send_button.config(state=tk.NORMAL)
        self.input_entry.config(state=tk.NORMAL)
        self.input_entry.focus()
    
    def _quick_action(self, action_text: str):
        """Handle quick action button click"""
        # Map action text to prompts
        action_prompts = {
            "🛡️ Quick Scan": "Run a quick security scan on my system",
            "🌐 Network Scan": "Scan my local network for connected devices",
            "📊 System Info": "Get system security information and status",
            "🔐 VPN Help": "Help me setup a WireGuard VPN"
        }
        
        prompt = action_prompts.get(action_text, action_text)
        self.input_var.set(prompt)
        self._send_message()
    
    def _refresh_ai_status(self):
        """Refresh AI assistant status display"""
        if self.assistant.ollama_available:
            status_text = "✅ Ollama Connected"
            status_color = "#10B981"
            self.status_label.config(text=status_text)
        else:
            status_text = "❌ Ollama Not Available"
            status_color = "#EF4444"
            self.status_label.config(text=status_text + "\n(Local AI features only)")
        
        # Update model label
        self.model_label.config(text=f"Model: {self.assistant.model}")
        
        # Update status indicator
        self.status_canvas.delete("all")
        self.status_canvas.create_oval(2, 2, 18, 18, fill=status_color, outline="")
        
        # Update functions list
        self._load_functions()
    
    def _load_functions(self):
        """Load available functions into treeview"""
        # Clear existing items
        for item in self.functions_tree.get_children():
            self.functions_tree.delete(item)
        
        # Get functions from assistant
        functions = self.assistant.get_available_functions()
        
        # Add to treeview
        for func in functions:
            # Shorten description for display
            desc = func['description']
            if len(desc) > 50:
                desc = desc[:47] + "..."
            
            self.functions_tree.insert(
                "", tk.END,
                values=(func['name'], desc),
                tags=(json.dumps(func['parameters'], indent=2),)
            )
    
    def _clear_chat(self):
        """Clear chat history"""
        if tk.messagebox.askyesno("Clear Chat", "Clear all chat history?"):
            self.assistant.clear_conversation()
            self._display_welcome()
            self.logger.info("Chat cleared")
    
    def _export_chat(self):
        """Export chat to file"""
        from tkinter import filedialog
        
        file_path = filedialog.asksaveasfilename(
            title="Export Chat",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("Markdown files", "*.md"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                # Get conversation summary
                summary = self.assistant.get_conversation_summary()
                
                # Format chat for export
                export_lines = []
                export_lines.append("=" * 60)
                export_lines.append("INDENTURED SERVANT - AI ASSISTANT CHAT EXPORT")
                export_lines.append("=" * 60)
                export_lines.append(f"Export Date: {datetime.now().isoformat()}")
                export_lines.append(f"Model: {self.assistant.model}")
                export_lines.append(f"Total Messages: {summary['total_messages']}")
                export_lines.append(f"Functions Called: {summary['functions_called']}")
                export_lines.append("-" * 60)
                export_lines.append("\n")
                
                # Add conversation
                for msg in self.assistant.conversation_history:
                    if msg.role == "system":
                        continue
                    
                    timestamp = datetime.fromisoformat(msg.timestamp).strftime("%H:%M:%S")
                    sender = msg.role.capitalize()
                    
                    export_lines.append(f"[{timestamp}] {sender}:")
                    export_lines.append(msg.content)
                    export_lines.append("")
                
                # Write to file
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(export_lines))
                
                tk.messagebox.showinfo("Export Successful", f"Chat exported to:\n{file_path}")
                self.logger.info(f"Chat exported to {file_path}")
                
            except Exception as e:
                tk.messagebox.showerror("Export Failed", f"Failed to export chat:\n\n{str(e)}")
                self.logger.error(f"Chat export failed: {e}")
    
    def _copy_last_response(self):
        """Copy last AI response to clipboard"""
        if self.assistant.conversation_history:
            # Find last assistant message
            for msg in reversed(self.assistant.conversation_history):
                if msg.role == "assistant":
                    self.chat_text.clipboard_clear()
                    self.chat_text.clipboard_append(msg.content)
                    tk.messagebox.showinfo("Copy", "Last response copied to clipboard.")
                    return
        
        tk.messagebox.showinfo("Copy", "No response to copy.")
    
    def _update_stats(self):
        """Update conversation statistics"""
        summary = self.assistant.get_conversation_summary()
        
        # Calculate approximate tokens (very rough estimate)
        total_tokens = 0
        for msg in self.assistant.conversation_history:
            total_tokens += len(msg.content.split())  # Words as proxy for tokens
        
        stats_text = f"Messages: {summary['user_messages']} | "
        stats_text += f"Tokens: ~{total_tokens} | "
        stats_text += f"Functions: {summary['functions_called']}"
        
        self.stats_label.config(text=stats_text)
    
    def refresh(self):
        """Refresh AI tab"""
        self._refresh_ai_status()
        self._update_stats()

if __name__ == "__main__":
    # Test the AI tab
    root = tk.Tk()
    root.geometry("1200x700")
    
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)
    
    ai_tab = AITab(notebook)
    notebook.add(ai_tab.frame, text="🤖 AI Assistant")
    
    root.mainloop()
