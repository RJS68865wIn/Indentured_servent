"""
Email Tools Tab - GUI for email configuration and sending
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from src.email_client import EmailClient
from src.secure_config import mask_email, generate_secure_password
from src.utils.logger import setup_logger

class EmailTab:
    """Email Tools tab for configuration and sending"""
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        
        # Initialize email client and logger
        self.client = EmailClient()
        self.logger = setup_logger("EmailGUI")
        
        # State variables
        self.current_attachments = []
        
        # Create widgets
        self._create_widgets()
        
        # Load configured services
        self._refresh_services()
    
    def _create_widgets(self):
        """Create email tab widgets"""
        # Main container with notebook
        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.config_frame = self._create_config_tab()
        self.compose_frame = self._create_compose_tab()
        self.templates_frame = self._create_templates_tab()
        self.history_frame = self._create_history_tab()
        
        self.notebook.add(self.config_frame, text="⚙️ Configuration")
        self.notebook.add(self.compose_frame, text="📝 Compose")
        self.notebook.add(self.templates_frame, text="📋 Templates")
        self.notebook.add(self.history_frame, text="📜 History")
    
    def _create_config_tab(self) -> ttk.Frame:
        """Create email configuration tab"""
        frame = ttk.Frame(self.notebook)
        
        # Services list section
        services_frame = ttk.LabelFrame(frame, text="Configured Email Services", padding=20)
        services_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Treeview for services
        columns = ("Service", "Email", "Status", "Last Used")
        self.services_tree = ttk.Treeview(
            services_frame,
            columns=columns,
            show="headings",
            height=8
        )
        
        # Configure columns
        col_widths = [100, 200, 100, 150]
        for col, width in zip(columns, col_widths):
            self.services_tree.heading(col, text=col, anchor=tk.W)
            self.services_tree.column(col, anchor=tk.W, width=width)
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(services_frame, orient=tk.VERTICAL, command=self.services_tree.yview)
        self.services_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack treeview and scrollbar
        self.services_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Service action buttons
        action_frame = ttk.Frame(services_frame)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            action_frame,
            text="🔄 Test Service",
            command=self._test_selected_service,
            width=15
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            action_frame,
            text="🗑️ Remove Service",
            command=self._remove_selected_service,
            bootstyle="danger",
            width=15
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            action_frame,
            text="🔄 Refresh List",
            command=self._refresh_services,
            width=15
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Service setup section
        setup_frame = ttk.LabelFrame(frame, text="Setup New Email Service", padding=20)
        setup_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        # Service selection
        service_row = ttk.Frame(setup_frame)
        service_row.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(service_row, text="Service:", width=10).pack(side=tk.LEFT)
        
        self.service_var = tk.StringVar(value="gmail")
        services = [
            ("Gmail", "gmail"),
            ("iCloud", "icloud"),
            ("Outlook", "outlook"),
            ("Yahoo", "yahoo"),
            ("Custom SMTP", "custom_smtp")
        ]
        
        service_menu = ttk.OptionMenu(
            service_row,
            self.service_var,
            "gmail",
            *[s[1] for s in services]
        )
        service_menu.pack(side=tk.LEFT, padx=(10, 0))
        
        # Bind service change
        self.service_var.trace('w', self._on_service_changed)
        
        # Email input
        email_row = ttk.Frame(setup_frame)
        email_row.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(email_row, text="Email:", width=10).pack(side=tk.LEFT)
        self.email_var = tk.StringVar()
        email_entry = ttk.Entry(email_row, textvariable=self.email_var, width=30)
        email_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Password input
        password_row = ttk.Frame(setup_frame)
        password_row.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(password_row, text="Password:", width=10).pack(side=tk.LEFT)
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(
            password_row,
            textvariable=self.password_var,
            width=30,
            show="•"
        )
        password_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # App password info button
        ttk.Button(
            password_row,
            text="ℹ️ App Password Info",
            command=self._show_app_password_info,
            width=15
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Custom SMTP fields (initially hidden)
        self.custom_smtp_frame = ttk.Frame(setup_frame)
        
        # Server
        server_row = ttk.Frame(self.custom_smtp_frame)
        server_row.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(server_row, text="SMTP Server:", width=15).pack(side=tk.LEFT)
        self.smtp_server_var = tk.StringVar(value="smtp.example.com")
        server_entry = ttk.Entry(server_row, textvariable=self.smtp_server_var, width=25)
        server_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Port
        port_row = ttk.Frame(self.custom_smtp_frame)
        port_row.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(port_row, text="Port:", width=15).pack(side=tk.LEFT)
        self.smtp_port_var = tk.StringVar(value="587")
        port_entry = ttk.Entry(port_row, textvariable=self.smtp_port_var, width=10)
        port_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # TLS/SSL options
        security_row = ttk.Frame(self.custom_smtp_frame)
        security_row.pack(fill=tk.X, pady=(0, 10))
        
        self.use_tls_var = tk.BooleanVar(value=True)
        tls_check = ttk.Checkbutton(
            security_row,
            text="Use TLS",
            variable=self.use_tls_var
        )
        tls_check.pack(side=tk.LEFT, padx=(0, 20))
        
        self.use_ssl_var = tk.BooleanVar(value=False)
        ssl_check = ttk.Checkbutton(
            security_row,
            text="Use SSL",
            variable=self.use_ssl_var
        )
        ssl_check.pack(side=tk.LEFT)
        
        # Setup button
        ttk.Button(
            setup_frame,
            text="🚀 Configure Service",
            command=self._configure_service,
            bootstyle="success",
            width=20
        ).pack()
        
        # Status display
        self.config_status_label = ttk.Label(
            setup_frame,
            text="",
            font=("Segoe UI", 9)
        )
        self.config_status_label.pack(pady=(10, 0))
        
        return frame
    
    def _create_compose_tab(self) -> ttk.Frame:
        """Create email composition tab"""
        frame = ttk.Frame(self.notebook)
        
        # Compose form
        form_frame = ttk.LabelFrame(frame, text="Compose Email", padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # From selection
        from_row = ttk.Frame(form_frame)
        from_row.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(from_row, text="From:", width=10).pack(side=tk.LEFT)
        
        self.from_service_var = tk.StringVar()
        self.from_service_menu = ttk.OptionMenu(
            from_row,
            self.from_service_var,
            "",
            ""
        )
        self.from_service_menu.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)
        
        # To recipients
        to_row = ttk.Frame(form_frame)
        to_row.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(to_row, text="To:", width=10).pack(side=tk.LEFT)
        self.to_var = tk.StringVar()
        to_entry = ttk.Entry(to_row, textvariable=self.to_var, width=40)
        to_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)
        
        ttk.Label(to_row, text="(comma-separated)").pack(side=tk.LEFT, padx=(5, 0))
        
        # CC recipients
        cc_row = ttk.Frame(form_frame)
        cc_row.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(cc_row, text="CC:", width=10).pack(side=tk.LEFT)
        self.cc_var = tk.StringVar()
        cc_entry = ttk.Entry(cc_row, textvariable=self.cc_var, width=40)
        cc_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)
        
        # BCC recipients
        bcc_row = ttk.Frame(form_frame)
        bcc_row.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(bcc_row, text="BCC:", width=10).pack(side=tk.LEFT)
        self.bcc_var = tk.StringVar()
        bcc_entry = ttk.Entry(bcc_row, textvariable=self.bcc_var, width=40)
        bcc_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)
        
        # Subject
        subject_row = ttk.Frame(form_frame)
        subject_row.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(subject_row, text="Subject:", width=10).pack(side=tk.LEFT)
        self.subject_var = tk.StringVar()
        subject_entry = ttk.Entry(subject_row, textvariable=self.subject_var, width=40)
        subject_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)
        
        # Body type
        body_type_row = ttk.Frame(form_frame)
        body_type_row.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(body_type_row, text="Format:", width=10).pack(side=tk.LEFT)
        
        self.body_type_var = tk.StringVar(value="plain")
        ttk.Radiobutton(
            body_type_row,
            text="Plain Text",
            value="plain",
            variable=self.body_type_var
        ).pack(side=tk.LEFT, padx=(10, 20))
        
        ttk.Radiobutton(
            body_type_row,
            text="HTML",
            value="html",
            variable=self.body_type_var
        ).pack(side=tk.LEFT)
        
        # Email body
        body_frame = ttk.LabelFrame(form_frame, text="Message Body", padding=10)
        body_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        self.body_text = tk.Text(
            body_frame,
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            height=12
        )
        
        # Add scrollbar
        body_scroll = ttk.Scrollbar(body_frame, command=self.body_text.yview)
        self.body_text.configure(yscrollcommand=body_scroll.set)
        
        # Pack body widgets
        self.body_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        body_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Attachments
        attach_frame = ttk.LabelFrame(form_frame, text="Attachments", padding=10)
        attach_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Attachments listbox
        self.attachments_listbox = tk.Listbox(
            attach_frame,
            height=3,
            selectmode=tk.EXTENDED
        )
        self.attachments_listbox.pack(fill=tk.X, pady=(0, 10))
        
        # Attachment buttons
        attach_buttons = ttk.Frame(attach_frame)
        attach_buttons.pack(fill=tk.X)
        
        ttk.Button(
            attach_buttons,
            text="📎 Add Files",
            command=self._add_attachments,
            width=12
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            attach_buttons,
            text="🗑️ Remove",
            command=self._remove_attachments,
            width=12
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            attach_buttons,
            text="🧹 Clear All",
            command=self._clear_attachments,
            width=12
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Send button
        send_frame = ttk.Frame(form_frame)
        send_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.send_button = ttk.Button(
            send_frame,
            text="📤 Send Email",
            command=self._send_email,
            bootstyle="success",
            width=15
        )
        self.send_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Save draft button
        ttk.Button(
            send_frame,
            text="💾 Save Draft",
            command=self._save_draft,
            width=12
        ).pack(side=tk.LEFT, padx=10)
        
        # Clear button
        ttk.Button(
            send_frame,
            text="🗑️ Clear Form",
            command=self._clear_form,
            bootstyle="danger",
            width=12
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Status label
        self.send_status_label = ttk.Label(
            send_frame,
            text="",
            font=("Segoe UI", 9)
        )
        self.send_status_label.pack(side=tk.RIGHT)
        
        # Load configured services into from menu
        self._update_from_menu()
        
        return frame
    
    def _create_templates_tab(self) -> ttk.Frame:
        """Create email templates tab"""
        frame = ttk.Frame(self.notebook)
        
        # Templates section
        templates_frame = ttk.LabelFrame(frame, text="Email Templates", padding=20)
        templates_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Template list
        list_frame = ttk.Frame(templates_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Treeview for templates
        columns = ("Name", "Subject", "Last Modified")
        self.templates_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            height=10
        )
        
        # Configure columns
        col_widths = [150, 250, 150]
        for col, width in zip(columns, col_widths):
            self.templates_tree.heading(col, text=col, anchor=tk.W)
            self.templates_tree.column(col, anchor=tk.W, width=width)
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.templates_tree.yview)
        self.templates_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack widgets
        self.templates_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add default templates
        self._add_default_templates()
        
        # Template preview
        preview_frame = ttk.LabelFrame(templates_frame, text="Template Preview", padding=15)
        preview_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.template_preview_text = tk.Text(
            preview_frame,
            height=8,
            font=("Consolas", 9),
            wrap=tk.WORD,
            bg="#1F2937",
            fg="white",
            relief=tk.FLAT
        )
        self.template_preview_text.pack(fill=tk.X)
        self.template_preview_text.insert("1.0", "Select a template to preview.")
        self.template_preview_text.config(state=tk.DISABLED)
        
        # Template actions
        action_frame = ttk.Frame(templates_frame)
        action_frame.pack(fill=tk.X)
        
        ttk.Button(
            action_frame,
            text="📝 Use Template",
            command=self._use_template,
            width=15
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            action_frame,
            text="➕ New Template",
            command=self._new_template,
            width=15
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            action_frame,
            text="✏️ Edit Template",
            command=self._edit_template,
            width=15
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            action_frame,
            text="🗑️ Delete Template",
            command=self._delete_template,
            bootstyle="danger",
            width=15
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Bind tree selection
        self.templates_tree.bind("<<TreeviewSelect>>", self._on_template_selected)
        
        return frame
    
    def _create_history_tab(self) -> ttk.Frame:
        """Create email history tab"""
        frame = ttk.Frame(self.notebook)
        
        # History section
        history_frame = ttk.LabelFrame(frame, text="Email History", padding=20)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Treeview for history
        columns = ("Date", "Service", "To", "Subject", "Status")
        self.history_tree = ttk.Treeview(
            history_frame,
            columns=columns,
            show="headings",
            height=15
        )
        
        # Configure columns
        col_widths = [150, 100, 150, 200, 100]
        for col, width in zip(columns, col_widths):
            self.history_tree.heading(col, text=col, anchor=tk.W)
            self.history_tree.column(col, anchor=tk.W, width=width)
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack widgets
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Action buttons
        action_frame = ttk.Frame(history_frame)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            action_frame,
            text="🔄 Refresh",
            command=self._load_history,
            width=12
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            action_frame,
            text="📋 Copy Details",
            command=self._copy_history_details,
            width=12
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            action_frame,
            text="🗑️ Clear History",
            command=self._clear_history,
            bootstyle="danger",
            width=12
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Load initial history
        self._load_history()
        
        return frame
    
    # ===== CONFIGURATION TAB METHODS =====
    
    def _on_service_changed(self, *args):
        """Handle service selection change"""
        service = self.service_var.get()
        
        if service == "custom_smtp":
            self.custom_smtp_frame.pack(fill=tk.X, pady=(15, 0))
        else:
            self.custom_smtp_frame.pack_forget()
    
    def _show_app_password_info(self):
        """Show app password instructions"""
        service = self.service_var.get()
        instructions = self.client.get_app_password_instructions(service)
        
        # Create info window
        info_window = tk.Toplevel(self.frame)
        info_window.title(f"{service.capitalize()} App Password Instructions")
        info_window.geometry("600x400")
        info_window.transient(self.frame)
        info_window.grab_set()
        
        # Text widget for instructions
        text_widget = tk.Text(
            info_window,
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            padx=10,
            pady=10
        )
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        # Insert instructions
        text_widget.insert("1.0", instructions)
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(
            info_window,
            text="Close",
            command=info_window.destroy,
            width=15
        ).pack(pady=10)
    
    def _configure_service(self):
        """Configure email service"""
        service = self.service_var.get()
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        
        # Validate inputs
        if not email or '@' not in email:
            self._show_config_status("❌ Please enter a valid email address.", "error")
            return
        
        if not password:
            self._show_config_status("❌ Please enter a password.", "error")
            return
        
        # Prepare custom config for custom SMTP
        custom_config = None
        if service == "custom_smtp":
            server = self.smtp_server_var.get().strip()
            port_str = self.smtp_port_var.get().strip()
            
            if not server:
                self._show_config_status("❌ Please enter SMTP server.", "error")
                return
            
            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    raise ValueError
            except ValueError:
                self._show_config_status("❌ Please enter a valid port number.", "error")
                return
            
            custom_config = {
                'server': server,
                'port': port,
                'use_tls': self.use_tls_var.get(),
                'use_ssl': self.use_ssl_var.get()
            }
        
        # Update status
        self._show_config_status("Configuring service...", "info")
        
        # Configure in background thread
        thread = threading.Thread(
            target=self._configure_service_thread,
            args=(service, email, password, custom_config),
            daemon=True
        )
        thread.start()
    
    def _configure_service_thread(self, service: str, email: str, password: str, custom_config: Dict[str, Any]):
        """Configure service in background thread"""
        try:
            result = self.client.configure_email_service(service, email, password, custom_config)
            
            if result['success']:
                self.frame.after(0, lambda: self._show_config_status(
                    f"✅ {service.capitalize()} configured successfully!",
                    "success"
                ))
                self.frame.after(0, self._refresh_services)
                self.frame.after(0, self._update_from_menu)
                
                # Clear password field
                self.frame.after(0, lambda: self.password_var.set(""))
            else:
                self.frame.after(0, lambda: self._show_config_status(
                    f"❌ Configuration failed: {result.get('error', 'Unknown error')}",
                    "error"
                ))
                
        except Exception as e:
            self.frame.after(0, lambda: self._show_config_status(
                f"❌ Error: {str(e)}",
                "error"
            ))
    
    def _show_config_status(self, message: str, status_type: str):
        """Show configuration status"""
        colors = {
            "success": "#10B981",
            "error": "#EF4444",
            "info": "#3B82F6"
        }
        
        self.config_status_label.config(
            text=message,
            foreground=colors.get(status_type, "#6B7280")
        )
    
    def _refresh_services(self):
        """Refresh configured services list"""
        # Clear existing items
        for item in self.services_tree.get_children():
            self.services_tree.delete(item)
        
        # Get configured services
        services = self.client.get_configured_services()
        
        # Add to treeview
        for service in services:
            self.services_tree.insert(
                "", tk.END,
                values=(
                    service['service'].capitalize(),
                    service['email'],
                    service['status'].capitalize(),
                    service['last_used']
                ),
                tags=(service['service'],)
            )
    
    def _test_selected_service(self):
        """Test selected email service"""
        selection = self.services_tree.selection()
        if not selection:
            messagebox.showinfo("Test Service", "Please select a service to test.")
            return
        
        item = self.services_tree.item(selection[0])
        service = item['tags'][0]
        
        # Show testing message
        self._show_config_status(f"Testing {service} connection...", "info")
        
        # Test in background thread
        thread = threading.Thread(
            target=self._test_service_thread,
            args=(service,),
            daemon=True
        )
        thread.start()
    
    def _test_service_thread(self, service: str):
        """Test service in background thread"""
        try:
            result = self.client.test_service(service)
            
            if result['success']:
                self.frame.after(0, lambda: messagebox.showinfo(
                    "Test Successful",
                    f"{service.capitalize()} connection test successful!"
                ))
                self.frame.after(0, self._refresh_services)
                self.frame.after(0, lambda: self._show_config_status("", "info"))
            else:
                self.frame.after(0, lambda: messagebox.showerror(
                    "Test Failed",
                    f"Connection test failed:\n\n{result.get('error', 'Unknown error')}"
                ))
                
        except Exception as e:
            self.frame.after(0, lambda: messagebox.showerror(
                "Test Error",
                f"Error testing service: {str(e)}"
            ))
    
    def _remove_selected_service(self):
        """Remove selected email service"""
        selection = self.services_tree.selection()
        if not selection:
            messagebox.showinfo("Remove Service", "Please select a service to remove.")
            return
        
        item = self.services_tree.item(selection[0])
        service = item['tags'][0]
        email = item['values'][1]
        
        if messagebox.askyesno(
            "Remove Service",
            f"Remove {service} configuration for {email}?\n\nThis will delete stored credentials."
        ):
            result = self.client.remove_service(service)
            
            if result['success']:
                messagebox.showinfo("Service Removed", result['message'])
                self._refresh_services()
                self._update_from_menu()
            else:
                messagebox.showerror("Remove Failed", result.get('error', 'Unknown error'))
    
    def _update_from_menu(self):
        """Update 'From' dropdown with configured services"""
        services = self.client.get_configured_services()
        
        if not services:
            self.from_service_var.set("")
            self.from_service_menu.set_menu("", "")
            return
        
        # Build menu values
        menu_values = []
        for service in services:
            display = f"{service['service'].capitalize()} ({service['email']})"
            menu_values.append((display, service['service']))
        
        # Update menu
        self.from_service_menu.set_menu(menu_values[0][0], *[v[0] for v in menu_values])
        self.from_service_var.set(menu_values[0][1])
    
    # ===== COMPOSE TAB METHODS =====
    
    def _add_attachments(self):
        """Add file attachments"""
        files = filedialog.askopenfilenames(
            title="Select Files to Attach",
            filetypes=[
                ("All files", "*.*"),
                ("Text files", "*.txt"),
                ("PDF files", "*.pdf"),
                ("Image files", "*.png *.jpg *.jpeg *.gif"),
                ("Document files", "*.doc *.docx *.xls *.xlsx *.ppt *.pptx")
            ]
        )
        
        for file in files:
            if file not in self.current_attachments:
                self.current_attachments.append(file)
                self.attachments_listbox.insert(tk.END, Path(file).name)
    
    def _remove_attachments(self):
        """Remove selected attachments"""
        selected = self.attachments_listbox.curselection()
        for index in reversed(selected):
            self.current_attachments.pop(index)
            self.attachments_listbox.delete(index)
    
    def _clear_attachments(self):
        """Clear all attachments"""
        self.current_attachments.clear()
        self.attachments_listbox.delete(0, tk.END)
    
    def _send_email(self):
        """Send email"""
        # Validate inputs
        service = self.from_service_var.get()
        if not service:
            messagebox.showwarning("Send Email", "Please select a 'From' service.")
            return
        
        to_emails = self.to_var.get().strip()
        if not to_emails:
            messagebox.showwarning("Send Email", "Please enter at least one recipient.")
            return
        
        subject = self.subject_var.get().strip()
        if not subject:
            messagebox.showwarning("Send Email", "Please enter a subject.")
            return
        
        body = self.body_text.get("1.0", tk.END).strip()
        if not body:
            messagebox.showwarning("Send Email", "Please enter a message body.")
            return
        
        # Parse recipients
        to_list = [e.strip() for e in to_emails.split(',')]
        cc_list = [e.strip() for e in self.cc_var.get().split(',') if e.strip()]
        bcc_list = [e.strip() for e in self.bcc_var.get().split(',') if e.strip()]
        
        # Validate email addresses
        for email_list, field_name in [(to_list, "To"), (cc_list, "CC"), (bcc_list, "BCC")]:
            for email in email_list:
                if '@' not in email:
                    messagebox.showwarning("Send Email", f"Invalid email address in {field_name}: {email}")
                    return
        
        # Update UI
        self.send_button.config(state=tk.DISABLED)
        self._update_send_status("Sending email...", "info")
        
        # Send in background thread
        thread = threading.Thread(
            target=self._send_email_thread,
            args=(service, to_list, subject, body, cc_list, bcc_list),
            daemon=True
        )
        thread.start()
    
    def _send_email_thread(self, 
                          service: str, 
                          to_list: List[str], 
                          subject: str, 
                          body: str,
                          cc_list: List[str],
                          bcc_list: List[str]):
        """Send email in background thread"""
        try:
            result = self.client.send_email(
                to_emails=to_list,
                subject=subject,
                body=body,
                service=service,
                cc_emails=cc_list if cc_list else None,
                bcc_emails=bcc_list if bcc_list else None,
                attachments=self.current_attachments,
                body_type=self.body_type_var.get()
            )
            
            if result['success']:
                self.frame.after(0, lambda: self._update_send_status(
                    f"✅ Email sent successfully!",
                    "success"
                ))
                
                # Clear form
                self.frame.after(0, self._clear_form)
                
                # Add to history
                self.frame.after(0, self._add_to_history, result)
                
                # Show success message
                self.frame.after(0, lambda: messagebox.showinfo(
                    "Email Sent",
                    f"Email sent to {len(to_list)} recipient(s)."
                ))
            else:
                self.frame.after(0, lambda: self._update_send_status(
                    f"❌ Failed to send email",
                    "error"
                ))
                
                error_msg = result.get('error', 'Unknown error')
                self.frame.after(0, lambda: messagebox.showerror(
                    "Send Failed",
                    f"Failed to send email:\n\n{error_msg}"
                ))
                
        except Exception as e:
            self.frame.after(0, lambda: self._update_send_status(
                f"❌ Error: {str(e)}",
                "error"
            ))
            
            self.frame.after(0, lambda: messagebox.showerror(
                "Send Error",
                f"Error sending email: {str(e)}"
            ))
        finally:
            self.frame.after(0, lambda: self.send_button.config(state=tk.NORMAL))
    
    def _update_send_status(self, message: str, status_type: str):
        """Update send status"""
        colors = {
            "success": "#10B981",
            "error": "#EF4444",
            "info": "#3B82F6"
        }
        
        self.send_status_label.config(
            text=message,
            foreground=colors.get(status_type, "#6B7280")
        )
    
    def _save_draft(self):
        """Save email as draft"""
        # Placeholder for draft saving functionality
        messagebox.showinfo("Save Draft", "Draft saving will be implemented.")
    
    def _clear_form(self):
        """Clear email composition form"""
        self.to_var.set("")
        self.cc_var.set("")
        self.bcc_var.set("")
        self.subject_var.set("")
        self.body_text.delete("1.0", tk.END)
        self._clear_attachments()
        self._update_send_status("", "info")
    
    # ===== TEMPLATES TAB METHODS =====
    
    def _add_default_templates(self):
        """Add default email templates"""
        templates = [
            ("Security Alert", "🚨 Security Alert - Immediate Action Required", """
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
<h2 style="color: #dc3545;">🚨 Security Alert</h2>
<p><strong>System:</strong> {system_name}</p>
<p><strong>Time:</strong> {timestamp}</p>
<p><strong>Alert Level:</strong> {alert_level}</p>

<h3>Issue Detected:</h3>
<p>{issue_description}</p>

<h3>Recommended Actions:</h3>
<ol>
<li>Review the security report</li>
<li>Run a full system scan</li>
<li>Update security software</li>
<li>Change passwords if necessary</li>
</ol>

<p>This alert was generated by Indentured Servant Cybersecurity Assistant.</p>
</body>
</html>
            """),
            
            ("Scan Report", "📊 Security Scan Report - {system_name}", """
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
<h2 style="color: #28a745;">📊 Security Scan Report</h2>
<p><strong>System:</strong> {system_name}</p>
<p><strong>Scan Date:</strong> {scan_date}</p>
<p><strong>Scan Type:</strong> {scan_type}</p>

<h3>Results Summary:</h3>
<ul>
<li><strong>Security Score:</strong> {security_score}/100</li>
<li><strong>Threats Found:</strong> {threats_count}</li>
<li><strong>Warnings:</strong> {warnings_count}</li>
<li><strong>Scan Duration:</strong> {scan_duration}</li>
</ul>

<h3>Key Findings:</h3>
<p>{key_findings}</p>

<h3>Recommendations:</h3>
<ol>
{recommendations}
</ol>

<p>Review the full report in Indentured Servant for detailed information.</p>
</body>
</html>
            """),
            
            ("Weekly Report", "📈 Weekly Security Report - {week_date}", """
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
<h2 style="color: #007bff;">📈 Weekly Security Report</h2>
<p><strong>Report Period:</strong> {week_date}</p>
<p><strong>System:</strong> {system_name}</p>

<h3>Weekly Summary:</h3>
<ul>
<li><strong>Scans Performed:</strong> {scan_count}</li>
<li><strong>Total Threats Detected:</strong> {total_threats}</li>
<li><strong>Average Security Score:</strong> {avg_score}/100</li>
<li><strong>VPN Connections:</strong> {vpn_connections}</li>
<li><strong>Security Alerts Sent:</strong> {alerts_sent}</li>
</ul>

<h3>Top Issues:</h3>
<ol>
{top_issues}
</ol>

<h3>Weekly Recommendations:</h3>
<ol>
{weekly_recommendations}
</ol>

<p>Stay vigilant and maintain good security practices.</p>
</body>
</html>
            """)
        ]
        
        for name, subject, body in templates:
            self.templates_tree.insert(
                "", tk.END,
                values=(name, subject, datetime.now().strftime("%Y-%m-%d")),
                tags=(body,)
            )
    
    def _on_template_selected(self, event):
        """Handle template selection"""
        selection = self.templates_tree.selection()
        if not selection:
            return
        
        item = self.templates_tree.item(selection[0])
        body = item['tags'][0] if item['tags'] else ""
        
        # Update preview
        self.template_preview_text.config(state=tk.NORMAL)
        self.template_preview_text.delete("1.0", tk.END)
        self.template_preview_text.insert("1.0", body.strip())
        self.template_preview_text.config(state=tk.DISABLED)
    
    def _use_template(self):
        """Use selected template"""
        selection = self.templates_tree.selection()
        if not selection:
            messagebox.showinfo("Use Template", "Please select a template.")
            return
        
        item = self.templates_tree.item(selection[0])
        subject = item['values'][1]
        body = item['tags'][0] if item['tags'] else ""
        
        # Switch to compose tab
        self.notebook.select(self.compose_frame)
        
        # Set subject and body
        self.subject_var.set(subject)
        self.body_text.delete("1.0", tk.END)
        self.body_text.insert("1.0", body.strip())
        
        # Set to HTML format
        self.body_type_var.set("html")
    
    def _new_template(self):
        """Create new template"""
        # Open template editor
        self._open_template_editor()
    
    def _edit_template(self):
        """Edit selected template"""
        selection = self.templates_tree.selection()
        if not selection:
            messagebox.showinfo("Edit Template", "Please select a template to edit.")
            return
        
        item = self.templates_tree.item(selection[0])
        name = item['values'][0]
        subject = item['values'][1]
        body = item['tags'][0] if item['tags'] else ""
        
        # Open template editor with existing data
        self._open_template_editor(name, subject, body)
    
    def _delete_template(self):
        """Delete selected template"""
        selection = self.templates_tree.selection()
        if not selection:
            messagebox.showinfo("Delete Template", "Please select a template to delete.")
            return
        
        item = self.templates_tree.item(selection[0])
        name = item['values'][0]
        
        if messagebox.askyesno("Delete Template", f"Delete template '{name}'?"):
            self.templates_tree.delete(selection[0])
    
    def _open_template_editor(self, name: str = "", subject: str = "", body: str = ""):
        """Open template editor window"""
        editor = tk.Toplevel(self.frame)
        editor.title("Template Editor" if not name else f"Edit Template: {name}")
        editor.geometry("600x500")
        editor.transient(self.frame)
        editor.grab_set()
        
        # Name field
        name_frame = ttk.Frame(editor, padding=10)
        name_frame.pack(fill=tk.X)
        
        ttk.Label(name_frame, text="Template Name:", width=15).pack(side=tk.LEFT)
        name_var = tk.StringVar(value=name)
        name_entry = ttk.Entry(name_frame, textvariable=name_var, width=30)
        name_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Subject field
        subject_frame = ttk.Frame(editor, padding=10)
        subject_frame.pack(fill=tk.X)
        
        ttk.Label(subject_frame, text="Subject:", width=15).pack(side=tk.LEFT)
        subject_var = tk.StringVar(value=subject)
        subject_entry = ttk.Entry(subject_frame, textvariable=subject_var, width=40)
        subject_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Body field
        body_frame = ttk.LabelFrame(editor, text="Template Body", padding=10)
        body_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        body_text = tk.Text(body_frame, font=("Consolas", 10), wrap=tk.WORD)
        body_text.pack(fill=tk.BOTH, expand=True)
        body_text.insert("1.0", body)
        
        # Buttons
        button_frame = ttk.Frame(editor, padding=10)
        button_frame.pack(fill=tk.X)
        
        def save_template():
            new_name = name_var.get().strip()
            new_subject = subject_var.get().strip()
            new_body = body_text.get("1.0", tk.END).strip()
            
            if not new_name:
                messagebox.showwarning("Save Template", "Please enter a template name.")
                return
            
            # Add or update template
            if name:  # Editing existing
                # Find and update existing item
                for item_id in self.templates_tree.get_children():
                    item = self.templates_tree.item(item_id)
                    if item['values'][0] == name:
                        self.templates_tree.item(item_id, values=(new_name, new_subject, datetime.now().strftime("%Y-%m-%d")), tags=(new_body,))
                        break
            else:  # New template
                self.templates_tree.insert(
                    "", tk.END,
                    values=(new_name, new_subject, datetime.now().strftime("%Y-%m-%d")),
                    tags=(new_body,)
                )
            
            editor.destroy()
            messagebox.showinfo("Template Saved", f"Template '{new_name}' saved successfully.")
        
        ttk.Button(
            button_frame,
            text="💾 Save Template",
            command=save_template,
            bootstyle="success",
            width=15
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame,
            text="❌ Cancel",
            command=editor.destroy,
            width=15
        ).pack(side=tk.LEFT)
    
    # ===== HISTORY TAB METHODS =====
    
    def _load_history(self):
        """Load email history"""
        # Placeholder - would load from file/database
        # For now, just clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Add some example history items
        example_history = [
            ("2024-01-15 14:30", "Gmail", "user@example.com", "Security Scan Report", "✅ Sent"),
            ("2024-01-14 10:15", "iCloud", "admin@test.com", "Weekly Security Update", "✅ Sent"),
            ("2024-01-13 16:45", "Gmail", "team@company.com", "Urgent: Threat Detected", "✅ Sent"),
        ]
        
        for date, service, to, subject, status in example_history:
            self.history_tree.insert(
                "", tk.END,
                values=(date, service, to, subject, status)
            )
    
    def _add_to_history(self, email_result: Dict[str, Any]):
        """Add sent email to history"""
        timestamp = email_result.get('timestamp', datetime.now().isoformat())
        service = email_result.get('service', 'Unknown')
        to_emails = email_result.get('to', [])
        subject = email_result.get('subject', 'No Subject')
        
        # Format date
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            date_str = dt.strftime("%Y-%m-%d %H:%M")
        except:
            date_str = timestamp
        
        # Add to treeview
        self.history_tree.insert(
            "", 0,  # Insert at beginning
            values=(
                date_str,
                service.capitalize(),
                ', '.join(to_emails[:2]) + ('...' if len(to_emails) > 2 else ''),
                subject[:50] + ('...' if len(subject) > 50 else ''),
                "✅ Sent"
            ),
            tags=(email_result,)
        )
    
    def _copy_history_details(self):
        """Copy selected history details to clipboard"""
        selection = self.history_tree.selection()
        if not selection:
            return
        
        item = self.history_tree.item(selection[0])
        details = '\t'.join(map(str, item['values']))
        
        self.history_tree.clipboard_clear()
        self.history_tree.clipboard_append(details)
        messagebox.showinfo("Copy", "History details copied to clipboard.")
    
    def _clear_history(self):
        """Clear email history"""
        if messagebox.askyesno("Clear History", "Clear all email history?"):
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)
    
    def refresh(self):
        """Refresh email tab"""
        self._refresh_services()
        self._update_from_menu()
        self._load_history()

if __name__ == "__main__":
    # Test the email tab
    root = tk.Tk()
    root.geometry("1200x700")
    
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)
    
    email_tab = EmailTab(notebook)
    notebook.add(email_tab.frame, text="Email Tools")
    
    root.mainloop()
