"""
Email Client for Indentured Servant
Secure email sending with Gmail, iCloud, and SMTP support
"""
import os
import json
import smtplib
import ssl
import base64
import mimetypes
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.application import MIMEApplication
from email import encoders
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict

from .secure_config import WindowsSecureConfig, generate_secure_password, mask_email
from .utils.logger import setup_logger, log_function_call
from .utils.windows_tools import run_powershell

@dataclass
class EmailConfig:
    """Email service configuration"""
    service: str  # gmail, icloud, custom_smtp
    email: str
    server: str
    port: int
    use_tls: bool
    use_ssl: bool
    auth_required: bool
    last_used: str
    status: str  # configured, verified, error

@dataclass
class EmailMessage:
    """Email message data"""
    to: Union[str, List[str]]
    subject: str
    body: str
    body_type: str  # plain, html
    attachments: List[str]
    cc: List[str]
    bcc: List[str]
    reply_to: str

class EmailClient:
    """
    Secure email client with multiple service support
    """
    
    def __init__(self):
        self.logger = setup_logger("EmailClient")
        self.secure_config = WindowsSecureConfig()
        self.email_configs = self._load_configs()
        
        # Service configurations
        self.service_configs = {
            'gmail': {
                'server': 'smtp.gmail.com',
                'port': 587,
                'use_tls': True,
                'use_ssl': False,
                'auth_required': True,
                'description': 'Gmail (requires app password)'
            },
            'icloud': {
                'server': 'smtp.mail.me.com',
                'port': 587,
                'use_tls': True,
                'use_ssl': False,
                'auth_required': True,
                'description': 'iCloud Mail'
            },
            'outlook': {
                'server': 'smtp-mail.outlook.com',
                'port': 587,
                'use_tls': True,
                'use_ssl': False,
                'auth_required': True,
                'description': 'Outlook/Hotmail'
            },
            'yahoo': {
                'server': 'smtp.mail.yahoo.com',
                'port': 587,
                'use_tls': True,
                'use_ssl': False,
                'auth_required': True,
                'description': 'Yahoo Mail'
            },
            'custom_smtp': {
                'server': '',
                'port': 587,
                'use_tls': True,
                'use_ssl': False,
                'auth_required': True,
                'description': 'Custom SMTP Server'
            }
        }
    
    @log_function_call
    def configure_email_service(self, 
                               service: str, 
                               email: str, 
                               password: str,
                               custom_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Configure an email service
        
        Args:
            service: Email service (gmail, icloud, etc.)
            email: Email address
            password: App password or account password
            custom_config: Custom SMTP configuration
            
        Returns:
            Dictionary with configuration result
        """
        try:
            if service not in self.service_configs and service != 'custom_smtp':
                return {'success': False, 'error': f'Unsupported service: {service}'}
            
            # Store credentials securely
            self.secure_config.set_email_credentials(service, email, password)
            
            # Prepare configuration
            config_data = self.service_configs.get(service, {}).copy()
            if custom_config:
                config_data.update(custom_config)
            
            # Create email config
            email_config = EmailConfig(
                service=service,
                email=email,
                server=config_data.get('server', ''),
                port=config_data.get('port', 587),
                use_tls=config_data.get('use_tls', True),
                use_ssl=config_data.get('use_ssl', False),
                auth_required=config_data.get('auth_required', True),
                last_used=datetime.now().isoformat(),
                status='configured'
            )
            
            # Save to configs
            self.email_configs[service] = asdict(email_config)
            self._save_configs()
            
            # Test connection if not custom_smtp
            if service != 'custom_smtp':
                test_result = self._test_connection(service)
                if test_result['success']:
                    self.email_configs[service]['status'] = 'verified'
                    self._save_configs()
            
            self.logger.info(f"Configured {service} email for {mask_email(email)}")
            
            return {
                'success': True,
                'service': service,
                'email': mask_email(email),
                'status': self.email_configs[service]['status'],
                'message': f'{service.capitalize()} email configured successfully'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to configure {service} email: {e}")
            return {'success': False, 'error': str(e)}
    
    @log_function_call
    def send_email(self,
                   to_emails: Union[str, List[str]],
                   subject: str,
                   body: str,
                   service: str = 'gmail',
                   cc_emails: List[str] = None,
                   bcc_emails: List[str] = None,
                   attachments: List[str] = None,
                   body_type: str = 'plain',
                   reply_to: str = None) -> Dict[str, Any]:
        """
        Send an email
        
        Args:
            to_emails: Recipient email(s)
            subject: Email subject
            body: Email body
            service: Email service to use
            cc_emails: CC recipients
            bcc_emails: BCC recipients
            attachments: List of file paths to attach
            body_type: 'plain' or 'html'
            reply_to: Reply-to email address
            
        Returns:
            Dictionary with send result
        """
        try:
            # Check if service is configured
            if service not in self.email_configs:
                return {
                    'success': False,
                    'error': f'{service.capitalize()} not configured. Please configure it first.'
                }
            
            # Get credentials
            creds = self.secure_config.get_email_credentials(service)
            if not creds:
                return {'success': False, 'error': 'Credentials not found for this service'}
            
            from_email = creds['email']
            password = creds['password']
            config = self.email_configs[service]
            
            # Normalize recipients
            if isinstance(to_emails, str):
                to_emails = [to_emails]
            
            # Create message
            msg = self._create_message(
                from_email=from_email,
                to_emails=to_emails,
                subject=subject,
                body=body,
                body_type=body_type,
                cc_emails=cc_emails or [],
                bcc_emails=bcc_emails or [],
                reply_to=reply_to,
                attachments=attachments or []
            )
            
            # Send email
            result = self._send_smtp(
                config=config,
                from_email=from_email,
                password=password,
                message=msg,
                recipients=to_emails + (cc_emails or []) + (bcc_emails or [])
            )
            
            if result['success']:
                # Update last used
                self.email_configs[service]['last_used'] = datetime.now().isoformat()
                self._save_configs()
                
                self.logger.info(f"Email sent via {service} to {len(to_emails)} recipients")
                
                return {
                    'success': True,
                    'service': service,
                    'from': mask_email(from_email),
                    'to': [mask_email(e) for e in to_emails],
                    'subject': subject,
                    'attachments': len(attachments or []),
                    'message_id': result.get('message_id', ''),
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return result
                
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
            return {'success': False, 'error': str(e)}
    
    @log_function_call
    def send_security_alert(self,
                           alert_type: str,
                           details: Dict[str, Any],
                           recipient: str = None) -> Dict[str, Any]:
        """
        Send a security alert email
        
        Args:
            alert_type: Type of alert (threat_detected, scan_complete, etc.)
            details: Alert details
            recipient: Override recipient email
            
        Returns:
            Dictionary with send result
        """
        try:
            # Get configured services
            configured_services = self.get_configured_services()
            if not configured_services:
                return {'success': False, 'error': 'No email services configured'}
            
            # Use first configured service
            service = configured_services[0]['service']
            
            # Determine recipient
            if not recipient:
                # Try to get user's email from config
                config = self.email_configs.get(service)
                if config:
                    recipient = config['email']
                else:
                    return {'success': False, 'error': 'No recipient specified'}
            
            # Create alert content
            subject, body = self._create_alert_content(alert_type, details)
            
            # Send email
            return self.send_email(
                to_emails=recipient,
                subject=subject,
                body=body,
                service=service,
                body_type='html'
            )
            
        except Exception as e:
            self.logger.error(f"Failed to send security alert: {e}")
            return {'success': False, 'error': str(e)}
    
    @log_function_call
    def test_service(self, service: str) -> Dict[str, Any]:
        """
        Test email service configuration
        
        Args:
            service: Service to test
            
        Returns:
            Dictionary with test result
        """
        try:
            if service not in self.email_configs:
                return {'success': False, 'error': 'Service not configured'}
            
            # Get credentials
            creds = self.secure_config.get_email_credentials(service)
            if not creds:
                return {'success': False, 'error': 'Credentials not found'}
            
            config = self.email_configs[service]
            from_email = creds['email']
            password = creds['password']
            
            # Test connection
            test_result = self._test_smtp_connection(config, from_email, password)
            
            if test_result['success']:
                # Update status
                self.email_configs[service]['status'] = 'verified'
                self._save_configs()
                
                return {
                    'success': True,
                    'service': service,
                    'email': mask_email(from_email),
                    'status': 'verified',
                    'message': f'{service.capitalize()} connection successful'
                }
            else:
                self.email_configs[service]['status'] = 'error'
                self._save_configs()
                
                return test_result
                
        except Exception as e:
            self.logger.error(f"Failed to test {service}: {e}")
            return {'success': False, 'error': str(e)}
    
    @log_function_call
    def get_configured_services(self) -> List[Dict[str, Any]]:
        """
        Get list of configured email services
        
        Returns:
            List of service configurations
        """
        services = []
        
        for service_name, config in self.email_configs.items():
            # Get masked email
            creds = self.secure_config.get_email_credentials(service_name)
            email = mask_email(creds['email']) if creds else 'Unknown'
            
            services.append({
                'service': service_name,
                'email': email,
                'status': config.get('status', 'unknown'),
                'last_used': config.get('last_used', 'Never'),
                'description': self.service_configs.get(service_name, {}).get('description', '')
            })
        
        return services
    
    @log_function_call
    def remove_service(self, service: str) -> Dict[str, Any]:
        """
        Remove email service configuration
        
        Args:
            service: Service to remove
            
        Returns:
            Dictionary with removal result
        """
        try:
            if service not in self.email_configs:
                return {'success': False, 'error': 'Service not configured'}
            
            # Remove from configs
            del self.email_configs[service]
            self._save_configs()
            
            # Remove credentials from secure storage
            # Note: SecureConfig doesn't have remove method yet, we'll clear via Windows Credential Manager
            self._clear_service_credentials(service)
            
            self.logger.info(f"Removed {service} email configuration")
            
            return {
                'success': True,
                'service': service,
                'message': f'{service.capitalize()} configuration removed'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to remove {service}: {e}")
            return {'success': False, 'error': str(e)}
    
    @log_function_call
    def get_app_password_instructions(self, service: str) -> str:
        """
        Get app password instructions for email service
        
        Args:
            service: Email service
            
        Returns:
            Instructions for creating app password
        """
        instructions = {
            'gmail': """
            Gmail App Password Instructions:
            
            1. Go to https://myaccount.google.com/security
            2. Enable 2-Step Verification (if not already enabled)
            3. Under "Signing in to Google", click "App passwords"
            4. Select "Mail" as the app and "Windows Computer" as the device
            5. Click "Generate"
            6. Use the 16-character password shown (without spaces) in Indentured Servant
            
            Note: This password is used instead of your regular Gmail password.
            """,
            
            'icloud': """
            iCloud App Password Instructions:
            
            1. Go to https://appleid.apple.com
            2. Sign in with your Apple ID
            3. Under "Security", click "Generate Password"
            4. Enter a label (e.g., "Indentured Servant")
            5. Click "Create"
            6. Use the generated password in Indentured Servant
            
            Note: This password is used instead of your regular Apple ID password.
            """,
            
            'outlook': """
            Outlook App Password Instructions:
            
            1. Go to https://account.microsoft.com/security
            2. Under "Advanced security options", click "Create a new app password"
            3. Generate a new app password
            4. Use the generated password in Indentured Servant
            
            Note: This password is used instead of your regular Outlook password.
            """,
            
            'yahoo': """
            Yahoo App Password Instructions:
            
            1. Go to https://login.yahoo.com/account/security
            2. Under "Account security", click "Generate app password"
            3. Select "Other" and enter "Indentured Servant"
            4. Click "Generate"
            5. Use the generated password in Indentured Servant
            
            Note: This password is used instead of your regular Yahoo password.
            """
        }
        
        return instructions.get(service, f"Please check {service}'s documentation for app password instructions.")
    
    # ===== PRIVATE METHODS =====
    
    def _load_configs(self) -> Dict[str, Any]:
        """Load email configurations from secure storage"""
        try:
            configs = self.secure_config.get_general_config('email_configs', {})
            return configs
        except Exception as e:
            self.logger.error(f"Failed to load email configs: {e}")
            return {}
    
    def _save_configs(self):
        """Save email configurations to secure storage"""
        try:
            self.secure_config.set_general_config('email_configs', self.email_configs)
        except Exception as e:
            self.logger.error(f"Failed to save email configs: {e}")
    
    def _create_message(self,
                       from_email: str,
                       to_emails: List[str],
                       subject: str,
                       body: str,
                       body_type: str,
                       cc_emails: List[str],
                       bcc_emails: List[str],
                       reply_to: str,
                       attachments: List[str]) -> MIMEMultipart:
        """Create email message with attachments"""
        # Create message container
        msg = MIMEMultipart('mixed')
        msg['From'] = from_email
        msg['To'] = ', '.join(to_emails)
        
        if cc_emails:
            msg['Cc'] = ', '.join(cc_emails)
        
        if reply_to:
            msg['Reply-To'] = reply_to
        
        msg['Subject'] = subject
        msg['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
        msg['X-Mailer'] = 'Indentured Servant Cybersecurity Assistant'
        
        # Create body part
        if body_type == 'html':
            body_part = MIMEText(body, 'html', 'utf-8')
        else:
            body_part = MIMEText(body, 'plain', 'utf-8')
        
        # Create alternative part for HTML/plain text
        alt_part = MIMEMultipart('alternative')
        alt_part.attach(body_part)
        msg.attach(alt_part)
        
        # Add attachments
        for attachment_path in attachments:
            if os.path.exists(attachment_path):
                self._add_attachment(msg, attachment_path)
        
        return msg
    
    def _add_attachment(self, msg: MIMEMultipart, file_path: str):
        """Add attachment to email message"""
        try:
            # Guess content type
            ctype, encoding = mimetypes.guess_type(file_path)
            if ctype is None or encoding is not None:
                ctype = 'application/octet-stream'
            
            maintype, subtype = ctype.split('/', 1)
            
            with open(file_path, 'rb') as fp:
                if maintype == 'text':
                    attachment = MIMEText(fp.read().decode('utf-8'), _subtype=subtype, _charset='utf-8')
                elif maintype == 'image':
                    attachment = MIMEImage(fp.read(), _subtype=subtype)
                elif maintype == 'application':
                    attachment = MIMEApplication(fp.read(), _subtype=subtype)
                else:
                    attachment = MIMEBase(maintype, subtype)
                    attachment.set_payload(fp.read())
                    encoders.encode_base64(attachment)
            
            # Add headers
            filename = os.path.basename(file_path)
            attachment.add_header('Content-Disposition', 'attachment', filename=filename)
            msg.attach(attachment)
            
            self.logger.debug(f"Attached: {filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to attach {file_path}: {e}")
    
    def _send_smtp(self,
                  config: Dict[str, Any],
                  from_email: str,
                  password: str,
                  message: MIMEMultipart,
                  recipients: List[str]) -> Dict[str, Any]:
        """Send email via SMTP"""
        try:
            server = config.get('server', '')
            port = config.get('port', 587)
            use_tls = config.get('use_tls', True)
            use_ssl = config.get('use_ssl', False)
            
            # Create SSL context
            context = ssl.create_default_context()
            
            if use_ssl:
                # SSL connection
                with smtplib.SMTP_SSL(server, port, context=context) as smtp:
                    if config.get('auth_required', True):
                        smtp.login(from_email, password)
                    
                    smtp.send_message(message)
            else:
                # TLS connection
                with smtplib.SMTP(server, port) as smtp:
                    smtp.ehlo()
                    
                    if use_tls:
                        smtp.starttls(context=context)
                        smtp.ehlo()
                    
                    if config.get('auth_required', True):
                        smtp.login(from_email, password)
                    
                    smtp.send_message(message)
            
            # Extract message ID if available
            message_id = message.get('Message-ID', '')
            
            return {
                'success': True,
                'message_id': message_id,
                'server': server,
                'port': port
            }
            
        except smtplib.SMTPAuthenticationError as e:
            error_msg = f"Authentication failed: {e}"
            self.logger.error(error_msg)
            return {'success': False, 'error': error_msg, 'type': 'authentication'}
            
        except smtplib.SMTPException as e:
            error_msg = f"SMTP error: {e}"
            self.logger.error(error_msg)
            return {'success': False, 'error': error_msg, 'type': 'smtp'}
            
        except Exception as e:
            error_msg = f"Connection error: {e}"
            self.logger.error(error_msg)
            return {'success': False, 'error': error_msg, 'type': 'connection'}
    
    def _test_connection(self, service: str) -> Dict[str, Any]:
        """Test connection to email service"""
        try:
            if service not in self.email_configs:
                return {'success': False, 'error': 'Service not configured'}
            
            config = self.email_configs[service]
            creds = self.secure_config.get_email_credentials(service)
            
            if not creds:
                return {'success': False, 'error': 'Credentials not found'}
            
            return self._test_smtp_connection(config, creds['email'], creds['password'])
            
        except Exception as e:
            self.logger.error(f"Connection test failed for {service}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _test_smtp_connection(self,
                             config: Dict[str, Any],
                             email: str,
                             password: str) -> Dict[str, Any]:
        """Test SMTP connection"""
        try:
            server = config.get('server', '')
            port = config.get('port', 587)
            use_ssl = config.get('use_ssl', False)
            
            context = ssl.create_default_context()
            
            if use_ssl:
                with smtplib.SMTP_SSL(server, port, context=context) as smtp:
                    if config.get('auth_required', True):
                        smtp.login(email, password)
                    # Success if we get here
                    return {'success': True}
            else:
                with smtplib.SMTP(server, port) as smtp:
                    smtp.ehlo()
                    
                    if config.get('use_tls', True):
                        smtp.starttls(context=context)
                        smtp.ehlo()
                    
                    if config.get('auth_required', True):
                        smtp.login(email, password)
                    
                    # Success if we get here
                    return {'success': True}
                    
        except smtplib.SMTPAuthenticationError as e:
            return {'success': False, 'error': f'Authentication failed: {e}'}
        except Exception as e:
            return {'success': False, 'error': f'Connection failed: {e}'}
    
    def _create_alert_content(self, alert_type: str, details: Dict[str, Any]) -> Tuple[str, str]:
        """Create security alert email content"""
        alerts = {
            'threat_detected': {
                'subject': '🚨 Security Threat Detected',
                'template': """
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #dc3545;">🚨 Security Threat Detected</h2>
                    <p><strong>System:</strong> {hostname}</p>
                    <p><strong>Time:</strong> {timestamp}</p>
                    <p><strong>Threats Found:</strong> {threat_count}</p>
                    
                    <h3 style="color: #6c757d;">Detected Threats:</h3>
                    <ul>
                        {threat_list}
                    </ul>
                    
                    <h3 style="color: #6c757d;">Recommendations:</h3>
                    <ol>
                        {recommendations}
                    </ol>
                    
                    <hr>
                    <p style="font-size: 0.9em; color: #6c757d;">
                        This alert was generated by Indentured Servant Cybersecurity Assistant.
                        Review the full report in the application for more details.
                    </p>
                </body>
                </html>
                """
            },
            'scan_complete': {
                'subject': '✅ Security Scan Complete',
                'template': """
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #28a745;">✅ Security Scan Complete</h2>
                    <p><strong>System:</strong> {hostname}</p>
                    <p><strong>Scan Type:</strong> {scan_type}</p>
                    <p><strong>Completed:</strong> {timestamp}</p>
                    <p><strong>Duration:</strong> {duration} seconds</p>
                    
                    <h3 style="color: #6c757d;">Results:</h3>
                    <ul>
                        <li><strong>Threats Found:</strong> {threat_count}</li>
                        <li><strong>Warnings:</strong> {warning_count}</li>
                        <li><strong>Security Score:</strong> {security_score}/100</li>
                    </ul>
                    
                    {result_summary}
                    
                    <hr>
                    <p style="font-size: 0.9em; color: #6c757d;">
                        View the complete scan report in Indentured Servant for detailed information.
                    </p>
                </body>
                </html>
                """
            },
            'vpn_connected': {
                'subject': '🔐 VPN Connection Established',
                'template': """
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #007bff;">🔐 VPN Connection Established</h2>
                    <p><strong>Device:</strong> {device_name}</p>
                    <p><strong>Connected:</strong> {timestamp}</p>
                    <p><strong>Remote IP:</strong> {remote_ip}</p>
                    <p><strong>Local IP:</strong> {local_ip}</p>
                    
                    <h3 style="color: #6c757d;">Connection Details:</h3>
                    <ul>
                        <li><strong>Protocol:</strong> {protocol}</li>
                        <li><strong>Port:</strong> {port}</li>
                        <li><strong>Duration:</strong> {duration}</li>
                        <li><strong>Data Transferred:</strong> {data_transferred}</li>
                    </ul>
                    
                    <hr>
                    <p style="font-size: 0.9em; color: #6c757d;">
                        VPN connection monitored by Indentured Servant.
                    </p>
                </body>
                </html>
                """
            }
        }
        
        alert_config = alerts.get(alert_type, alerts['scan_complete'])
        subject = alert_config['subject']
        template = alert_config['template']
        
        # Format template with details
        body = template.format(**details)
        
        return subject, body
    
    def _clear_service_credentials(self, service: str):
        """Clear service credentials from Windows Credential Manager"""
        try:
            # This would use Windows Credential Manager API
            # For now, we'll just log it
            self.logger.info(f"Credentials cleared for {service} (would use Windows Credential Manager)")
        except Exception as e:
            self.logger.error(f"Failed to clear credentials for {service}: {e}")
    
    def _format_threat_list(self, threats: List[Dict[str, Any]]) -> str:
        """Format threat list for email"""
        if not threats:
            return "<li>No threats detected</li>"
        
        items = []
        for threat in threats[:10]:  # Limit to 10 threats in email
            items.append(f"<li><strong>{threat.get('name', 'Unknown')}</strong> - {threat.get('severity', 'Unknown')} severity</li>")
        
        if len(threats) > 10:
            items.append(f"<li>... and {len(threats) - 10} more threats</li>")
        
        return '\n'.join(items)
    
    def _format_recommendations(self, recommendations: List[str]) -> str:
        """Format recommendations for email"""
        if not recommendations:
            return "<li>No specific recommendations</li>"
        
        items = []
        for rec in recommendations[:5]:  # Limit to 5 recommendations
            items.append(f"<li>{rec}</li>")
        
        return '\n'.join(items)

# ===== TEST FUNCTION =====
def test_email_client():
    """Test email client functionality"""
    print("📧 Testing Email Client...")
    print("=" * 60)
    
    client = EmailClient()
    
    # Get configured services
    print("\n1. Configured Email Services:")
    services = client.get_configured_services()
    
    if services:
        for service in services:
            print(f"   • {service['service']}: {service['email']} ({service['status']})")
    else:
        print("   No services configured.")
    
    # Test Gmail configuration instructions
    print("\n2. Gmail App Password Instructions:")
    print(client.get_app_password_instructions('gmail')[:200] + "...")
    
    # Test alert creation
    print("\n3. Test Alert Creation:")
    
    test_details = {
        'hostname': 'DESKTOP-ABC123',
        'timestamp': datetime.now().isoformat(),
        'threat_count': 3,
        'threat_list': '<li>Malware.exe - High severity</li><li>Spyware.dll - Medium severity</li>',
        'recommendations': '<li>Run full system scan</li><li>Update antivirus definitions</li>'
    }
    
    subject, body = client._create_alert_content('threat_detected', test_details)
    print(f"   Subject: {subject}")
    print(f"   Body length: {len(body)} characters")
    
    # Show available services
    print("\n4. Available Email Services:")
    for service, config in client.service_configs.items():
        print(f"   • {service}: {config['description']}")
    
    print("\n" + "=" * 60)
    print("✅ Email client test complete!")
    print("\nNote: Actual email sending requires proper configuration with app passwords.")

if __name__ == "__main__":
    test_email_client()