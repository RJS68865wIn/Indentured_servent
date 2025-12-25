"""
AI Assistant for Indentured Servant
Ollama integration for intelligent cybersecurity assistance
"""
import json
import requests
import threading
import time
import re
from typing import Dict, List, Any, Optional, Tuple, Callable
from datetime import datetime
from dataclasses import dataclass, asdict

from src.utils.logger import setup_logger, log_function_call
from src.secure_config import WindowsSecureConfig

@dataclass
class AIMessage:
    """AI message with metadata"""
    role: str  # user, assistant, system
    content: str
    timestamp: str
    tokens: int = 0

@dataclass
class AIFunction:
    """AI-callable function definition"""
    name: str
    description: str
    parameters: Dict[str, Any]
    handler: Callable

class AIAssistant:
    """
    AI Assistant powered by Ollama with cybersecurity expertise
    """
    
    def __init__(self, model: str = "llama3.2"):
        self.logger = setup_logger("AIAssistant")
        self.model = model
        self.ollama_url = "http://localhost:11434/api"
        
        # Conversation history
        self.conversation_history: List[AIMessage] = []
        self.max_history = 20
        
        # Registered functions that AI can call
        self.functions: Dict[str, AIFunction] = {}
        self._register_default_functions()
        
        # System prompt for cybersecurity assistant
        self.system_prompt = self._create_system_prompt()
        
        # Initialize conversation
        self._initialize_conversation()
        
        # Check Ollama connection
        self.ollama_available = self._check_ollama_connection()
        
        if not self.ollama_available:
            self.logger.warning("Ollama not available. AI features will be limited.")
    
    def _check_ollama_connection(self) -> bool:
        """Check if Ollama is running and accessible"""
        try:
            response = requests.get(f"{self.ollama_url}/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                available_models = [m.get('name', '') for m in models]
                
                if self.model not in available_models:
                    self.logger.warning(f"Model {self.model} not found. Available: {available_models}")
                    if available_models:
                        self.model = available_models[0]
                        self.logger.info(f"Using model: {self.model}")
                
                self.logger.info(f"Ollama connected. Using model: {self.model}")
                return True
        except Exception as e:
            self.logger.error(f"Ollama connection failed: {e}")
        
        return False
    
    def _create_system_prompt(self) -> str:
        """Create the system prompt for cybersecurity assistant"""
        return """You are "Indentured Servant", a cybersecurity assistant AI. Your purpose is to help users with security tasks and answer questions.

CAPABILITIES:
1. Security Analysis - Analyze security issues and provide recommendations
2. Threat Intelligence - Explain threats and vulnerabilities
3. Technical Guidance - Provide step-by-step security instructions
4. Report Generation - Help create security reports
5. Automation - Execute security tasks via available functions

PERSONALITY:
- Professional but approachable
- Prioritize security and privacy
- Explain technical concepts clearly
- Be proactive about potential risks
- Admit when you don't know something

RESPONSE FORMAT:
1. Provide clear, actionable advice
2. Use markdown formatting for readability
3. Include severity levels when discussing threats
4. Reference specific tools or commands when possible
5. End with a summary or next steps

AVAILABLE FUNCTIONS (call automatically when appropriate):
{function_descriptions}

When calling functions:
1. Extract all necessary parameters from the conversation
2. Call the function with EXACT parameter names
3. Wait for function results before continuing

IMPORTANT: Always maintain conversation context and be helpful."""
    
    def _register_default_functions(self):
        """Register default AI-callable functions"""
        # Security scan functions
        self.register_function(
            name="run_security_scan",
            description="Run a security scan on the system",
            parameters={
                "scan_type": {
                    "type": "string",
                    "description": "Type of scan: quick, full, memory, network, or custom",
                    "enum": ["quick", "full", "memory", "network", "custom"]
                },
                "scan_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional: Custom paths to scan (for custom scans)",
                    "default": []
                }
            },
            handler=self._handle_security_scan
        )
        
        # Network scan functions
        self.register_function(
            name="scan_network",
            description="Scan the local network for devices",
            parameters={
                "timeout": {
                    "type": "number",
                    "description": "Ping timeout in seconds",
                    "default": 2.0
                }
            },
            handler=self._handle_network_scan
        )
        
        # Port scan functions
        self.register_function(
            name="scan_ports",
            description="Scan ports on a target IP address",
            parameters={
                "target_ip": {
                    "type": "string",
                    "description": "IP address to scan",
                    "default": "127.0.0.1"
                },
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Ports to scan (comma-separated or range)",
                    "default": [80, 443, 3389]
                }
            },
            handler=self._handle_port_scan
        )
        
        # Email functions
        self.register_function(
            name="send_security_alert",
            description="Send a security alert email",
            parameters={
                "alert_type": {
                    "type": "string",
                    "description": "Type of alert: threat_detected, scan_complete, vpn_connected",
                    "enum": ["threat_detected", "scan_complete", "vpn_connected"]
                },
                "recipient": {
                    "type": "string",
                    "description": "Recipient email address (optional, uses default if not specified)",
                    "default": ""
                },
                "details": {
                    "type": "object",
                    "description": "Alert details JSON object"
                }
            },
            handler=self._handle_send_alert
        )
        
        # VPN functions
        self.register_function(
            name="setup_vpn",
            description="Setup WireGuard VPN for a device",
            parameters={
                "device_name": {
                    "type": "string",
                    "description": "Name of the device (e.g., iPhone, Android)",
                    "default": "MyDevice"
                },
                "port": {
                    "type": "integer",
                    "description": "VPN port number",
                    "default": 51820
                }
            },
            handler=self._handle_setup_vpn
        )
        
        # System info functions
        self.register_function(
            name="get_system_info",
            description="Get system information",
            parameters={},
            handler=self._handle_get_system_info
        )
        
        # Windows Defender functions
        self.register_function(
            name="check_defender",
            description="Check Windows Defender status",
            parameters={},
            handler=self._handle_check_defender
        )
        
        # Firewall functions
        self.register_function(
            name="check_firewall",
            description="Check Windows Firewall status",
            parameters={},
            handler=self._handle_check_firewall
        )
        
        self.logger.info(f"Registered {len(self.functions)} AI-callable functions")
    
    def register_function(self, name: str, description: str, parameters: Dict[str, Any], handler: Callable):
        """Register a new AI-callable function"""
        self.functions[name] = AIFunction(
            name=name,
            description=description,
            parameters=parameters,
            handler=handler
        )
    
    def _initialize_conversation(self):
        """Initialize the conversation with system prompt"""
        # Update system prompt with function descriptions
        function_descriptions = []
        for func_name, func in self.functions.items():
            params = json.dumps(func.parameters, indent=2)
            function_descriptions.append(f"- {func_name}: {func.description}\n  Parameters: {params}")
        
        system_prompt = self.system_prompt.format(
            function_descriptions="\n".join(function_descriptions)
        )
        
        # Add system message
        system_message = AIMessage(
            role="system",
            content=system_prompt,
            timestamp=datetime.now().isoformat()
        )
        
        self.conversation_history = [system_message]
        
        # Add welcome message
        welcome_message = AIMessage(
            role="assistant",
            content="""🔒 **Indentured Servant AI Assistant Online**

Hello! I'm your AI-powered cybersecurity assistant. I can help you with:

• **Security Scanning** - Run quick or full system scans
• **Network Analysis** - Discover devices and scan ports  
• **Threat Detection** - Identify and explain security threats
• **VPN Setup** - Configure WireGuard VPN for secure connections
• **Email Alerts** - Send security notifications
• **System Hardening** - Provide security recommendations

What would you like to do today? You can ask me to run scans, check security status, or explain security concepts.""",
            timestamp=datetime.now().isoformat()
        )
        
        self.conversation_history.append(welcome_message)
    
    @log_function_call
    def chat(self, user_message: str, stream_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Process a user message and generate AI response
        
        Args:
            user_message: User's message/text
            stream_callback: Optional callback for streaming responses
            
        Returns:
            Dictionary with response and metadata
        """
        try:
            # Add user message to history
            user_msg = AIMessage(
                role="user",
                content=user_message,
                timestamp=datetime.now().isoformat()
            )
            self.conversation_history.append(user_msg)
            
            # Prepare messages for Ollama
            messages = self._prepare_messages()
            
            # Generate AI response
            if self.ollama_available:
                response = self._generate_ollama_response(messages, stream_callback)
            else:
                response = self._generate_fallback_response(user_message)
            
            # Parse response for function calls
            function_calls = self._extract_function_calls(response)
            
            # Execute function calls if any
            function_results = []
            if function_calls:
                for func_call in function_calls:
                    result = self._execute_function_call(func_call)
                    function_results.append(result)
                    
                    # Add function result to conversation
                    if result.get('success'):
                        result_msg = AIMessage(
                            role="function",
                            content=json.dumps(result, indent=2),
                            timestamp=datetime.now().isoformat()
                        )
                        self.conversation_history.append(result_msg)
            
            # If functions were called, generate follow-up response
            if function_calls and function_results:
                follow_up_response = self._generate_followup_response(response, function_results)
                
                # Add AI response to history
                ai_msg = AIMessage(
                    role="assistant",
                    content=follow_up_response,
                    timestamp=datetime.now().isoformat(),
                    tokens=len(follow_up_response.split())  # Approximate
                )
                self.conversation_history.append(ai_msg)
                
                # Trim history if too long
                if len(self.conversation_history) > self.max_history:
                    self.conversation_history = [self.conversation_history[0]] + self.conversation_history[-self.max_history+1:]
                
                return {
                    'success': True,
                    'response': follow_up_response,
                    'function_calls': function_calls,
                    'function_results': function_results,
                    'tokens': ai_msg.tokens,
                    'timestamp': ai_msg.timestamp
                }
            else:
                # Add AI response to history
                ai_msg = AIMessage(
                    role="assistant",
                    content=response,
                    timestamp=datetime.now().isoformat(),
                    tokens=len(response.split())  # Approximate
                )
                self.conversation_history.append(ai_msg)
                
                # Trim history
                if len(self.conversation_history) > self.max_history:
                    self.conversation_history = [self.conversation_history[0]] + self.conversation_history[-self.max_history+1:]
                
                return {
                    'success': True,
                    'response': response,
                    'function_calls': [],
                    'function_results': [],
                    'tokens': ai_msg.tokens,
                    'timestamp': ai_msg.timestamp
                }
                
        except Exception as e:
            self.logger.error(f"Chat failed: {e}")
            error_response = f"I apologize, but I encountered an error: {str(e)}\n\nPlease try again or rephrase your request."
            
            return {
                'success': False,
                'response': error_response,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _prepare_messages(self) -> List[Dict[str, str]]:
        """Prepare conversation history for Ollama API"""
        messages = []
        
        for msg in self.conversation_history[-10:]:  # Last 10 messages for context
            if msg.role == "function":
                # Format function results
                messages.append({
                    "role": "assistant",
                    "content": f"[Function result]: {msg.content}"
                })
            else:
                messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
        
        return messages
    
    def _generate_ollama_response(self, messages: List[Dict[str, str]], stream_callback: Optional[Callable] = None) -> str:
        """Generate response using Ollama API"""
        try:
            if stream_callback:
                # Streaming response
                response_text = ""
                url = f"{self.ollama_url}/chat"
                
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "stream": True,
                    "options": {
                        "temperature": 0.7,
                        "top_p": 0.9,
                        "num_predict": 1024
                    }
                }
                
                response = requests.post(url, json=payload, stream=True)
                
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line)
                        if 'message' in data and 'content' in data['message']:
                            chunk = data['message']['content']
                            response_text += chunk
                            stream_callback(chunk)
                
                return response_text
            else:
                # Non-streaming response
                url = f"{self.ollama_url}/chat"
                
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": 0.7,
                        "top_p": 0.9,
                        "num_predict": 1024
                    }
                }
                
                response = requests.post(url, json=payload, timeout=60)
                response.raise_for_status()
                
                data = response.json()
                return data.get('message', {}).get('content', '')
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ollama API error: {e}")
            return self._generate_fallback_response(messages[-1]['content'] if messages else "")
        except Exception as e:
            self.logger.error(f"Response generation error: {e}")
            return f"I apologize, but I encountered an error: {str(e)}"
    
    def _generate_fallback_response(self, user_message: str) -> str:
        """Generate fallback response when Ollama is unavailable"""
        # Simple rule-based responses
        user_lower = user_message.lower()
        
        if any(word in user_lower for word in ['hello', 'hi', 'hey', 'greetings']):
            return "Hello! I'm your cybersecurity assistant. How can I help you with security tasks today?"
        
        elif any(word in user_lower for word in ['scan', 'security scan', 'check system']):
            return "I can help you run security scans. You can use the Security Scanner tab or ask me to run specific scans like 'run a quick scan' or 'scan for malware'."
        
        elif any(word in user_lower for word in ['network', 'devices', 'scan network']):
            return "For network scanning, use the Network Tools tab. I can help you discover devices on your network or scan specific IP addresses."
        
        elif any(word in user_lower for word in ['vpn', 'wireguard', 'secure connection']):
            return "I can help you setup WireGuard VPN in the Network Tools tab. This creates a secure connection between your computer and mobile devices."
        
        elif any(word in user_lower for word in ['email', 'alert', 'notification']):
            return "You can configure email alerts in the Email Tools tab. I can help send security notifications when threats are detected."
        
        elif any(word in user_lower for word in ['help', 'what can you do', 'capabilities']):
            return """I can help with:
• Security scanning and threat detection
• Network analysis and device discovery  
• VPN setup and configuration
• Email security alerts
• System security recommendations
• Explaining security concepts

Use the specific tabs for detailed features, or ask me questions!"""
        
        else:
            return "I'm your cybersecurity assistant. For full AI capabilities, please ensure Ollama is running with a model like llama3.2. In the meantime, you can use the application's built-in security tools in each tab."
    
    def _extract_function_calls(self, response: str) -> List[Dict[str, Any]]:
        """Extract function calls from AI response"""
        function_calls = []
        
        # Look for function call patterns
        patterns = [
            r'ACTION:\s*(\w+)\((.*?)\)',  # ACTION: function_name(params)
            r'FUNCTION:\s*(\w+)\s*{\s*(.*?)\s*}',  # FUNCTION: name {json}
            r'```function\s+(\w+)\s*(.*?)```',  # ```function name json```
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
            for match in matches:
                func_name = match[0].strip()
                params_str = match[1].strip() if len(match) > 1 else "{}"
                
                # Try to parse parameters as JSON
                try:
                    if params_str:
                        params = json.loads(params_str)
                    else:
                        params = {}
                except json.JSONDecodeError:
                    # Try to parse as key=value pairs
                    params = {}
                    for pair in params_str.split(','):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            params[key.strip()] = value.strip().strip('"\'')
                
                if func_name in self.functions:
                    function_calls.append({
                        'function': func_name,
                        'parameters': params
                    })
        
        return function_calls
    
    def _execute_function_call(self, func_call: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an AI-requested function call"""
        try:
            func_name = func_call['function']
            params = func_call['parameters']
            
            if func_name not in self.functions:
                return {
                    'success': False,
                    'error': f"Function '{func_name}' not found",
                    'function': func_name
                }
            
            func = self.functions[func_name]
            
            # Validate parameters
            validated_params = self._validate_parameters(func.parameters, params)
            
            # Execute function
            self.logger.info(f"Executing function: {func_name} with params: {validated_params}")
            result = func.handler(**validated_params)
            
            return {
                'success': True,
                'function': func_name,
                'parameters': validated_params,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Function execution failed: {e}")
            return {
                'success': False,
                'function': func_name,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _validate_parameters(self, schema: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize function parameters"""
        validated = {}
        
        for param_name, param_schema in schema.items():
            if param_name in params:
                # Use provided value
                value = params[param_name]
                
                # Type validation (simplified)
                expected_type = param_schema.get('type', 'string')
                
                if expected_type == 'integer':
                    try:
                        value = int(value)
                    except (ValueError, TypeError):
                        if 'default' in param_schema:
                            value = param_schema['default']
                        else:
                            raise ValueError(f"Parameter '{param_name}' must be an integer")
                
                elif expected_type == 'number':
                    try:
                        value = float(value)
                    except (ValueError, TypeError):
                        if 'default' in param_schema:
                            value = param_schema['default']
                        else:
                            raise ValueError(f"Parameter '{param_name}' must be a number")
                
                elif expected_type == 'array':
                    if not isinstance(value, list):
                        if isinstance(value, str):
                            # Try to parse as comma-separated list
                            value = [item.strip() for item in value.split(',')]
                        else:
                            if 'default' in param_schema:
                                value = param_schema['default']
                            else:
                                raise ValueError(f"Parameter '{param_name}' must be an array")
                
                # Enum validation
                if 'enum' in param_schema and value not in param_schema['enum']:
                    if 'default' in param_schema:
                        value = param_schema['default']
                    else:
                        raise ValueError(f"Parameter '{param_name}' must be one of: {param_schema['enum']}")
                
                validated[param_name] = value
            
            elif 'default' in param_schema:
                # Use default value
                validated[param_name] = param_schema['default']
            else:
                # Required parameter missing
                raise ValueError(f"Required parameter '{param_name}' is missing")
        
        return validated
    
    def _generate_followup_response(self, initial_response: str, function_results: List[Dict[str, Any]]) -> str:
        """Generate follow-up response after function execution"""
        try:
            # Prepare context for follow-up
            context_messages = self.conversation_history.copy()
            
            # Add function results as assistant messages
            for result in function_results:
                result_str = json.dumps(result, indent=2)
                context_messages.append(AIMessage(
                    role="assistant",
                    content=f"[Function executed]: {result_str}",
                    timestamp=datetime.now().isoformat()
                ))
            
            # Prepare messages for Ollama
            messages = []
            for msg in context_messages[-12:]:  # Include function results
                messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
            
            # Add instruction for follow-up
            messages.append({
                "role": "user",
                "content": "Based on the function results, provide a helpful response summarizing what was done and any recommendations."
            })
            
            # Generate follow-up
            if self.ollama_available:
                url = f"{self.ollama_url}/chat"
                
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": 0.7}
                }
                
                response = requests.post(url, json=payload, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                return data.get('message', {}).get('content', '')
            else:
                # Simple follow-up without Ollama
                successful_results = [r for r in function_results if r.get('success')]
                
                if successful_results:
                    actions = [f"✅ {r['function']}" for r in successful_results]
                    return f"I've completed the requested actions:\n\n" + "\n".join(actions) + "\n\nCheck the respective tabs for detailed results."
                else:
                    return "I attempted the requested actions but encountered some issues. Please check the application logs for details."
                    
        except Exception as e:
            self.logger.error(f"Follow-up response failed: {e}")
            return "I've executed the requested functions. Check the application for results."
    
    # ===== FUNCTION HANDLERS =====
    
    def _handle_security_scan(self, scan_type: str = "quick", scan_paths: List[str] = None) -> Dict[str, Any]:
        """Handle security scan request"""
        try:
            # Import here to avoid circular imports
            from .security_scanner import WindowsSecurityScanner
            
            scanner = WindowsSecurityScanner()
            result = scanner.run_scan(scan_type, scan_paths)
            
            return {
                'scan_type': scan_type,
                'threats_found': result.threats_found,
                'warnings': len(result.warnings),
                'duration': result.scan_duration,
                'report_saved': True,
                'message': f"Security scan completed: {result.threats_found} threats found"
            }
            
        except Exception as e:
            self.logger.error(f"Security scan failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Security scan failed: {str(e)}"
            }
    
    def _handle_network_scan(self, timeout: float = 2.0) -> Dict[str, Any]:
        """Handle network scan request"""
        try:
            from .network_tools import NetworkTools
            
            tools = NetworkTools()
            devices = tools.scan_local_network(timeout)
            
            return {
                'devices_found': len(devices),
                'devices': [
                    {
                        'ip': device.ip,
                        'hostname': device.hostname,
                        'vendor': device.vendor,
                        'open_ports': device.open_ports[:5]  # Limit ports
                    }
                    for device in devices[:10]  # Limit devices
                ],
                'message': f"Network scan found {len(devices)} devices"
            }
            
        except Exception as e:
            self.logger.error(f"Network scan failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Network scan failed: {str(e)}"
            }
    
    def _handle_port_scan(self, target_ip: str = "127.0.0.1", ports: List[int] = None) -> Dict[str, Any]:
        """Handle port scan request"""
        try:
            from .network_tools import NetworkTools
            
            if ports is None:
                ports = [80, 443, 3389]
            
            tools = NetworkTools()
            result = tools.port_scan(target_ip, ports)
            
            return {
                'target': target_ip,
                'ports_scanned': len(ports),
                'open_ports': result['open_ports'],
                'scan_duration': result['scan_duration'],
                'message': f"Port scan found {len(result['open_ports'])} open ports on {target_ip}"
            }
            
        except Exception as e:
            self.logger.error(f"Port scan failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Port scan failed: {str(e)}"
            }
    
    def _handle_send_alert(self, alert_type: str, details: Dict[str, Any], recipient: str = "") -> Dict[str, Any]:
        """Handle security alert email request"""
        try:
            from .email_client import EmailClient
            
            client = EmailClient()
            result = client.send_security_alert(alert_type, details, recipient)
            
            return {
                'alert_type': alert_type,
                'sent': result['success'],
                'message_id': result.get('message_id', ''),
                'message': f"Security alert email sent via {result.get('service', 'unknown')}"
            }
            
        except Exception as e:
            self.logger.error(f"Send alert failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to send security alert: {str(e)}"
            }
    
    def _handle_setup_vpn(self, device_name: str = "MyDevice", port: int = 51820) -> Dict[str, Any]:
        """Handle VPN setup request"""
        try:
            from .network_tools import NetworkTools
            
            tools = NetworkTools()
            result = tools.setup_wireguard_vpn(device_name, port)
            
            if result['success']:
                return {
                    'device': device_name,
                    'port': port,
                    'public_ip': result.get('public_ip', ''),
                    'config_files': {
                        'server': result.get('server_config'),
                        'client': result.get('client_config')
                    },
                    'message': f"VPN setup complete for {device_name}"
                }
            else:
                return {
                    'success': False,
                    'error': result.get('error', 'Unknown error'),
                    'message': f"VPN setup failed: {result.get('error', 'Unknown error')}"
                }
            
        except Exception as e:
            self.logger.error(f"VPN setup failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"VPN setup failed: {str(e)}"
            }
    
    def _handle_get_system_info(self) -> Dict[str, Any]:
        """Handle system info request"""
        try:
            from .utils.windows_tools import get_system_info
            
            info = get_system_info()
            
            return {
                'system': 'Windows',
                'hostname': info.get('hostname', 'Unknown'),
                'local_ip': info.get('local_ip', 'Unknown'),
                'public_ip': info.get('public_ip', 'Unknown'),
                'memory': info.get('memory', {}),
                'disks': len(info.get('disks', [])),
                'message': "System information retrieved"
            }
            
        except Exception as e:
            self.logger.error(f"Get system info failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to get system info: {str(e)}"
            }
    
    def _handle_check_defender(self) -> Dict[str, Any]:
        """Handle Windows Defender check request"""
        try:
            from .security_scanner import WindowsSecurityScanner
            
            scanner = WindowsSecurityScanner()
            status = scanner._check_defender_status()
            
            return {
                'realtime_enabled': status.get('realtime_enabled', False),
                'tamper_protection': status.get('tamper_protection', False),
                'cloud_enabled': status.get('cloud_enabled', False),
                'definitions_updated': status.get('definitions_updated', False),
                'message': "Windows Defender status checked"
            }
            
        except Exception as e:
            self.logger.error(f"Check defender failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to check Windows Defender: {str(e)}"
            }
    
    def _handle_check_firewall(self) -> Dict[str, Any]:
        """Handle firewall check request"""
        try:
            from .utils.windows_tools import check_firewall_status
            
            firewall = check_firewall_status()
            
            return {
                'profiles': firewall,
                'all_enabled': all(firewall.values()) if firewall else False,
                'message': "Firewall status checked"
            }
            
        except Exception as e:
            self.logger.error(f"Check firewall failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to check firewall: {str(e)}"
            }
    
    # ===== UTILITY METHODS =====
    
    def clear_conversation(self):
        """Clear conversation history"""
        self._initialize_conversation()
        self.logger.info("Conversation cleared")
    
    def get_conversation_summary(self) -> Dict[str, Any]:
        """Get conversation summary"""
        user_messages = [msg for msg in self.conversation_history if msg.role == "user"]
        assistant_messages = [msg for msg in self.conversation_history if msg.role == "assistant"]
        
        return {
            'total_messages': len(self.conversation_history),
            'user_messages': len(user_messages),
            'assistant_messages': len(assistant_messages),
            'functions_called': len([msg for msg in self.conversation_history if msg.role == "function"]),
            'last_interaction': self.conversation_history[-1].timestamp if self.conversation_history else None,
            'ollama_available': self.ollama_available,
            'model': self.model
        }
    
    def get_available_functions(self) -> List[Dict[str, Any]]:
        """Get list of available functions"""
        functions = []
        
        for func_name, func in self.functions.items():
            functions.append({
                'name': func_name,
                'description': func.description,
                'parameters': func.parameters
            })
        
        return functions

# ===== TEST FUNCTION =====
def test_ai_assistant():
    """Test AI assistant functionality"""
    print("🧠 Testing AI Assistant...")
    print("=" * 60)
    
    assistant = AIAssistant()
    
    # Check Ollama status
    print(f"\n1. Ollama Status: {'✅ Connected' if assistant.ollama_available else '❌ Not Available'}")
    if assistant.ollama_available:
        print(f"   Model: {assistant.model}")
    
    # Get available functions
    print("\n2. Available Functions:")
    functions = assistant.get_available_functions()
    for func in functions[:5]:  # Show first 5
        print(f"   • {func['name']}: {func['description'][:50]}...")
    
    if len(functions) > 5:
        print(f"   ... and {len(functions) - 5} more functions")
    
    # Test conversation
    print("\n3. Test Conversation:")
    
    test_messages = [
        "Hello!",
        "Can you check my system security?",
        "What functions can you call?"
    ]
    
    for i, message in enumerate(test_messages[:2], 1):
        print(f"\n   You: {message}")
        
        result = assistant.chat(message)
        
        if result['success']:
            response = result['response']
            # Show first 100 characters of response
            preview = response[:100] + "..." if len(response) > 100 else response
            print(f"   AI: {preview}")
            
            if result['function_calls']:
                print(f"   Functions called: {[fc['function'] for fc in result['function_calls']]}")
        else:
            print(f"   Error: {result.get('error', 'Unknown error')}")
    
    # Get conversation summary
    print("\n4. Conversation Summary:")
    summary = assistant.get_conversation_summary()
    print(f"   Total messages: {summary['total_messages']}")
    print(f"   User messages: {summary['user_messages']}")
    print(f"   AI responses: {summary['assistant_messages']}")
    print(f"   Functions called: {summary['functions_called']}")
    
    print("\n" + "=" * 60)
    print("✅ AI assistant test complete!")

if __name__ == "__main__":
    test_ai_assistant()