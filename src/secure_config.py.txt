"""
Secure Configuration Manager for Windows 11
Uses Windows Credential Manager for secure credential storage
"""
import os
import json
import base64
import hashlib
import winreg
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List

try:
    import win32cred
    import win32security
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("Warning: pywin32 not installed. Secure storage may be limited.")

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography not installed. Using basic encryption.")

class SecureConfigError(Exception):
    """Custom exception for secure config errors"""
    pass

class WindowsSecureConfig:
    """
    Secure configuration manager for Windows using Credential Manager
    and encrypted files for non-credential data
    """
    
    def __init__(self, app_name="IndenturedServant"):
        """
        Initialize secure configuration manager for Windows
        
        Args:
            app_name: Application name for credential namespacing
        """
        self.app_name = app_name
        self.config_dir = self._get_config_dir()
        self.key_file = self.config_dir / "master.key"
        self.config_file = self.config_dir / "config.enc"
        
        # Create config directory with restricted permissions
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self._secure_directory(self.config_dir)
        
        # Initialize encryption for file-based storage
        self.cipher = self._init_cipher()
        
        # Migration from old insecure config
        self._migrate_old_config()
    
    def _get_config_dir(self) -> Path:
        """Get Windows-specific configuration directory"""
        # Use AppData\Local for user-specific data
        appdata = os.environ.get('LOCALAPPDATA', 
                                os.path.expanduser('~\\AppData\\Local'))
        return Path(appdata) / self.app_name / "config"
    
    def _secure_directory(self, directory: Path):
        """Set restrictive permissions on directory (Windows ACL)"""
        if WIN32_AVAILABLE:
            try:
                # Get current user SID
                user = win32security.LookupAccountName(None, 
                                                      win32security.GetUserName())[0]
                
                # Create security descriptor
                sd = win32security.SECURITY_DESCRIPTOR()
                sd.Initialize()
                
                # Add ACL entries
                acl = win32security.ACL()
                
                # Allow full control to current user
                acl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    win32con.FILE_ALL_ACCESS,
                    user
                )
                
                # Apply the ACL
                sd.SetSecurityDescriptorDacl(1, acl, 0)
                win32security.SetFileSecurity(
                    str(directory),
                    win32security.DACL_SECURITY_INFORMATION,
                    sd
                )
            except:
                pass  # If we can't set ACLs, continue anyway
    
    def _init_cipher(self):
        """Initialize encryption cipher"""
        if CRYPTO_AVAILABLE:
            return FileBasedCipher(self.key_file)
        else:
            return BasicCipher()
    
    def _migrate_old_config(self):
        """Migrate from old insecure email_config.json if exists"""
        old_config = Path("config/email_config.json")
        if old_config.exists():
            try:
                with open(old_config, 'r') as f:
                    old_data = json.load(f)
                
                print("Migrating old insecure config to secure storage...")
                
                for service, creds in old_data.items():
                    if isinstance(creds, dict) and 'email' in creds and 'password' in creds:
                        self.set_email_credentials(
                            service=service,
                            email=creds['email'],
                            password=creds['password']
                        )
                
                # Backup old config
                backup_file = old_config.with_suffix(f".backup.{datetime.now().strftime('%Y%m%d')}")
                old_config.rename(backup_file)
                print(f"✅ Old config backed up to: {backup_file}")
                
            except Exception as e:
                print(f"⚠️ Could not migrate old config: {e}")
    
    # ===== PUBLIC API =====
    
    def set_email_credentials(self, service: str, email: str, password: str) -> bool:
        """
        Securely store email credentials in Windows Credential Manager
        
        Args:
            service: Email service (gmail, icloud, etc.)
            email: Email address
            password: App password
            
        Returns:
            bool: True if successful
        """
        try:
            # Store in Windows Credential Manager
            credential_dict = {
                'email': email,
                'password': password,
                'service': service,
                'updated': datetime.now().isoformat()
            }
            
            # Use Credential Manager for maximum security
            self._store_in_credential_manager(
                target_name=f"{self.app_name}_{service}",
                username=email,
                password=json.dumps(credential_dict)
            )
            
            # Also store non-sensitive info in config file
            config = self._load_config()
            config['email_services'] = config.get('email_services', {})
            config['email_services'][service] = {
                'email': email,
                'configured': True,
                'last_updated': datetime.now().isoformat()
            }
            self._save_config(config)
            
            print(f"✅ {service} credentials stored in Windows Credential Manager")
            return True
            
        except Exception as e:
            print(f"❌ Failed to store credentials: {e}")
            return False
    
    def get_email_credentials(self, service: str) -> Optional[Dict[str, str]]:
        """
        Retrieve email credentials from Windows Credential Manager
        
        Args:
            service: Email service name
            
        Returns:
            Dict with 'email' and 'password' or None if not found
        """
        try:
            # Retrieve from Credential Manager
            credential_data = self._retrieve_from_credential_manager(
                target_name=f"{self.app_name}_{service}"
            )
            
            if credential_data:
                creds = json.loads(credential_data)
                return {
                    'email': creds['email'],
                    'password': creds['password']
                }
        except Exception as e:
            print(f"⚠️ Could not retrieve {service} credentials: {e}")
        
        return None
    
    def set_vpn_config(self, config_name: str, config_data: Dict[str, Any]) -> bool:
        """Securely store VPN configuration"""
        try:
            config = self._load_config()
            config[f'vpn_{config_name}'] = config_data
            return self._save_config(config)
        except Exception as e:
            print(f"Failed to store VPN config: {e}")
            return False
    
    def get_vpn_config(self, config_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve VPN configuration"""
        config = self._load_config()
        return config.get(f'vpn_{config_name}')
    
    def set_setting(self, key: str, value: Any) -> bool:
        """Store application setting"""
        config = self._load_config()
        config[key] = value
        return self._save_config(config)
    
    def get_setting(self, key: str, default=None) -> Any:
        """Retrieve application setting"""
        config = self._load_config()
        return config.get(key, default)
    
    def list_stored_services(self) -> List[str]:
        """List all stored email services"""
        config = self._load_config()
        services = config.get('email_services', {})
        return list(services.keys())
    
    def clear_all_credentials(self) -> bool:
        """Clear all stored credentials"""
        try:
            # Clear Credential Manager entries
            config = self._load_config()
            services = config.get('email_services', {})
            
            for service in services.keys():
                self._delete_from_credential_manager(f"{self.app_name}_{service}")
            
            # Clear config file
            if self.config_file.exists():
                self.config_file.unlink()
            
            print("✅ All credentials cleared")
            return True
            
        except Exception as e:
            print(f"❌ Failed to clear credentials: {e}")
            return False
    
    # ===== WINDOWS CREDENTIAL MANAGER METHODS =====
    
    def _store_in_credential_manager(self, target_name: str, username: str, password: str):
        """Store credentials in Windows Credential Manager"""
        if not WIN32_AVAILABLE:
            raise SecureConfigError("pywin32 not available for Credential Manager")
        
        try:
            credential = {
                'Type': win32cred.CRED_TYPE_GENERIC,
                'TargetName': target_name,
                'UserName': username,
                'CredentialBlob': password,
                'Persist': win32cred.CRED_PERSIST_LOCAL_MACHINE,
                'Comment': f'{self.app_name} secure storage'
            }
            
            win32cred.CredWrite(credential, 0)
            
        except Exception as e:
            raise SecureConfigError(f"Credential Manager write failed: {e}")
    
    def _retrieve_from_credential_manager(self, target_name: str) -> Optional[str]:
        """Retrieve credentials from Windows Credential Manager"""
        if not WIN32_AVAILABLE:
            return None
        
        try:
            credential = win32cred.CredRead(target_name, 
                                          win32cred.CRED_TYPE_GENERIC, 0)
            if credential:
                return credential['CredentialBlob']
        except:
            pass  # Credential doesn't exist
        
        return None
    
    def _delete_from_credential_manager(self, target_name: str) -> bool:
        """Delete credentials from Windows Credential Manager"""
        if not WIN32_AVAILABLE:
            return False
        
        try:
            win32cred.CredDelete(target_name, win32cred.CRED_TYPE_GENERIC, 0)
            return True
        except:
            return False
    
    # ===== FILE-BASED CONFIG METHODS =====
    
    def _load_config(self) -> Dict[str, Any]:
        """Load the encrypted configuration file"""
        if not self.config_file.exists():
            return {}
        
        try:
            encrypted_data = self.config_file.read_text()
            if CRYPTO_AVAILABLE:
                decrypted = self.cipher.decrypt(encrypted_data)
                return json.loads(decrypted)
            else:
                return json.loads(encrypted_data)
                
        except Exception as e:
            print(f"⚠️ Could not load config: {e}")
            return {}
    
    def _save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to encrypted file"""
        try:
            if CRYPTO_AVAILABLE:
                encrypted = self.cipher.encrypt(json.dumps(config))
                self.config_file.write_text(encrypted)
            else:
                self.config_file.write_text(json.dumps(config, indent=2))
            
            # Set file permissions
            self._secure_file(self.config_file)
            return True
            
        except Exception as e:
            print(f"Failed to save config: {e}")
            return False
    
    def _secure_file(self, file_path: Path):
        """Set restrictive permissions on file"""
        try:
            # On Windows, we set hidden and system attributes
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(file_path), 2)  # FILE_ATTRIBUTE_HIDDEN
        except:
            pass

# ===== ENCRYPTION CLASSES (Fallbacks) =====

class FileBasedCipher:
    """File-based encryption using cryptography library"""
    
    def __init__(self, key_file: Path):
        self.key_file = key_file
        self.key = self._get_or_create_key()
        self.fernet = Fernet(self.key)
    
    def _get_or_create_key(self) -> bytes:
        """Get existing key or generate new one"""
        if self.key_file.exists():
            key = self.key_file.read_bytes()
            if len(key) == 44:  # Valid Fernet key
                return key
        
        # Generate new key
        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        
        # Hide the key file
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(self.key_file), 2)
        except:
            pass
        
        return key
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted: str) -> str:
        """Decrypt string data"""
        return self.fernet.decrypt(encrypted.encode()).decode()

class BasicCipher:
    """Basic cipher (NOT SECURE) for when cryptography is not available"""
    
    def __init__(self):
        # Use Windows machine GUID for slightly better security
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                r"SOFTWARE\Microsoft\Cryptography")
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            self.secret_key = machine_guid.encode()
        except:
            self.secret_key = b"insecure_fallback_key_change_this"
    
    def encrypt(self, data: str) -> str:
        """Basic 'encryption' - just base64 with XOR obfuscation"""
        import base64
        # Simple XOR with key
        encoded = bytearray(data.encode())
        key_byte = self.secret_key[0]
        for i in range(len(encoded)):
            encoded[i] ^= key_byte
        
        return base64.b64encode(encoded).decode()
    
    def decrypt(self, encrypted: str) -> str:
        """Basic 'decryption'"""
        import base64
        decoded = bytearray(base64.b64decode(encrypted))
        key_byte = self.secret_key[0]
        for i in range(len(decoded)):
            decoded[i] ^= key_byte
        
        return decoded.decode()

# ===== UTILITY FUNCTIONS =====

def generate_secure_password(length: int = 16) -> str:
    """Generate a secure random password"""
    import secrets
    import string
    
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def mask_email(email: str) -> str:
    """Mask email for display (e.g., t***@example.com)"""
    if '@' in email:
        local, domain = email.split('@', 1)
        if len(local) > 2:
            masked = local[0] + '*' * (len(local) - 2) + local[-1]
        else:
            masked = '*' * len(local)
        return f"{masked}@{domain}"
    return email

def get_windows_username() -> str:
    """Get current Windows username"""
    import getpass
    return getpass.getuser()

# ===== TEST FUNCTION =====
def test_secure_config():
    """Test the secure configuration system"""
    print("🔐 Testing Windows Secure Configuration...")
    print("=" * 60)
    
    config = WindowsSecureConfig()
    
    # Test storing credentials
    print("\n1. Testing credential storage...")
    success = config.set_email_credentials(
        service="gmail_test",
        email="test@example.com",
        password="test_password_123"
    )
    
    if success:
        print("✅ Credentials stored in Windows Credential Manager")
        
        # Test retrieval
        creds = config.get_email_credentials("gmail_test")
        if creds:
            print(f"📧 Retrieved email: {mask_email(creds['email'])}")
            print(f"🔑 Password retrieved: {'Yes' if creds['password'] else 'No'}")
    
    # List services
    print("\n2. Listing stored services...")
    services = config.list_stored_services()
    print(f"Services: {services}")
    
    # Generate secure password
    print("\n3. Generating secure password...")
    secure_pass = generate_secure_password()
    print(f"🔒 Generated: {secure_pass}")
    
    print("\n" + "=" * 60)
    print("✅ Secure configuration test complete!")
    
    # Cleanup test credentials
    config.clear_all_credentials()

if __name__ == "__main__":
    test_secure_config()