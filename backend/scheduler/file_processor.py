"""
SecureFlow File Processor

Handles file filtering, sharding, and processing utilities.
"""

import os
import logging
from pathlib import Path
from typing import List, Set, Dict, Any
import mimetypes

logger = logging.getLogger(__name__)

class FileProcessor:
    """Processes files for security analysis."""
    
    def __init__(self):
        self.supported_extensions = self._load_supported_extensions()
        self.max_file_size = int(os.getenv("MAX_FILE_SIZE_MB", "10")) * 1024 * 1024  # 10MB default
        self.skip_directories = {
            ".git", ".svn", ".hg", ".bzr",  # VCS directories
            "node_modules", "__pycache__", ".pytest_cache",  # Build/cache directories
            "venv", ".venv", "env", ".env",  # Virtual environments
            "build", "dist", "target", "bin", "obj",  # Build output
            ".idea", ".vscode", ".vs",  # IDE directories
            "coverage", ".coverage", ".nyc_output",  # Coverage directories
            "logs", "log", "temp", "tmp"  # Temporary directories
        }
        self.skip_files = {
            ".gitignore", ".gitattributes", ".dockerignore",
            "package-lock.json", "yarn.lock", "poetry.lock",
            "requirements.txt", "Pipfile.lock", "composer.lock",
            "Cargo.lock", "go.sum"
        }
    
    def _load_supported_extensions(self) -> Set[str]:
        """Load supported file extensions from environment or defaults."""
        extensions_str = os.getenv(
            "SUPPORTED_EXTENSIONS",
            ".py,.js,.ts,.jsx,.tsx,.java,.cpp,.c,.h,.hpp,.cs,.php,.rb,.go,.rs,.kt,.swift,.scala,.m,.mm,.pl,.sh,.bash,.zsh,.ps1,.sql,.xml,.json,.yaml,.yml,.toml,.ini,.cfg,.conf,.md"
        )
        return set(ext.strip() for ext in extensions_str.split(","))
    
    def get_supported_files(self, directory: Path) -> List[Path]:
        """Get all supported files from a directory recursively."""
        supported_files = []
        
        try:
            # Handle both file and directory inputs
            if directory.is_file():
                if self._should_include_file(directory):
                    supported_files.append(directory)
                return supported_files
            
            # Process directory recursively
            for file_path in directory.rglob("*"):
                if file_path.is_file() and self._should_include_file(file_path):
                    supported_files.append(file_path)
            
            logger.info(f"Found {len(supported_files)} supported files in {directory}")
            
            # Log some examples for debugging
            if supported_files:
                logger.debug(f"Example files found: {[str(f) for f in supported_files[:5]]}")
            else:
                logger.warning(f"No supported files found in {directory}")
                # List what files are actually there
                all_files = list(directory.rglob("*"))
                logger.debug(f"All files in directory: {[str(f) for f in all_files[:10]]}")
            
            return supported_files
            
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
            return []
    
    # def _should_include_file(self, file_path: Path) -> bool:
    #     """Check if a file should be included in analysis."""
    #     try:
    #         # Convert to Path object if it's a string
    #         if isinstance(file_path, str):
    #             file_path = Path(file_path)
                
    #         # Get file extension
    #         ext = file_path.suffix.lower()
            
    #         # Define supported extensions - MAKE SURE .py IS HERE!
    #         supported_extensions = {
    #             # Python - THIS IS CRITICAL
    #             '.py', '.pyw', '.pyi',
    #             # JavaScript/TypeScript
    #             '.js', '.jsx', '.ts', '.tsx', '.mjs',
    #             # Java
    #             '.java',
    #             # C/C++
    #             '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
    #             # C#
    #             '.cs',
    #             # Go
    #             '.go',
    #             # Rust
    #             '.rs',
    #             # PHP
    #             '.php', '.php3', '.php4', '.php5', '.phtml',
    #             # Ruby
    #             '.rb', '.rbw',
    #             # Shell scripts
    #             '.sh', '.bash', '.zsh',
    #             # Config files
    #             '.yml', '.yaml', '.json', '.xml', '.toml', '.ini', '.cfg', '.conf',
    #             # SQL
    #             '.sql',
    #             # Web files
    #             '.html', '.htm', '.vue'
    #         }
            
    #         # Log the check for debugging
    #         logger.info(f"Checking file: {file_path}, extension: {ext}, supported: {ext in supported_extensions}")
            
    #         # Check extension FIRST
    #         if ext not in supported_extensions:
    #             logger.warning(f"File {file_path} not supported (extension: {ext})")
    #             return False
                
    #         # Check if file exists and is readable
    #         if not file_path.exists():
    #             logger.warning(f"File {file_path} does not exist")
    #             return False
                
    #         # Check file size (skip very large files > 10MB)
    #         try:
    #             file_size = file_path.stat().st_size
    #             if file_size > 10 * 1024 * 1024:
    #                 logger.warning(f"File {file_path} too large: {file_size} bytes")
    #                 return False
    #         except (OSError, FileNotFoundError):
    #             logger.warning(f"Cannot read file stats for {file_path}")
    #             return False
                
    #         # Check if it's a binary file
    #         if self._is_binary_file(file_path):
    #             logger.warning(f"File {file_path} is binary")
    #             return False
                
    #         # Check specific filenames (without extension)
    #         filename_lower = file_path.name.lower()
    #         supported_filenames = {
    #             'dockerfile', 'makefile', 'rakefile', 'gemfile', 
    #             'package.json', 'composer.json', 'requirements.txt',
    #             '.env', '.env.local', '.env.production', '.env.development'
    #         }
            
    #         if filename_lower in supported_filenames:
    #             logger.info(f"File {file_path} supported by filename")
    #             return True
                
    #         # If we get here, it passed all checks
    #         logger.info(f"File {file_path} accepted for analysis")
    #         return True
            
    #     except Exception as e:
    #         logger.error(f"Error checking file {file_path}: {e}")
    #         return False
     
# Update the _should_include_file method to be more permissive

    def _should_include_file(self, file_path: Path) -> bool:
        """Check if a file should be included in analysis."""
        try:
            # Convert to Path object if it's a string
            if isinstance(file_path, str):
                file_path = Path(file_path)
                
            # Get file extension
            ext = file_path.suffix.lower()
            
            # Check if the file exists and is readable first
            if not file_path.exists():
                logger.warning(f"File {file_path} does not exist")
                return False
                
            # Log for debugging all file attempts
            logger.info(f"Processing file: {file_path}, extension: {ext}")
            
            # Check if it's in the supported extensions set from the environment
            # (This uses the config-defined extensions rather than hardcoded ones)
            if ext not in self.supported_extensions:
                # Special handling for specific files without extensions
                filename_lower = file_path.name.lower()
                supported_filenames = {
                    'dockerfile', 'makefile', 'rakefile', 'gemfile', 
                    'package.json', 'composer.json', 'requirements.txt',
                    '.env', '.env.local', '.env.production', '.env.development'
                }
                
                if filename_lower in supported_filenames:
                    logger.info(f"File {file_path} supported by filename")
                    return True
                    
                logger.warning(f"File {file_path} not supported (extension: {ext})")
                return False
            
            # Skip very large files but increase limit to 15MB
            try:
                file_size = file_path.stat().st_size
                max_size = int(os.getenv("MAX_FILE_SIZE_MB", "15")) * 1024 * 1024
                if file_size > max_size:
                    logger.warning(f"File {file_path} too large: {file_size} bytes")
                    return False
            except Exception as e:
                logger.warning(f"Cannot read file stats for {file_path}: {e}")
                return False
                
            # More permissive binary file check for text-like files
            if ext not in {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.html', '.css', '.md', '.txt', '.json', '.yml', '.yaml', '.xml'} and self._is_binary_file(file_path):
                logger.warning(f"File {file_path} appears to be binary")
                return False
                
            # If we get here, it passed all checks
            logger.info(f"File {file_path} accepted for analysis")
            return True
            
        except Exception as e:
            logger.error(f"Error checking file {file_path}: {e}", exc_info=True)
            # Be more permissive - if we can't check, include it
            return True

    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if a file is binary."""
        try:
            # For Python files, always treat as text
            if file_path.suffix.lower() in {'.py', '.pyw', '.pyi'}:
                return False
                
            # Check MIME type first
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type and not mime_type.startswith('text/'):
                # Allow some specific types that might be text but detected as binary
                allowed_extensions = {'.json', '.xml', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
                                    '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.cpp', '.c', '.h'}
                if file_path.suffix.lower() not in allowed_extensions:
                    return True
            
            # Read first chunk and check for null bytes
            try:
                with open(file_path, 'rb') as f:
                    chunk = f.read(1024)  # Read first 1KB
                    # Check for null bytes (common in binary files)
                    if b'\x00' in chunk:
                        return True
                        
                    # Check if content is mostly printable
                    try:
                        chunk.decode('utf-8')
                        return False  # Successfully decoded as UTF-8
                    except UnicodeDecodeError:
                        # Try other encodings
                        for encoding in ['latin-1', 'cp1252']:
                            try:
                                chunk.decode(encoding)
                                return False
                            except UnicodeDecodeError:
                                continue
                        return True  # Couldn't decode with any encoding
                        
            except (OSError, PermissionError):
                logger.warning(f"Cannot read file {file_path} for binary check")
                return True  # Assume binary if can't read
                
            return False
            
        except Exception as e:
            logger.error(f"Error in binary file check for {file_path}: {e}")
            return False  # Assume text if error
    
    def create_shards(self, file_paths: List[Path], shard_size: int = 50) -> List[List[Path]]:
        """Split files into shards for parallel processing."""
        if not file_paths:
            logger.warning("No files provided for sharding")
            return []
            
        shards = []
        current_shard = []
        
        for file_path in file_paths:
            current_shard.append(file_path)
            
            if len(current_shard) >= shard_size:
                shards.append(current_shard)
                current_shard = []
        
        # Add remaining files as final shard
        if current_shard:
            shards.append(current_shard)
        
        logger.info(f"Created {len(shards)} shards from {len(file_paths)} files")
        return shards
    
    def get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get detailed file information."""
        try:
            stat = file_path.stat()
            
            return {
                "path": str(file_path),
                "name": file_path.name,
                "extension": file_path.suffix.lower(),
                "size": stat.st_size,
                "modified": stat.st_mtime,
                "is_executable": os.access(file_path, os.X_OK),
                "language": self._detect_language(file_path)
            }
            
        except Exception as e:
            logger.error(f"Error getting file info for {file_path}: {e}")
            return {
                "path": str(file_path),
                "name": file_path.name,
                "error": str(e)
            }
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension."""
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.c': 'c',
            '.h': 'c',
            '.hpp': 'cpp',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.kt': 'kotlin',
            '.swift': 'swift',
            '.scala': 'scala',
            '.m': 'objective-c',
            '.mm': 'objective-cpp',
            '.pl': 'perl',
            '.sh': 'bash',
            '.bash': 'bash',
            '.zsh': 'zsh',
            '.ps1': 'powershell',
            '.sql': 'sql',
            '.xml': 'xml',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.toml': 'toml',
            '.ini': 'ini',
            '.cfg': 'config',
            '.conf': 'config'
        }
        
        return extension_map.get(file_path.suffix.lower(), 'unknown')
    
    def read_file_content(self, file_path: Path, max_lines: int = 10000) -> str:
        """Read file content with size limits."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        lines.append(f"... (truncated after {max_lines} lines)")
                        break
                    lines.append(line.rstrip())
                
                return '\n'.join(lines)
                
        except UnicodeDecodeError:
            # Try with different encodings
            for encoding in ['latin1', 'ascii', 'utf-16']:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                        if len(content.split('\n')) > max_lines:
                            lines = content.split('\n')[:max_lines]
                            return '\n'.join(lines) + f"\n... (truncated after {max_lines} lines)"
                        return content
                except UnicodeDecodeError:
                    continue
            
            # If all encodings fail, read as binary and decode
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    return content.decode('utf-8', errors='replace')
            except Exception as e:
                logger.error(f"Failed to read file {file_path}: {e}")
                return f"Error reading file: {e}"
                
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return f"Error reading file: {e}"
    
    def extract_code_snippet(self, file_path: Path, line_number: int, context_lines: int = 5) -> str:
        """Extract code snippet around a specific line."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start_line = max(0, line_number - context_lines - 1)
            end_line = min(len(lines), line_number + context_lines)
            
            snippet_lines = []
            for i in range(start_line, end_line):
                line_num = i + 1
                prefix = ">>> " if line_num == line_number else "    "
                snippet_lines.append(f"{prefix}{line_num:4d}: {lines[i].rstrip()}")
            
            return '\n'.join(snippet_lines)
            
        except Exception as e:
            logger.error(f"Error extracting snippet from {file_path}:{line_number}: {e}")
            return f"Error extracting snippet: {e}"
    
    def get_language_stats(self, file_paths: List[Path]) -> Dict[str, int]:
        """Get statistics about programming languages in the file set."""
        language_counts = {}
        
        for file_path in file_paths:
            language = self._detect_language(file_path)
            language_counts[language] = language_counts.get(language, 0) + 1
        
        return language_counts
    
    def filter_by_language(self, file_paths: List[Path], languages: List[str]) -> List[Path]:
        """Filter files by programming language."""
        filtered_files = []
        
        for file_path in file_paths:
            if self._detect_language(file_path) in languages:
                filtered_files.append(file_path)
        
        return filtered_files
    
# temp
    def debug_file_check(self, file_path: Path) -> Dict[str, Any]:
        """Debug why a file might be excluded."""
        result = {
            "file": str(file_path),
            "exists": file_path.exists(),
            "is_file": file_path.is_file() if file_path.exists() else False,
            "extension": file_path.suffix.lower(),
            "extension_supported": file_path.suffix.lower() in self.supported_extensions,
            "size": file_path.stat().st_size if file_path.exists() else 0,
            "is_hidden": file_path.name.startswith('.'),
            "in_skip_dirs": any(part in self.skip_directories for part in file_path.parts),
            "in_skip_files": file_path.name in self.skip_files
        }
        
        try:
            result["is_binary"] = self._is_binary_file(file_path)
        except:
            result["is_binary"] = "error"
        
        return result