"""
Storage Service for CSP_V2.

Supports:
1. Local filesystem storage (default).
2. Supabase Private Object Storage (bucket: complaint-files).
3. Deterministic, safe object-key generation tied to complaint IDs.
4. Authenticated byte streaming and short-lived signed download URLs.
5. Path traversal prevention and safe filename sanitization.
6. Secret-safe error handling and logging.
"""

import os
import io
import re
import mimetypes
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Union

from config import Config


class StorageError(Exception):
    """Base exception for all storage service errors."""
    pass


class StorageConfigError(StorageError):
    """Raised when storage configuration is invalid or missing."""
    pass


class StorageNotFoundError(StorageError):
    """Raised when a requested storage object is not found."""
    pass


# Map common extensions to explicit content types
MIME_MAP = {
    ".webm": "audio/webm",
    ".wav": "audio/wav",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".ogg": "audio/ogg",
    ".opus": "audio/ogg",
    ".flac": "audio/flac",
    ".pdf": "application/pdf",
}


def get_content_type(filename_or_key: str) -> str:
    """Return appropriate MIME content type for audio or PDF files."""
    ext = os.path.splitext(filename_or_key)[1].lower()
    if ext in MIME_MAP:
        return MIME_MAP[ext]
    mime, _ = mimetypes.guess_type(filename_or_key)
    return mime or "application/octet-stream"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal and unsafe characters.
    Extracts base filename and removes path separators and forbidden symbols.
    """
    base = os.path.basename(filename.strip().replace("\\", "/"))
    # Remove any null bytes or path traversal dots
    cleaned = re.sub(r"[\x00/\\:]+", "_", base)
    cleaned = re.sub(r"^\.+", "", cleaned)  # no leading dots
    if not cleaned:
        cleaned = "unnamed_file"
    return cleaned


def build_storage_key(complaint_id: int, file_category: str, filename: str) -> str:
    """
    Build a safe, deterministic, unique storage key tied to a complaint ID.

    Example:
        complaints/1/audio/Complaint_Audio.webm
        complaints/1/pdf/Complaint_Telugu.pdf
        complaints/1/pdf/Complaint_English.pdf

    Valid categories: 'audio', 'pdf'.
    """
    if not isinstance(complaint_id, int) or complaint_id <= 0:
        raise ValueError(f"complaint_id must be a positive integer, got: {complaint_id}")

    category = file_category.strip().lower()
    if category not in ("audio", "pdf"):
        raise ValueError(f"Invalid file_category: '{file_category}'. Allowed: 'audio', 'pdf'")

    safe_name = sanitize_filename(filename)
    return f"complaints/{complaint_id}/{category}/{safe_name}"


class BaseStorageBackend(ABC):
    """Abstract storage backend interface."""

    @abstractmethod
    def save_file(
        self,
        file_source: Union[str, Path, bytes, io.BytesIO],
        destination_key: str,
        content_type: Optional[str] = None
    ) -> str:
        """
        Store a file at the given destination key.
        Returns the saved storage key or path.
        """
        pass

    @abstractmethod
    def get_file(self, storage_key: str) -> bytes:
        """Retrieve file content as raw bytes."""
        pass

    @abstractmethod
    def get_file_stream(self, storage_key: str) -> io.BytesIO:
        """Retrieve file content as a readable BytesIO stream."""
        pass

    @abstractmethod
    def get_signed_url(self, storage_key: str, expires_in: int = 3600) -> Optional[str]:
        """
        Generate a short-lived signed download URL for private objects.
        Returns None or raises NotImplementedError if signed URLs are not supported.
        """
        pass

    @abstractmethod
    def file_exists(self, storage_key: str) -> bool:
        """Check whether an object exists in storage."""
        pass

    @abstractmethod
    def delete_file(self, storage_key: str) -> bool:
        """Delete an object from storage. Returns True if deleted or did not exist."""
        pass


class LocalStorageBackend(BaseStorageBackend):
    """
    Local filesystem storage backend preserving existing CSP_V2 conventions.
    """

    def __init__(self, base_dir: Optional[Union[str, Path]] = None):
        self.base_dir = Path(base_dir or Config.BASE_DIR).resolve()

    def _resolve_path(self, storage_key: str) -> Path:
        """Resolve a storage key safely within base_dir or absolute if valid."""
        path = Path(storage_key)
        if not path.is_absolute():
            path = (self.base_dir / storage_key).resolve()
        else:
            path = path.resolve()

        # Prevent traversal outside allowed directories
        try:
            path.relative_to(self.base_dir)
        except ValueError:
            # Check if it's within an allowed temp/test folder
            raise StorageError(f"Access denied: path traversal attempt outside base directory.")

        return path

    def save_file(
        self,
        file_source: Union[str, Path, bytes, io.BytesIO],
        destination_key: str,
        content_type: Optional[str] = None
    ) -> str:
        dest_path = self._resolve_path(destination_key)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            if isinstance(file_source, (str, Path)):
                src_path = Path(file_source)
                if not src_path.exists():
                    raise StorageNotFoundError(f"Source file not found: {src_path.name}")
                with open(src_path, "rb") as f_in, open(dest_path, "wb") as f_out:
                    f_out.write(f_in.read())
            elif isinstance(file_source, bytes):
                with open(dest_path, "wb") as f_out:
                    f_out.write(file_source)
            elif hasattr(file_source, "read"):
                with open(dest_path, "wb") as f_out:
                    f_out.write(file_source.read())
            else:
                raise ValueError("Unsupported file_source type")
        except Exception as e:
            if isinstance(e, StorageError):
                raise
            raise StorageError(f"Failed to save local file: {type(e).__name__}") from e

        # Return standardized relative path with forward slashes
        return str(dest_path.relative_to(self.base_dir)).replace("\\", "/")

    def get_file(self, storage_key: str) -> bytes:
        dest_path = self._resolve_path(storage_key)
        if not dest_path.exists() or not dest_path.is_file():
            raise StorageNotFoundError(f"File not found: {dest_path.name}")
        try:
            with open(dest_path, "rb") as f:
                return f.read()
        except Exception as e:
            raise StorageError(f"Failed to read local file: {type(e).__name__}") from e

    def get_file_stream(self, storage_key: str) -> io.BytesIO:
        return io.BytesIO(self.get_file(storage_key))

    def get_signed_url(self, storage_key: str, expires_in: int = 3600) -> Optional[str]:
        # Local backend does not provide cloud signed URLs; returns None
        return None

    def file_exists(self, storage_key: str) -> bool:
        try:
            dest_path = self._resolve_path(storage_key)
            return dest_path.exists() and dest_path.is_file()
        except Exception:
            return False

    def delete_file(self, storage_key: str) -> bool:
        try:
            dest_path = self._resolve_path(storage_key)
            if dest_path.exists() and dest_path.is_file():
                dest_path.unlink()
            return True
        except Exception as e:
            raise StorageError(f"Failed to delete local file: {type(e).__name__}") from e


class SupabaseStorageBackend(BaseStorageBackend):
    """
    Supabase Private Object Storage backend.
    Interacts with the private 'complaint-files' bucket using the Supabase client SDK.
    Never exposes credentials or public URLs.
    """

    def __init__(
        self,
        supabase_url: Optional[str] = None,
        supabase_key: Optional[str] = None,
        bucket_name: Optional[str] = None,
        client=None
    ):
        self.url = supabase_url or Config.SUPABASE_URL
        self.key = supabase_key or Config.SUPABASE_KEY
        self.bucket_name = bucket_name or Config.STORAGE_BUCKET or "complaint-files"
        self._client = client

        # If client not injected, validate configuration
        if self._client is None:
            if not self.url or not self.key:
                raise StorageConfigError(
                    "Supabase storage backend requires both SUPABASE_URL and SUPABASE_KEY."
                )

    @property
    def client(self):
        """Lazily initialize Supabase client if not injected."""
        if self._client is None:
            try:
                from supabase import create_client
                self._client = create_client(self.url, self.key)
            except Exception as e:
                # Do not leak secrets in error message
                raise StorageConfigError(
                    f"Failed to initialize Supabase client: {type(e).__name__}"
                ) from None
        return self._client

    def _get_bucket(self):
        """Return the bucket client proxy."""
        try:
            return self.client.storage.from_(self.bucket_name)
        except Exception as e:
            raise StorageError(f"Failed to access Supabase bucket: {type(e).__name__}") from None

    def save_file(
        self,
        file_source: Union[str, Path, bytes, io.BytesIO],
        destination_key: str,
        content_type: Optional[str] = None
    ) -> str:
        """
        Upload file bytes to private Supabase storage bucket.
        """
        # Read file bytes
        if isinstance(file_source, (str, Path)):
            src_path = Path(file_source)
            if not src_path.exists():
                raise StorageNotFoundError(f"Source file for upload not found: {src_path.name}")
            with open(src_path, "rb") as f:
                data = f.read()
        elif isinstance(file_source, bytes):
            data = file_source
        elif hasattr(file_source, "read"):
            data = file_source.read()
        else:
            raise ValueError("Unsupported file_source type")

        if not content_type:
            content_type = get_content_type(destination_key)

        bucket = self._get_bucket()
        # Clean destination key (no leading slashes for Supabase storage)
        clean_key = destination_key.lstrip("/")

        try:
            # upsert='true' allows retrying or updating without throwing duplicate error
            file_options = {
                "content-type": content_type,
                "upsert": "true"
            }
            bucket.upload(path=clean_key, file=data, file_options=file_options)
            return clean_key
        except Exception as e:
            # Check if it was duplicate or other error, wrap safely without printing secrets
            err_msg = str(e)
            # Remove any possible token/key leaks in error text
            if self.key and self.key in err_msg:
                err_msg = err_msg.replace(self.key, "[REDACTED]")
            raise StorageError(f"Supabase upload failed for key '{clean_key}': {err_msg}") from None

    def get_file(self, storage_key: str) -> bytes:
        """
        Download raw file bytes from private Supabase bucket.
        """
        bucket = self._get_bucket()
        clean_key = storage_key.lstrip("/")

        try:
            response_bytes = bucket.download(clean_key)
            if response_bytes is None:
                raise StorageNotFoundError(f"Object not found in Supabase storage: {clean_key}")
            return response_bytes
        except StorageNotFoundError:
            raise
        except Exception as e:
            err_str = str(e).lower()
            if "not found" in err_str or "404" in err_str:
                raise StorageNotFoundError(f"Object not found in Supabase storage: {clean_key}") from None
            raise StorageError(f"Supabase download failed: {type(e).__name__}") from None

    def get_file_stream(self, storage_key: str) -> io.BytesIO:
        return io.BytesIO(self.get_file(storage_key))

    def get_signed_url(self, storage_key: str, expires_in: int = 3600) -> str:
        """
        Generate short-lived signed URL for private bucket file.
        Expires in 3600 seconds (1 hour) by default.
        """
        bucket = self._get_bucket()
        clean_key = storage_key.lstrip("/")

        try:
            res = bucket.create_signed_url(clean_key, expires_in=expires_in)
            signed_url = None
            if isinstance(res, dict):
                signed_url = res.get("signedURL") or res.get("signedUrl")
            elif hasattr(res, "signed_url"):
                signed_url = getattr(res, "signed_url")
            elif hasattr(res, "get"):
                signed_url = res.get("signedURL") or res.get("signedUrl")

            if not signed_url:
                raise StorageError("Supabase did not return a valid signed URL.")
            return signed_url
        except Exception as e:
            if isinstance(e, StorageError):
                raise
            raise StorageError(f"Failed to generate Supabase signed URL: {type(e).__name__}") from None

    def file_exists(self, storage_key: str) -> bool:
        """Check if an object exists in the private bucket."""
        clean_key = storage_key.lstrip("/")
        bucket = self._get_bucket()
        try:
            # If exists() method exists on proxy
            if hasattr(bucket, "exists"):
                return bool(bucket.exists(clean_key))
            # Otherwise attempt download or list
            parent_dir = os.path.dirname(clean_key)
            base_name = os.path.basename(clean_key)
            items = bucket.list(parent_dir)
            if isinstance(items, list):
                return any(item.get("name") == base_name for item in items if isinstance(item, dict))
            return False
        except Exception:
            return False

    def delete_file(self, storage_key: str) -> bool:
        """Delete an object from Supabase bucket (used for rollback/cleanup)."""
        bucket = self._get_bucket()
        clean_key = storage_key.lstrip("/")
        try:
            bucket.remove([clean_key])
            return True
        except Exception as e:
            raise StorageError(f"Failed to delete Supabase object '{clean_key}': {type(e).__name__}") from None


def get_storage_service(
    backend_type: Optional[str] = None,
    **kwargs
) -> BaseStorageBackend:
    """
    Factory function returning the configured storage backend service.
    Defaults to Config.STORAGE_BACKEND (which defaults to 'local').
    """
    backend = (backend_type or Config.STORAGE_BACKEND or "local").strip().lower()

    if backend == "local":
        return LocalStorageBackend(**kwargs)
    elif backend == "supabase":
        Config.validate_storage_config()
        return SupabaseStorageBackend(**kwargs)
    else:
        raise StorageConfigError(f"Unknown storage backend: '{backend}'. Must be 'local' or 'supabase'.")
