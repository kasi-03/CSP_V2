"""
backend/services/session_service.py
===================================
Service for safe management and cleanup of expired Flask filesystem session files (SEC-09).

Architecture & Multi-Process Safety Guarantees:
1. Built-in Expiration Enforcement:
   - Flask-Session and Cachelib natively enforce access-time session expiration.
   - When an expired session is accessed, Cachelib's FileSystemCache returns None,
     immediately invalidating the session on read.
2. Storage Bound Protection:
   - Cachelib's built-in threshold mechanism (SESSION_FILE_THRESHOLD) bounds filesystem
     storage growth natively during session writes.
3. Multi-Process Coordination Across Gunicorn Workers:
   - Python in-memory threading locks CANNOT synchronize multiple Gunicorn worker processes.
   - Maintenance cleanup uses SessionProcessLock (an inter-process OS file lock on .cleanup.lock).
   - If another worker or maintenance job is currently executing cleanup, concurrent workers
     immediately bail out without waiting, blocking, or colliding.
4. No Private Cachelib Internals:
   - Does NOT depend on private Cachelib methods (_list_dir, _safe_stream_open, _update_count).
   - Uses standard library filesystem operations (os.scandir) and standard binary stream reading.
5. Zero Information Leakage:
   - Never logs or exposes session IDs, filenames, or session payload contents.
6. Safety & Preservation:
   - Never deletes active/unexpired sessions.
   - Preserves internal cache management files (.fs_count, .cleanup.lock).
   - Does not delete or recreate the session directory.
"""

import hashlib
import logging
import os
import struct
import sys
import time
from typing import Optional, Tuple
from flask import Flask, current_app
from config import Config

logger = logging.getLogger(__name__)

# Cache management filenames that must never be deleted or counted as user sessions
CACHE_MANAGEMENT_FILES = {
    "__wz_cache_count",
    hashlib.sha256(b"__wz_cache_count").hexdigest(),
    hashlib.md5(b"__wz_cache_count").hexdigest(),
    hashlib.sha256(b"__fs_count").hexdigest(),
    hashlib.md5(b"__fs_count").hexdigest(),
}

_cachelib_format_compatible: Optional[bool] = None


def is_cachelib_format_compatible() -> bool:
    """
    Explicit compatibility safeguard ensuring that the installed Cachelib FileSystemCache
    actually writes files using the expected 4-byte unsigned integer timestamp prefix.

    Verifies actual Cachelib behavior by creating an isolated test cache instance,
    writing a short-lived entry, and confirming that the file written on disk:
    1. Contains exactly a 4-byte unsigned integer header matching the expiration timestamp.
    2. Is followed by a valid serialized payload decodable by Cachelib's serializer.

    Fails closed (returns False) if Cachelib ever changes its internal file structure,
    header length, integer width, or serialization mechanism in future releases.
    """
    global _cachelib_format_compatible
    if _cachelib_format_compatible is not None:
        return _cachelib_format_compatible

    if struct.calcsize("I") != 4:
        _cachelib_format_compatible = False
        return False

    try:
        import cachelib.file
        import tempfile
        import shutil

        tmp_dir = tempfile.mkdtemp(prefix="cachelib_compat_check_")
        try:
            test_cache = cachelib.file.FileSystemCache(cache_dir=tmp_dir)
            target_timeout = 300
            test_key = "__csp_format_compat_probe__"
            test_cache.set(test_key, {"probe": "ok"}, timeout=target_timeout)

            found_valid_probe = False
            now = time.time()
            with os.scandir(tmp_dir) as probe_entries:
                for entry in probe_entries:
                    if entry.name.startswith(".") or entry.name in CACHE_MANAGEMENT_FILES:
                        continue
                    with open(entry.path, "rb") as f:
                        header = f.read(4)
                        if len(header) != 4:
                            continue
                        exp = struct.unpack("I", header)[0]
                        # Expiration must match now + target_timeout within +/- 15 seconds
                        if abs(exp - (now + target_timeout)) <= 15:
                            payload = test_cache.serializer.load(f)
                            if isinstance(payload, dict) and payload.get("probe") == "ok":
                                found_valid_probe = True
                                break

            _cachelib_format_compatible = found_valid_probe
            return found_valid_probe
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception as exc:
        logger.warning("Cachelib format compatibility probe failed: %s", exc)
        _cachelib_format_compatible = False
        return False


class SessionProcessLock:
    """
    Cross-process file lock ensuring that maintenance cleanup cannot execute
    concurrently across multiple Gunicorn worker processes.
    Prefers the 'filelock' library if available; falls back to OS-level msvcrt / fcntl.
    """
    def __init__(self, lock_file: str):
        self.lock_file = lock_file
        self._fl = None
        self._fd = None

    def acquire(self) -> bool:
        """Attempt non-blocking acquisition. Returns True if acquired, False otherwise."""
        # Method 1: Try filelock library if available
        try:
            import filelock
            try:
                self._fl = filelock.FileLock(self.lock_file, timeout=0, preserve_lock_file=True)
            except TypeError:
                self._fl = filelock.FileLock(self.lock_file, timeout=0)
            self._fl.acquire()
            return True
        except ImportError:
            pass
        except Exception:
            return False

        # Method 2: Standard library OS file lock fallback
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.lock_file)), exist_ok=True)
            self._fd = os.open(self.lock_file, os.O_CREAT | os.O_RDWR)
            if sys.platform == "win32":
                import msvcrt
                try:
                    msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                    return True
                except (BlockingIOError, OSError):
                    os.close(self._fd)
                    self._fd = None
                    return False
            else:
                import fcntl
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return True
                except (BlockingIOError, OSError):
                    os.close(self._fd)
                    self._fd = None
                    return False
        except OSError:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
            return False

    def release(self):
        """Release the acquired process lock."""
        if self._fl is not None:
            try:
                self._fl.release()
            except Exception:
                pass
            finally:
                self._fl = None

        if self._fd is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None

    def __enter__(self):
        if not self.acquire():
            raise TimeoutError("Could not acquire session process lock (held by another worker).")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


def resolve_session_dir(
    session_dir = None,
    app: Optional[Flask] = None
) -> Optional[str]:
    """Resolve the session storage directory path from arguments, app config, or Config."""
    if isinstance(session_dir, Flask):
        app = session_dir
        session_dir = None
    elif isinstance(session_dir, str):
        return session_dir

    target_app = app or (current_app._get_current_object() if current_app else None)
    if target_app:
        return target_app.config.get("SESSION_FILE_DIR")
    return getattr(Config, "SESSION_FILE_DIR", None)


def get_session_cache(app: Optional[Flask] = None):
    """
    Retrieve the cache instance from Flask's session_interface if available.
    Does not rely on private methods.
    """
    target_app = app or (current_app._get_current_object() if current_app else None)
    if target_app and hasattr(target_app, "session_interface"):
        return getattr(target_app.session_interface, "cache", None)
    return None


def cleanup_expired_sessions(
    session_dir = None,
    app: Optional[Flask] = None,
    **kwargs
) -> Tuple[int, int]:
    """
    Safely remove expired session files from the filesystem.

    Multi-Process Coordination:
        - Uses SessionProcessLock on '.cleanup.lock' in the session directory.
        - If another Gunicorn worker is already performing cleanup, returns (0, 0)
          immediately without blocking.

    Safety:
        - Does NOT call private Cachelib methods (_list_dir, _safe_stream_open, _update_count).
        - Inspects files using standard library os.scandir().
        - Skips all management and dotfiles (e.g. .fs_count, .cleanup.lock).
        - Reads the 4-byte unsigned integer timestamp prefix.
        - Strictly deletes only files where expires != 0 and expires < now.
        - Never deletes active sessions (expires >= now or expires == 0).
        - Suppresses transient file lock / permission exceptions.
        - Zero exposure of session keys or session data in logs.

    Returns:
        tuple (removed_count: int, remaining_count: int)
    """
    target_dir = resolve_session_dir(session_dir, app)
    if not target_dir or not os.path.exists(target_dir):
        return 0, 0

    # Explicit format compatibility safeguard: verify 4-byte header compatibility
    if not is_cachelib_format_compatible():
        logger.error(
            "Cachelib session format compatibility check failed; aborting cleanup to prevent accidental session deletion."
        )
        return 0, 0

    lock_file = os.path.join(target_dir, ".cleanup.lock")
    lock = SessionProcessLock(lock_file)
    if not lock.acquire():
        logger.debug("Session cleanup lock is held by another worker; skipping to prevent concurrent sweeps.")
        return 0, 0

    try:
        now = time.time()
        removed_count = 0
        remaining_count = 0

        with os.scandir(target_dir) as entries:
            for entry in entries:
                # Skip non-files and management files (e.g. .fs_count, .cleanup.lock, __wz_cache_count)
                if (
                    not entry.is_file()
                    or entry.name.startswith(".")
                    or entry.name.startswith("__")
                    or entry.name in CACHE_MANAGEMENT_FILES
                ):
                    continue

                try:
                    with open(entry.path, "rb") as f:
                        header = f.read(4)
                        if len(header) < 4:
                            continue
                        expires = struct.unpack("I", header)[0]

                    if expires != 0 and expires < now:
                        try:
                            os.remove(entry.path)
                            removed_count += 1
                        except FileNotFoundError:
                            pass
                        except OSError as e:
                            logger.debug("Transient error removing expired session file: %s", type(e).__name__)
                    else:
                        remaining_count += 1
                except FileNotFoundError:
                    pass
                except (OSError, EOFError, struct.error) as e:
                    logger.debug("Transient error inspecting session file: %s", type(e).__name__)

        if removed_count > 0:
            logger.info(
                "Session cleanup completed: %d expired session(s) safely removed, %d active session(s) remaining.",
                removed_count,
                remaining_count
            )
        else:
            logger.debug(
                "Session cleanup check: 0 expired sessions found, %d active session(s) remaining.",
                remaining_count
            )

        return removed_count, remaining_count
    finally:
        lock.release()
