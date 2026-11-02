"""Backend services for database, AI, speech recognition, and PDF generation."""
from .database import (
    init_db,
    save_complaint,
    get_complaints,
    get_complaint_by_id,
    update_audio_path,
    update_complaint_storage,
    get_complaint_storage_info,
    get_statistics
)
from .ai_generator import (
    call_llm,
    clean_speech,
    generate_complaint,
    translate_to_english,
    english_to_telugu,
    generate_subject,
    translate_subject
)
from .speech import speech_to_text
from .pdf_generator import generate_telugu_pdf, generate_english_pdf
from .storage import (
    BaseStorageBackend,
    LocalStorageBackend,
    SupabaseStorageBackend,
    get_storage_service,
    build_storage_key,
    get_content_type,
    sanitize_filename,
    StorageError,
    StorageConfigError,
    StorageNotFoundError
)
