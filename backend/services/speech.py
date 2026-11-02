"""
Speech transcription service for CSP_V2.
Directly transcribes supported audio formats (WebM, WAV, MP3, M4A, OGG, FLAC)
using the Groq Whisper API without requiring FFmpeg or Pydub conversions.
"""

import os
from pathlib import Path
import speech_recognition as sr
from config import Config
from backend.services.ai_generator import get_groq_client


def speech_to_text(audio_path: str) -> str:
    """
    Transcribe audio file into Telugu text.
    Uses Groq's high-speed Whisper models (whisper-large-v3-turbo / whisper-large-v3)
    which natively support WebM, WAV, MP3, M4A, OGG, FLAC directly without FFmpeg.
    Provides a WAV-only fallback to Google Speech Recognition if Groq is unavailable.
    """
    if not audio_path or not os.path.exists(audio_path):
        raise FileNotFoundError(f"Audio file does not exist: {audio_path}")

    file_size = os.path.getsize(audio_path)
    if file_size == 0:
        raise ValueError("The uploaded audio file is empty (0 bytes). Please provide a valid recording or audio file.")

    extension = os.path.splitext(audio_path)[1].lower()
    supported = getattr(Config, "SUPPORTED_AUDIO_EXTENSIONS", {
        ".flac", ".mp3", ".mp4", ".mpeg", ".mpga", ".m4a", ".ogg", ".opus", ".wav", ".webm"
    })

    if extension not in supported:
        formats_list = ", ".join(sorted(supported))
        raise ValueError(f"Unsupported audio format '{extension}'. Supported formats are: {formats_list}")

    # Primary Transcription: Groq Whisper API
    filename = os.path.basename(audio_path)
    client = get_groq_client()
    whisper_models = getattr(Config, "GROQ_WHISPER_MODELS", ["whisper-large-v3-turbo", "whisper-large-v3"])

    last_error = None
    with open(audio_path, "rb") as audio_file:
        audio_bytes = audio_file.read()

    for model_name in whisper_models:
        try:
            transcription = client.audio.transcriptions.create(
                model=model_name,
                file=(filename, audio_bytes),
                language="te"
            )
            if transcription and transcription.text:
                return transcription.text.strip()
        except Exception as e:
            last_error = e
            continue

    # Secondary Fallback: speech_recognition (PCM WAV only, since Python wave module requires no FFmpeg)
    if extension == ".wav":
        try:
            recognizer = sr.Recognizer()
            with sr.AudioFile(audio_path) as source:
                recognizer.adjust_for_ambient_noise(source, duration=0.5)
                audio_data = recognizer.record(source)
            text = recognizer.recognize_google(audio_data, language="te-IN")
            if text:
                return text.strip()
        except Exception:
            pass

    if last_error:
        raise RuntimeError("Audio transcription could not be completed. Please verify audio quality and try again.")

    raise RuntimeError("No transcription text could be extracted from the audio.")
