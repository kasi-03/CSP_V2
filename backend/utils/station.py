import os
import json
from config import Config

DEFAULT_STATION = {
    "station_name": "Police Station",
    "place": "Place",
    "district": "District",
    "station_name_telugu": "పోలీస్ స్టేషన్",
    "place_telugu": "ప్రదేశం",
    "district_telugu": "జిల్లా"
}


def load_station() -> dict:
    """Load station configuration from JSON file or return defaults."""
    if not os.path.exists(Config.STATION_CONFIG_PATH):
        return DEFAULT_STATION.copy()

    try:
        with open(Config.STATION_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_STATION.copy()


def save_station(data: dict):
    """Save station configuration to JSON file."""
    with open(Config.STATION_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
