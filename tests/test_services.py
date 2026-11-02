"""
Tests for backend service modules: database, file_helpers, and station settings.
"""

import unittest
from backend.services.database import get_complaints, get_statistics, get_complaint_by_id
from backend.utils.file_helpers import build_case_name_from_registered, get_case_folder
from backend.utils.station import load_station


class TestBackendServices(unittest.TestCase):

    def test_database_complaints_retrieval(self):
        """Verify that complaints can be fetched from the database."""
        complaints = get_complaints()
        self.assertIsInstance(complaints, list)
        if len(complaints) > 0:
            first_complaint = complaints[0]
            self.assertGreaterEqual(len(first_complaint), 9)

    def test_database_statistics(self):
        """Verify that statistics return 3 integer counts."""
        total, today, month = get_statistics()
        self.assertIsInstance(total, int)
        self.assertIsInstance(today, int)
        self.assertIsInstance(month, int)
        self.assertGreaterEqual(total, 0)
        self.assertGreaterEqual(today, 0)
        self.assertGreaterEqual(month, 0)

    def test_get_complaint_by_id(self):
        """Verify retrieving an existing complaint by its ID."""
        complaints = get_complaints()
        if complaints:
            test_id = complaints[0][0]
            record = get_complaint_by_id(test_id)
            self.assertIsNotNone(record)
            self.assertEqual(record[0], test_id)

    def test_station_settings(self):
        """Verify station settings loading."""
        station = load_station()
        self.assertIsInstance(station, dict)
        self.assertIn("station_name", station)
        self.assertIn("place", station)
        self.assertIn("district", station)

    def test_file_helpers_case_name(self):
        """Verify case name formatting from registered date and complainant name."""
        case_name = build_case_name_from_registered(1, "Ramesh", "19-10-2026 02:30 PM")
        self.assertTrue(case_name.startswith("C001_Ramesh_19-10-2026"))


if __name__ == "__main__":
    unittest.main()
