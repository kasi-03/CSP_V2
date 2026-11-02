"""
Tests for AI generator, speech recognition, and PDF generation modules.
"""

import unittest
from backend.services.ai_generator import (
    clean_ai_output,
    clean_speech,
    generate_complaint,
    translate_to_english,
    generate_subject
)
from backend.services.pdf_generator import generate_telugu_pdf, generate_english_pdf
from backend.services.speech import speech_to_text


class TestAISpeechPDF(unittest.TestCase):

    def test_clean_ai_output(self):
        """Test markdown fence removal and prefix cleanup."""
        sample_output = "```markdown\nఅయ్యా నా బైక్ దొంగిలించబడింది.\n```"
        cleaned = clean_ai_output(sample_output)
        self.assertNotIn("```", cleaned)

    def test_clean_speech(self):
        """Test speech cleanup."""
        raw = "నా బైక్ పోయింది  "
        cleaned = clean_speech(raw)
        self.assertEqual(cleaned, "నా బైక్ పోయింది")

    def test_ai_generation_integration(self):
        """
        Verify Groq AI integration with fictional sample input.
        Ensures model generates Telugu complaint, English translation, and subject.
        """
        fictional_narration = "నిన్న సాయంత్రం బస్టాండ్ వద్ద నా నల్లటి బ్యాగ్ పోయింది. అందులో కొన్ని పుస్తకాలు ఉన్నాయి."
        complainant = "సురేష్"

        try:
            complaint = generate_complaint(fictional_narration, complainant)
            self.assertIsInstance(complaint, str)
            self.assertGreater(len(complaint), 20)

            english = translate_to_english(complaint, "Suresh")
            self.assertIsInstance(english, str)
            self.assertGreater(len(english), 20)

            subject = generate_subject(complaint)
            self.assertIsInstance(subject, str)
            self.assertGreater(len(subject), 3)
        except Exception as e:
            self.fail(f"AI Generation failed with exception: {e}")

    def test_pdf_functions_callable(self):
        """Ensure PDF generator functions exist and are callable."""
        self.assertTrue(callable(generate_telugu_pdf))
        self.assertTrue(callable(generate_english_pdf))

    def test_speech_callable(self):
        """Ensure speech recognition function is callable."""
        self.assertTrue(callable(speech_to_text))


if __name__ == "__main__":
    unittest.main()
