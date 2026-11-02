import unittest
from discord_ticket_detector import classify


class TicketDetectorTests(unittest.TestCase):
    def test_requires_consent(self):
        self.assertIsNone(classify({"notification_text": "Ticket Closed", "source": "user_submitted_notification"}))

    def test_unknown_server_is_inventory(self):
        result = classify({"consent": True, "source": "user_submitted_notification",
                           "notification_text": "Your ticket has been closed",
                           "server_name": "Help Center"})
        self.assertEqual(result.classification, "inventory")
        self.assertEqual(result.event, "closed")

    def test_catalog_match_never_auto_bans(self):
        result = classify({"consent": True, "source": "authorized_windows_notification",
                           "notification_text": "Ticket Opened",
                           "server_name": "Example Cheats"}, ["example cheats"])
        self.assertEqual(result.classification, "manual_review")

    def test_no_server_inconclusive(self):
        result = classify({"consent": True, "source": "user_submitted_notification",
                           "notification_text": "Ticket fechado"})
        self.assertEqual(result.classification, "inconclusive")

    def test_irrelevant_notification(self):
        self.assertIsNone(classify({"consent": True, "source": "user_submitted_notification",
                                    "notification_text": "Hello there"}))


if __name__ == "__main__":
    unittest.main()
