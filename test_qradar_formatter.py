import os
import unittest


os.environ["OUTPUT_FORMAT"] = "qradar"

import config as _config
import formatters


class QRadarFormatterTests(unittest.TestCase):
    def setUp(self) -> None:
        _config.OUTPUT_FORMAT = "qradar"

    def test_alert_qradar_shape(self) -> None:
        record = {
            "alert_id": "1001",
            "name": "Suspicious PowerShell",
            "description": "Behavioral alert from Cortex XDR",
            "severity": "high",
            "action": "blocked",
            "detection_timestamp": 1712505600123,
            "last_modified_ts": 1712509200456,
            "host_name": "wkstn-01",
            "host_ip": "10.0.0.5",
            "endpoint_id": "ep-123",
            "source": "agent",
            "category": "Credential Theft",
            "user_name": "alice@example.com",
        }

        out = formatters.format_record(record, "alerts")

        self.assertTrue(
            out.startswith(
                "CEF:0|PaloAlto|XDR Agent|Credential Theft|1001|Credential Theft|7|"
            )
        )
        self.assertIn("cat=Credential Theft", out)
        self.assertIn("qradarCategory=XDR Agent", out)
        self.assertIn("shost=wkstn-01", out)
        self.assertIn("suser=alice@example.com", out)
        self.assertIn("start=2024-04-07T16:00:00.123000Z", out)
        self.assertIn("rt=1712505600123", out)
        self.assertIn("end=1712509200456", out)

    def test_mgmt_audit_qradar_shape(self) -> None:
        record = {
            "AUDIT_ID": "audit-9",
            "AUDIT_OWNER_EMAIL": "admin@example.com",
            "AUDIT_OWNER_NAME": "Admin User",
            "AUDIT_SOURCE_IP": "192.0.2.10",
            "AUDIT_ENTITY": "REPORTING",
            "AUDIT_ENTITY_SUBTYPE": "REPORTING",
            "AUDIT_RESULT": "SUCCESS",
            "AUDIT_DESCRIPTION": "Report exported",
            "AUDIT_SEVERITY": "low",
            "AUDIT_INSERT_TIME": 1712505600123,
            "AUDIT_HOSTNAME": "xdr-console",
        }

        out = formatters.format_record(record, "mgmt_audits")

        self.assertTrue(
            out.startswith(
                "CEF:0|PaloAlto|Management Audit Logs|REPORTING|audit-9|REPORTING|3|"
            )
        )
        self.assertIn("cat=REPORTING", out)
        self.assertIn("qradarCategory=Management Audit Logs", out)
        self.assertIn("shost=xdr-console", out)
        self.assertIn("suser=admin@example.com", out)
        self.assertIn("src=192.0.2.10", out)
        self.assertIn("start=2024-04-07T16:00:00.123000Z", out)

    def test_agent_audit_qradar_shape(self) -> None:
        record = {
            "ENDPOINTID": "endpoint-7",
            "ENDPOINTNAME": "host-7",
            "DOMAIN": "corp.example",
            "CATEGORY": "AGENT_CONFIGURATION",
            "TYPE": "POLICY",
            "SUBTYPE": "UPDATE",
            "RESULT": "SUCCESS",
            "REASON": "User approved",
            "DESCRIPTION": "Agent policy updated",
            "TIMESTAMP": 1712505600123,
            "RECEIVEDTIME": 1712509200456,
            "TRAPSVERSION": "8.5.1",
        }

        out = formatters.format_record(record, "agent_audits")

        self.assertTrue(
            out.startswith(
                "CEF:0|PaloAlto|Agent Audit Logs|AGENT_CONFIGURATION|endpoint-7|AGENT_CONFIGURATION|5|"
            )
        )
        self.assertIn("cat=AGENT_CONFIGURATION", out)
        self.assertIn("qradarCategory=Agent Audit Logs", out)
        self.assertIn("shost=host-7", out)
        self.assertIn("suser=corp.example", out)
        self.assertIn("TYPE=POLICY", out)
        self.assertIn("SUBTYPE=UPDATE", out)
        self.assertIn("TRAPSVERSION=8.5.1", out)

    def test_incidents_are_best_effort_3rd_party(self) -> None:
        record = {
            "incident_id": "inc-2",
            "incident_name": "Suspicious sign-in",
            "severity": "medium",
            "status": "new",
            "modification_time": 1712509200456,
            "assigned_user_mail": "soc@example.com",
        }

        out = formatters.format_record(record, "incidents")

        self.assertTrue(
            out.startswith(
                "CEF:0|PaloAlto|3rd Party|Suspicious sign-in|inc-2|Suspicious sign-in|5|"
            )
        )
        self.assertIn("cat=Suspicious sign-in", out)
        self.assertIn("qradarCategory=3rd Party", out)
        self.assertIn("suser=soc@example.com", out)


if __name__ == "__main__":
    unittest.main()
