from unittest.mock import create_autospec

from assemblyline_v4_service.common.request import ServiceRequest

import metapeek


def test_Explicit_Directional_Isolates():
    file_name = "‎⁨‏واتساب⁩.pdf"

    mock = create_autospec(ServiceRequest)
    mock.file_name = file_name
    mock.file_type = "document/pdf"

    m = metapeek.MetaPeek()
    m.check_file_name_anomalies(mock)
