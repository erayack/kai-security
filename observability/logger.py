import logging
from typing import Dict, Optional
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME


LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class OtelLogger:
    def __init__(
        self,
        otlp_endpoint: str,
        service_name: str = "exploit-agent",
        logger_name: str = "exploit_tracker",
        resource_attrs: Optional[Dict[str, str]] = None,
    ):
        resource = Resource(attributes={SERVICE_NAME: service_name})
        if resource_attrs:
            resource = Resource(
                attributes={**{SERVICE_NAME: service_name}, **resource_attrs}
            )

        self.provider = LoggerProvider(resource=resource)
        self.exporter = OTLPLogExporter(endpoint=otlp_endpoint)
        self.processor = BatchLogRecordProcessor(self.exporter)
        self.provider.add_log_record_processor(self.processor)

        set_logger_provider(self.provider)

        self.handler = LoggingHandler(
            level=logging.NOTSET, logger_provider=self.provider
        )

        self.logger_name = logger_name
        self.py_logger = logging.getLogger(self.logger_name)
        self.py_logger.setLevel(logging.DEBUG)
        self.py_logger.addHandler(self.handler)

    def send(
        self,
        message: str,
        severity: str = "INFO",
        attrs: Optional[Dict[str, str]] = None,
    ):
        level = LEVEL_MAP.get(severity.upper(), logging.INFO)
        extra = {"otelAttributes": attrs or {}}
        self.py_logger.log(level, message, extra=extra)

    def shutdown(self):
        try:
            self.processor.shutdown()
            self.exporter.shutdown()
        except Exception:
            pass


## Create a global instance of the logger to import it in other modules
exploit_logger = OtelLogger(
    otlp_endpoint="http://localhost:4318/v1/logs",
    service_name="exploit-agent",
    logger_name="exploit_tracker",
)
