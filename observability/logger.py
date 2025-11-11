import logging
import time
from typing import Dict, Optional

from opentelemetry._logs import set_logger_provider, get_logger
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
    """
    - Sadece bu sınıfın send() metodunu çağırdığınızda OTel export gerçekleşir.
    - Root logger'a handler eklemiyoruz; kendi özel logger'ımızı kullanıyoruz.
    """

    def __init__(
        self,
        otlp_endpoint: str,
        service_name: str = "my-service",
        logger_name: str = "manual_otel_logger",
        resource_attrs: Optional[Dict[str, str]] = None,
    ):
        # Resource (service name)
        resource = Resource(attributes={SERVICE_NAME: service_name})
        if resource_attrs:
            resource = Resource(
                attributes={**{SERVICE_NAME: service_name}, **resource_attrs}
            )

        # Logger provider + OTLP exporter (http)
        self.provider = LoggerProvider(resource=resource)
        # OTLPLogExporter: endpoint örn. "http://LOKI_HOST:4318/otlp" veya collector endpoint
        self.exporter = OTLPLogExporter(endpoint=otlp_endpoint)
        self.processor = BatchLogRecordProcessor(self.exporter)
        self.provider.add_log_record_processor(self.processor)

        # Global provider (opsiyonel, ama get_logger kullanacağız)
        set_logger_provider(self.provider)

        # Python logging handler (sadece bizim logger'ımıza ekleyeceğiz)
        self.handler = LoggingHandler(
            level=logging.NOTSET, logger_provider=self.provider
        )

        # Bizim manuel logger'ımız (diğer kısımlardan gelecek otomatik loglardan izole)
        self.logger_name = logger_name
        self.py_logger = logging.getLogger(self.logger_name)
        self.py_logger.setLevel(logging.DEBUG)
        # Handler'ı yalnızca bizim logger'a ekliyoruz
        self.py_logger.addHandler(self.handler)

    def send(
        self,
        message: str,
        severity: str = "INFO",
        attrs: Optional[Dict[str, str]] = None,
    ):
        level = LEVEL_MAP.get(severity.upper(), logging.INFO)
        # OTel LoggingHandler, python logging record'u OTel LogRecord'a çevirip exporter'a verir.
        # Burada structured attributes için logging.extra kullanıyoruz:
        extra = {"otelAttributes": attrs or {}}
        # timestamp veya başka alan gerekiyorsa burada ekleyebilirsiniz.
        self.py_logger.log(level, message, extra=extra)

    def shutdown(self):
        try:
            # processor'ı / exporter'ı kapat
            self.processor.shutdown()
            self.exporter.shutdown()
        except Exception:
            pass
