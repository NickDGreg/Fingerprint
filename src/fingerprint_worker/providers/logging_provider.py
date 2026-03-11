import logging

from fingerprint_worker.config.env import WorkerConfig

LOGGER = logging.getLogger("fingerprint.worker")


def configure_logging(config: WorkerConfig) -> None:
    level = getattr(logging, config.log_level, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [worker] %(message)s",
    )
