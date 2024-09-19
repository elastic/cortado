import logging
from typing import Any

import ecs_logging
import structlog
from elasticapm.handlers.structlog import structlog_processor  # type: ignore
from structlog.processors import CallsiteParameter

CUSTOM_ECS_FIELDS_ROOT_KEY = "cortado"


def normalise_eventdict_to_ecs(
    logger: logging.Logger,
    _: str,  # the name of the method is not used
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Normalise event dict into ECS-formatted dict suitable for `ecs_logging.StructlogFormatter`"""

    new_fields: dict[str, Any] = {}

    # Convert `func_name` field provided by `CallsiteParameter.FUNC_NAME` upstream into
    # ECS-compatible `log.origin.function`
    # https://www.elastic.co/guide/en/ecs/master/ecs-log.html#field-log-origin-function
    func_name = event_dict.pop("func_name", None)
    if func_name:
        new_fields["log.origin.function"] = func_name

    # https://www.elastic.co/guide/en/ecs/master/ecs-log.html#field-log-logger
    record = event_dict.pop("_record", None)
    if record is None:
        new_fields["log.logger"] = logger.name
    else:
        new_fields["log.logger"] = record.name

    # Fields needed for `ecs_logging.StructlogFormatter`
    root_fields = ("event",)

    # Collect custom fields that need to be sandboxed
    custom_fields = {k: v for k, v in event_dict.items() if k not in root_fields}

    # Drop custom fields from the root level
    for k in custom_fields.keys():
        event_dict.pop(k)

    # Capitalise custom fields to avoid collisions with the default field names
    event_dict[CUSTOM_ECS_FIELDS_ROOT_KEY] = {k.capitalize(): v for k, v in custom_fields.items()}
    event_dict.update(new_fields)
    return event_dict


def configure_logging(logging_level: int = logging.DEBUG, as_json: bool = False, root_logger_name: str = "cortado"):
    """Configure logging level and log output format for the root logger.

    By default, logging level is set to DEBUG and logs are printed to stderr as plain text.
    If `as_json` set to `True`, logs are printed as JSON-formatted ECS-valid lines.
    """

    with_colors = False if as_json else True

    # remove all configured log handlers before we set up our own
    for name in logging.root.manager.loggerDict.keys():
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True

    if as_json:
        attr_processors: list[Any] = []
        additional_processors: list[Any] = [
            structlog.processors.format_exc_info,
            normalise_eventdict_to_ecs,
            # Extend event dict with APM tracing properties
            structlog_processor,
            ecs_logging.StructlogFormatter(),
        ]
    else:
        attr_processors: list[Any] = [
            # Add the name of the logger to event dict
            structlog.stdlib.add_logger_name,
            # Add log level to event dict
            structlog.stdlib.add_log_level,
            # Add a timestamp in ISO 8601 format
            structlog.processors.TimeStamper(fmt="iso"),
        ]
        additional_processors: list[Any] = [
            # If the "stack_info" key in the event dict is true, remove it and
            # render the current stack trace in the "stack" key
            structlog.processors.StackInfoRenderer(),
            # Wrapping is needed in order to use formatter down the stream
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ]

    structlog.configure(
        processors=(
            [
                # If log level is too low, abort pipeline and throw away log entry
                structlog.stdlib.filter_by_level,
            ]  # type: ignore
            + attr_processors
            + [
                # Perform %-style formatting
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.CallsiteParameterAdder([CallsiteParameter.FUNC_NAME]),
            ]
            + additional_processors
        ),
        # `wrapper_class` is the bound logger that you get back from get_logger()
        wrapper_class=structlog.stdlib.BoundLogger,
        # `logger_factory` is used to create wrapped loggers that are used for OUTPUT
        logger_factory=structlog.stdlib.LoggerFactory(),
        # Effectively freeze configuration after creating the first bound logger.
        cache_logger_on_first_use=True,
    )

    # Warnings issued by the ``warnings`` module will be redirected to the ``py.warnings`` logger
    logging.captureWarnings(True)

    cortado_root_logger: structlog.stdlib.BoundLogger = structlog.get_logger(root_logger_name)
    cortado_root_logger.setLevel(logging_level)

    # if `as_json` is `True`, event dict will contain only ECS-serialised message
    # that can be sent to `ConsoleRenderer` for output
    renderer = structlog.dev.ConsoleRenderer(colors=with_colors, pad_event=10)
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=attr_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    # https://www.structlog.org/en/stable/standard-library.html#rendering-using-structlog-based-formatters-within-logging
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handlers = [handler]

    # Reset handlers on a root logger
    logging.getLogger().handlers = handlers  # type: ignore
