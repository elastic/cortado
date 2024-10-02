# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from typing import Any, AsyncGenerator, Sequence

import structlog
from elasticsearch import AsyncElasticsearch

ES_REQUEST_TIMEOUT_SECS = 30
SCROLL_QUERY_STEP_SIZE = 1000

DEFAULT_SCROLL_TTL = "2m"

EVENT_INGESTED_ORDER_DESC = {"event.ingested": {"order": "desc"}}

log = structlog.get_logger(__name__)


async def get_es_instance(cloud_id: str, api_key: str) -> AsyncElasticsearch:
    """Create an instance of Elasticsearch client"""
    es = AsyncElasticsearch(
        cloud_id=cloud_id,
        api_key=api_key,
        request_timeout=ES_REQUEST_TIMEOUT_SECS,
    )

    ping_result = await es.ping()
    if not ping_result:
        log.error("Elasticsearch is unreachable: ping failed", cloud_id=cloud_id)
        raise ValueError("Elasticsearch is unreachable")
    return es


async def stream_scrolled_query_results(
    es: AsyncElasticsearch,
    *,
    index: str,
    query: dict[str, Any],
    max_size: int,
    sort: list[dict[str, dict[str, str]]] | None = None,
    search_after: Sequence[Any] | None = None,
    step_size: int = SCROLL_QUERY_STEP_SIZE,
    scroll_ttl: str = DEFAULT_SCROLL_TTL,
) -> AsyncGenerator[dict[str, Any], None]:
    """Stream the results from Elasticsearch search scroll query"""
    log.debug(
        "Starting scroll search",
        index=index,
        max_size=max_size,
        scroll_ttl=scroll_ttl,
        step_size=step_size,
        search_after=search_after,
    )

    query_params: dict[str, Any] = {}
    if sort:
        query_params["sort"] = sort

    scroll_id = None
    counter = 0

    while True:
        if scroll_id:
            log.debug(
                "Fetching new scroll page",
                index=index,
                results_count=counter,
                max_size=max_size,
                step_size=step_size,
            )
            response = await es.scroll(scroll_id=scroll_id, scroll=scroll_ttl)
        else:
            # No scroll_id yet, send first search query to obtain one

            # Use smaller value in case `max_size` is smaller than `step_size`
            search_size = min(step_size, max_size)
            search_after = list(search_after) if search_after else None

            log.debug(
                "Fetching initial scroll page",
                index=index,
                results_count=counter,
                max_size=max_size,
                step_size=step_size,
            )

            response = await es.search(
                index=index,
                query=query,
                size=search_size,
                search_after=search_after,
                scroll=scroll_ttl,
                **query_params,
            )
            scroll_id = response.get("_scroll_id")

        hits = response.get("hits", {}).get("hits", [])

        if not hits:
            break

        for hit in hits:
            query_params["search_after"] = hit["sort"]

            yield hit["_source"]

            counter += 1

            if counter >= max_size:
                break

    log.debug("Finished scroll query", results_count=counter, query=query)


async def stream_detonation_events(
    cloud_id: str,
    cloud_api_key: str,
    *,
    agent_id: str,
    index_name: str = "logs-*",
    limit: int = 50000,
) -> AsyncGenerator[dict[str, Any], None]:
    """Stream detonation events for a specific agent."""

    es = await get_es_instance(cloud_id, cloud_api_key)

    query = {
        "bool": {
            "filter": [
                {"match_phrase": {"agent.type": "endpoint"}},
                {"match_phrase": {"agent.id": agent_id}},
            ]
        }
    }
    sort = [
        {"event.ingested": {"order": "desc"}},
        {"event.id": {"order": "asc"}},
    ]

    events_stream = stream_scrolled_query_results(
        es,
        index=index_name,
        query=query,
        max_size=limit,
        sort=sort,
    )

    async for event_doc in events_stream:
        yield event_doc

    await es.close()
