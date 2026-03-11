from typing import Any, Mapping, cast

from convex import ConvexClient

from .logging_provider import LOGGER


def build_convex_client(env: Mapping[str, str]) -> ConvexClient | None:
    convex_url = env.get("CONVEX_URL")
    if not convex_url:
        return None

    admin_key = env.get("CONVEX_ADMIN_KEY")
    auth_token = env.get("CONVEX_AUTH_TOKEN")
    client = None
    if admin_key or auth_token:
        try:
            client = cast(
                ConvexClient,
                cast(Any, ConvexClient)(
                    convex_url,
                    admin_key=admin_key,
                    auth_token=auth_token,
                ),
            )
        except TypeError:
            client = None

    if client is None:
        client = ConvexClient(convex_url)
        if auth_token and hasattr(client, "set_auth"):
            client.set_auth(auth_token)
        elif auth_token:
            LOGGER.warning(
                "auth token provided but Convex SDK does not support set_auth",
            )
        if admin_key:
            LOGGER.warning(
                "admin key provided but Convex SDK did not accept it in constructor",
            )
    return client
