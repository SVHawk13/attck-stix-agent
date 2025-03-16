def serve_api(
    host: str = "127.0.0.1", port: int = 8000, log_level: str = "info"
) -> None:
    from uvicorn import Config, Server

    from attck_stix_agent.api.api import api

    api_conf = Config(app=api, host=host, port=port, log_level=log_level)
    api_server = Server(config=api_conf)
    api_server.run()
