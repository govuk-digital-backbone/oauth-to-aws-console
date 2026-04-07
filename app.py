import hashlib
import json
import logging
import os
import secrets
import string
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlencode

import apig_wsgi
import boto3
import jwt
import requests
import urllib3
from authlib.integrations.flask_client import OAuth
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    LoginTokenLoadError,
    MissingDependencyException,
    NoCredentialsError,
)
from flask import (
    Flask,
    Response,
    current_app,
    make_response,
    redirect,
    render_template_string,
    request,
)
from itsdangerous import BadSignature, BadTimeSignature, URLSafeTimedSerializer
from jwt import InvalidTokenError, PyJWKClient


DEFAULT_ISSUER = "https://sso.service.security.gov.uk"
DEFAULT_CONSOLE_DESTINATION = "https://console.aws.amazon.com/"
FEDERATION_ENDPOINT = "https://signin.aws.amazon.com/federation"
ERROR_TEMPLATE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign-in Error</title>
    <style>
      body { font-family: sans-serif; margin: 3rem auto; max-width: 40rem; padding: 0 1rem; }
      h1 { margin-bottom: 0.5rem; }
      p { line-height: 1.5; }
    </style>
  </head>
  <body>
    <h1>Sign-in failed</h1>
    <p>{{ message }}</p>
  </body>
</html>
"""
ALLOWED_SESSION_NAME_CHARS = set(string.ascii_letters + string.digits + "_=,.@-+")


logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
_aws_tls_warning_logged = False


class ConfigError(RuntimeError):
    """Raised when runtime configuration is incomplete or invalid."""


class AwsRoleAssumptionError(RuntimeError):
    """Raised when the app cannot initialize AWS credentials or assume the target role."""


@dataclass(slots=True)
class AppConfig:
    oidc_issuer: str = DEFAULT_ISSUER
    oidc_client_id: str = ""
    oidc_client_secret: str | None = None
    oidc_redirect_uri: str | None = None
    oidc_scopes: str = "openid email profile"
    oidc_email_claim: str = "email"
    oidc_email_verified_claim: str = "email_verified"
    app_secret_key: str = ""
    aws_role_arn: str = ""
    aws_console_destination: str = DEFAULT_CONSOLE_DESTINATION
    aws_use_source_identity: bool = False
    aws_verify_ssl: bool = True
    cookie_secure: bool = True
    state_cookie_name: str = "auth_state"
    state_ttl_seconds: int = 600
    jwt_leeway_seconds: int = 60

    @property
    def discovery_url(self) -> str:
        return f"{self.oidc_issuer}/.well-known/openid-configuration"


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_issuer(value: str | None) -> str:
    issuer = (value or DEFAULT_ISSUER).strip()
    return issuer.rstrip("/")


def load_config_from_env() -> AppConfig:
    return AppConfig(
        oidc_issuer=normalize_issuer(os.getenv("OIDC_ISSUER")),
        oidc_client_id=(os.getenv("OIDC_CLIENT_ID") or "").strip(),
        oidc_client_secret=(os.getenv("OIDC_CLIENT_SECRET") or "").strip() or None,
        oidc_redirect_uri=(os.getenv("OIDC_REDIRECT_URI") or "").strip() or None,
        oidc_scopes=(os.getenv("OIDC_SCOPES") or "openid email profile").strip(),
        oidc_email_claim=(os.getenv("OIDC_EMAIL_CLAIM") or "email").strip(),
        oidc_email_verified_claim=(
            os.getenv("OIDC_EMAIL_VERIFIED_CLAIM") or "email_verified"
        ).strip(),
        app_secret_key=(
            os.getenv("APP_SECRET_KEY") or secrets.token_urlsafe(32)
        ).strip(),
        aws_role_arn=(os.getenv("AWS_ROLE_ARN") or "").strip(),
        aws_console_destination=(
            os.getenv("AWS_CONSOLE_DESTINATION") or DEFAULT_CONSOLE_DESTINATION
        ).strip(),
        aws_use_source_identity=parse_bool(
            os.getenv("AWS_USE_SOURCE_IDENTITY"), default=False
        ),
        aws_verify_ssl=parse_bool(os.getenv("AWS_VERIFY_SSL"), default=True),
        cookie_secure=parse_bool(os.getenv("COOKIE_SECURE"), default=True),
        state_cookie_name=(os.getenv("STATE_COOKIE_NAME") or "auth_state").strip(),
        state_ttl_seconds=int(os.getenv("STATE_TTL_SECONDS", "600")),
        jwt_leeway_seconds=int(os.getenv("JWT_LEEWAY_SECONDS", "60")),
    )


def validate_runtime_config(config: AppConfig) -> None:
    missing = []
    if not config.oidc_issuer:
        missing.append("OIDC_ISSUER")
    if not config.oidc_client_id:
        missing.append("OIDC_CLIENT_ID")
    if not config.app_secret_key:
        missing.append("APP_SECRET_KEY")
    if not config.aws_role_arn:
        missing.append("AWS_ROLE_ARN")
    if missing:
        raise ConfigError(
            f"Missing required environment variables: {', '.join(missing)}"
        )


def get_runtime_config() -> AppConfig:
    config: AppConfig = current_app.config["BROKER_CONFIG"]
    validate_runtime_config(config)
    return config


def create_state_serializer(config: AppConfig) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(config.app_secret_key, salt="oidc-auth-state")


def issue_auth_state(config: AppConfig) -> tuple[str, str]:
    nonce = secrets.token_urlsafe(32)
    token = create_state_serializer(config).dumps({"nonce": nonce})
    return token, nonce


def decode_auth_state(state_token: str, config: AppConfig) -> dict[str, Any]:
    try:
        payload = create_state_serializer(config).loads(
            state_token, max_age=config.state_ttl_seconds
        )
    except BadTimeSignature as exc:
        raise ValueError("State token expired") from exc
    except BadSignature as exc:
        raise ValueError("State token failed signature validation") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("nonce"), str):
        raise ValueError("State token payload is invalid")
    return payload


def is_verified_claim(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    if isinstance(value, int):
        return value == 1
    return False


def extract_verified_email(
    claims: dict[str, Any],
    email_claim: str = "email",
    verified_claim: str = "email_verified",
) -> str:
    email = claims.get(email_claim)
    if (
        not isinstance(email, str)
        or not email
        or any(ch.isspace() for ch in email)
        or "@" not in email
    ):
        raise ValueError("Validated token does not contain a usable email address")
    if not is_verified_claim(claims.get(verified_claim)):
        raise ValueError(f"Validated token is missing a true {verified_claim} claim")
    return email


def sanitize_role_session_name(email: str) -> str:
    cleaned = "".join(ch if ch in ALLOWED_SESSION_NAME_CHARS else "-" for ch in email)
    if not cleaned:
        cleaned = "session"
    if len(cleaned) <= 64:
        return cleaned
    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:8]
    prefix = cleaned[:55].rstrip("-")
    if not prefix:
        prefix = "session"
    return f"{prefix}-{digest}"[:64]


@lru_cache(maxsize=8)
def get_jwk_client(jwks_uri: str) -> PyJWKClient:
    return PyJWKClient(jwks_uri)


def validate_id_token(
    id_token: str,
    config: AppConfig,
    expected_nonce: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    issuer = metadata.get("issuer") or config.oidc_issuer
    jwks_uri = metadata.get("jwks_uri")
    if not jwks_uri:
        raise ConfigError("OIDC discovery document is missing jwks_uri")

    signing_key = get_jwk_client(jwks_uri).get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=config.oidc_client_id,
        issuer=issuer,
        leeway=config.jwt_leeway_seconds,
        options={"require": ["aud", "exp", "iat", "iss", "nonce"]},
    )
    if claims.get("nonce") != expected_nonce:
        raise InvalidTokenError("ID token nonce did not match the stored nonce")
    return claims


def get_redirect_uri(config: AppConfig) -> str:
    return config.oidc_redirect_uri or request.url_root.rstrip("/") + "/auth/callback"


def mark_no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def set_state_cookie(response: Response, config: AppConfig, value: str) -> None:
    response.set_cookie(
        config.state_cookie_name,
        value,
        max_age=config.state_ttl_seconds,
        secure=config.cookie_secure,
        httponly=True,
        samesite="Lax",
        path="/",
    )


def clear_state_cookie(response: Response, config: AppConfig) -> None:
    response.delete_cookie(
        config.state_cookie_name,
        secure=config.cookie_secure,
        httponly=True,
        samesite="Lax",
        path="/",
    )


def render_error(
    message: str, status_code: int = 400, clear_state: bool = False
) -> Response:
    response = make_response(
        render_template_string(ERROR_TEMPLATE, message=message), status_code
    )
    if clear_state:
        try:
            config = current_app.config["BROKER_CONFIG"]
            clear_state_cookie(response, config)
        except Exception:
            logger.debug(
                "Could not clear state cookie while building error response",
                exc_info=True,
            )
    return mark_no_store(response)


def get_metadata(client: Any) -> dict[str, Any]:
    metadata = client.load_server_metadata()
    required_keys = ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer")
    missing = [key for key in required_keys if not metadata.get(key)]
    if missing:
        raise ConfigError(
            "OIDC discovery document is missing required fields: " + ", ".join(missing)
        )
    return metadata


def get_aws_tls_verify(config: AppConfig) -> bool:
    global _aws_tls_warning_logged

    if not config.aws_verify_ssl:
        if not _aws_tls_warning_logged:
            logger.warning(
                "AWS SSL certificate verification is disabled for AWS SDK and federation requests"
            )
            _aws_tls_warning_logged = True
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return config.aws_verify_ssl


def assume_target_role(email: str, config: AppConfig) -> dict[str, str]:
    try:
        sts_client = boto3.client("sts", verify=get_aws_tls_verify(config))
    except MissingDependencyException as exc:
        logger.error(
            "Failed to create the STS client because the active AWS credential provider "
            "requires awscrt. Install awscrt or botocore[crt] in this runtime."
        )
        raise AwsRoleAssumptionError(
            "AWS credentials require the awscrt package in this runtime."
        ) from exc
    except NoCredentialsError as exc:
        logger.error("No AWS credentials were available for the STS client")
        raise AwsRoleAssumptionError(
            "AWS credentials are not available for role assumption."
        ) from exc
    except LoginTokenLoadError as exc:
        logger.error("The local AWS login session has expired: %s", exc)
        raise AwsRoleAssumptionError(
            "The local AWS login session has expired. Run 'aws login' and try again."
        ) from exc
    except BotoCoreError as exc:
        logger.error("Failed to create the STS client: %s", exc)
        raise AwsRoleAssumptionError(
            "AWS credentials could not be initialized for role assumption."
        ) from exc

    assume_role_args: dict[str, Any] = {
        "RoleArn": config.aws_role_arn,
        "RoleSessionName": sanitize_role_session_name(email),
        "Tags": [{"Key": "Email", "Value": email}],
        "TransitiveTagKeys": ["Email"],
    }
    if config.aws_use_source_identity:
        assume_role_args["SourceIdentity"] = email

    try:
        response = sts_client.assume_role(**assume_role_args)
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        request_id = exc.response.get("ResponseMetadata", {}).get(
            "RequestId", "Unknown"
        )
        logger.error(
            "AssumeRole failed for target role %s with %s (request id %s)",
            config.aws_role_arn,
            error_code,
            request_id,
        )
        raise AwsRoleAssumptionError("AWS role assumption failed.") from exc
    except MissingDependencyException as exc:
        logger.error(
            "The active AWS credential provider requires awscrt during AssumeRole. "
            "Install awscrt or botocore[crt] in this runtime."
        )
        raise AwsRoleAssumptionError(
            "AWS credentials require the awscrt package in this runtime."
        ) from exc
    except NoCredentialsError as exc:
        logger.error("No AWS credentials were available while calling AssumeRole")
        raise AwsRoleAssumptionError(
            "AWS credentials are not available for role assumption."
        ) from exc
    except LoginTokenLoadError as exc:
        logger.error("The local AWS login session expired during AssumeRole: %s", exc)
        raise AwsRoleAssumptionError(
            "The local AWS login session has expired. Run 'aws login' and try again."
        ) from exc
    except BotoCoreError as exc:
        logger.error("Unexpected botocore error while calling AssumeRole: %s", exc)
        raise AwsRoleAssumptionError(
            "AWS role assumption could not be completed."
        ) from exc

    credentials = response["Credentials"]
    return {
        "AccessKeyId": credentials["AccessKeyId"],
        "SecretAccessKey": credentials["SecretAccessKey"],
        "SessionToken": credentials["SessionToken"],
    }


def get_signin_token(credentials: dict[str, str], config: AppConfig) -> str:
    session_payload = json.dumps(
        {
            "sessionId": credentials["AccessKeyId"],
            "sessionKey": credentials["SecretAccessKey"],
            "sessionToken": credentials["SessionToken"],
        },
        separators=(",", ":"),
    )
    response = requests.get(
        FEDERATION_ENDPOINT,
        params={"Action": "getSigninToken", "Session": session_payload},
        timeout=10,
        verify=get_aws_tls_verify(config),
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("SigninToken")
    if not token:
        raise ValueError("AWS federation endpoint did not return a SigninToken")
    return token


def build_console_signin_url(
    signin_token: str, destination: str, issuer: str | None = None
) -> str:
    params = {
        "Action": "login",
        "Destination": destination,
        "SigninToken": signin_token,
    }
    if issuer:
        params["Issuer"] = issuer
    return f"{FEDERATION_ENDPOINT}?{urlencode(params)}"


def create_console_signin_url(
    credentials: dict[str, str],
    config: AppConfig,
    destination: str,
    issuer: str | None = None,
) -> str:
    sign_in_token = get_signin_token(credentials, config)
    return build_console_signin_url(sign_in_token, destination, issuer)


def create_app(config: AppConfig | None = None) -> Flask:
    config = config or load_config_from_env()

    app = Flask(__name__)
    app.secret_key = config.app_secret_key or "missing-app-secret-key"
    app.config["BROKER_CONFIG"] = config

    oauth = OAuth(app)
    oauth.register(
        name="oidc",
        client_id=config.oidc_client_id or "missing-client-id",
        client_secret=config.oidc_client_secret,
        server_metadata_url=config.discovery_url,
        client_kwargs={"scope": config.oidc_scopes},
    )
    app.extensions["oidc_client"] = oauth.oidc

    @app.get("/healthz")
    def healthcheck() -> tuple[dict[str, str], int]:
        return {"status": "ok"}, 200

    @app.get("/")
    def start_login() -> Response:
        try:
            runtime_config = get_runtime_config()
            oidc_client = current_app.extensions["oidc_client"]
            get_metadata(oidc_client)
        except ConfigError as exc:
            logger.error("Configuration error while starting login: %s", exc)
            return render_error(
                "This sign-in service is not configured correctly.", 500
            )
        except Exception:
            logger.exception("Failed to load OIDC metadata")
            return render_error(
                "The identity provider metadata could not be loaded.", 502
            )

        state_token, nonce = issue_auth_state(runtime_config)
        redirect_uri = get_redirect_uri(runtime_config)

        authorization = oidc_client.create_authorization_url(
            redirect_uri=redirect_uri,
            response_type="code",
            state=state_token,
            nonce=nonce,
        )
        response = redirect(authorization["url"], code=302)
        set_state_cookie(response, runtime_config, state_token)
        return mark_no_store(response)

    @app.get("/auth/callback")
    def auth_callback() -> Response:
        try:
            runtime_config = get_runtime_config()
            oidc_client = current_app.extensions["oidc_client"]
            metadata = get_metadata(oidc_client)
        except ConfigError as exc:
            logger.error("Configuration error while handling callback: %s", exc)
            return render_error(
                "This sign-in service is not configured correctly.",
                500,
                clear_state=True,
            )
        except Exception:
            logger.exception("Failed to load OIDC metadata during callback")
            return render_error(
                "The identity provider metadata could not be loaded.",
                502,
                clear_state=True,
            )

        if request.args.get("error"):
            error = request.args.get("error", "access_denied")
            logger.warning("OIDC provider returned callback error %s", error)
            return render_error(
                "Authentication was cancelled or denied.", 400, clear_state=True
            )

        state_token = request.args.get("state", "")
        code = request.args.get("code", "")
        state_cookie = request.cookies.get(runtime_config.state_cookie_name)
        if not state_token or not state_cookie or state_cookie != state_token:
            logger.warning(
                "State validation failed because the callback state did not match the stored cookie"
            )
            return render_error(
                "The login session could not be verified.", 400, clear_state=True
            )

        try:
            state_payload = decode_auth_state(state_token, runtime_config)
        except ValueError as exc:
            logger.warning("State token validation failed: %s", exc)
            return render_error(
                "The login session is invalid or has expired.", 400, clear_state=True
            )

        if not code:
            logger.warning("OIDC callback was missing an authorization code")
            return render_error(
                "The identity provider did not return an authorization code.",
                400,
                clear_state=True,
            )

        try:
            token = oidc_client.fetch_access_token(
                redirect_uri=get_redirect_uri(runtime_config),
                grant_type="authorization_code",
                code=code,
            )
        except Exception:
            logger.exception("Token exchange failed")
            return render_error(
                "Token exchange with the identity provider failed.",
                502,
                clear_state=True,
            )

        id_token = token.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            logger.error("Token response did not include an id_token")
            return render_error(
                "The identity provider did not return an ID token.",
                502,
                clear_state=True,
            )

        try:
            claims = validate_id_token(
                id_token=id_token,
                config=runtime_config,
                expected_nonce=state_payload["nonce"],
                metadata=metadata,
            )
            email = extract_verified_email(
                claims,
                email_claim=runtime_config.oidc_email_claim,
                verified_claim=runtime_config.oidc_email_verified_claim,
            )
        except (InvalidTokenError, ValueError) as exc:
            logger.warning("ID token validation failed: %s", exc)
            return render_error(
                "The validated identity token did not contain a verified email.",
                403,
                clear_state=True,
            )

        try:
            credentials = assume_target_role(email, runtime_config)
        except AwsRoleAssumptionError as exc:
            return render_error(
                str(exc),
                502,
                clear_state=True,
            )

        try:
            sign_in_url = create_console_signin_url(
                credentials,
                runtime_config,
                runtime_config.aws_console_destination,
                issuer=request.url_root.rstrip("/"),
            )
        except Exception:
            logger.exception("Failed to create the AWS federation sign-in URL")
            return render_error(
                "AWS console sign-in could not be created.", 502, clear_state=True
            )

        response = redirect(sign_in_url, code=302)
        clear_state_cookie(response, runtime_config)
        return mark_no_store(response)

    return app


app = create_app()
handler = apig_wsgi.make_lambda_handler(app)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8085")), debug=False)
