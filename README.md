# OIDC to AWS Console Broker

> [!WARNING]
> This broker is intended as a small, deployment-specific integration for one OIDC provider and one AWS access pattern, not as a drop-in authentication component for general reuse. If you adapt it for any other environment, review the design carefully before doing so.

Minimal AWS Lambda broker for `https://sso.service.security.gov.uk` that:

1. starts an OIDC authorization code flow,
2. validates the returned ID token,
3. extracts a verified email address,
4. assumes a role with an `Email` session tag (for use with things like QuickSight),
5. exchanges the temporary credentials for an AWS federation sign-in token,
6. redirects the browser into the AWS console.

The app is intentionally small: one Flask app, one Lambda handler, no database, no frontend framework.

## OIDC metadata

The issuer exposes the endpoints needed for the flow:

- `issuer`: `https://sso.service.security.gov.uk`
- `authorization_endpoint`: `https://sso.service.security.gov.uk/auth/oidc`
- `token_endpoint`: `https://sso.service.security.gov.uk/auth/token`
- `jwks_uri`: `https://sso.service.security.gov.uk/.well-known/jwks.json`
- `userinfo_endpoint`: `https://sso.service.security.gov.uk/auth/profile`

One caveat remains: the discovery document advertises `email`, but not `email_verified`. This app still requires a truthy verified-email claim and fails closed if it is missing or false. If the provider uses a different claim name, set `OIDC_EMAIL_VERIFIED_CLAIM` accordingly.

## Files

- `app.py`: Flask app, Lambda handler, OIDC validation, STS assume-role, federation redirect
- `build.sh`: zip packaging script for Lambda
- `pyproject.toml`: project metadata and runtime dependencies
- `tests/test_app.py`: focused unit tests

## Environment variables

Required:

- `OIDC_CLIENT_ID`
- `APP_SECRET_KEY`

Usually required:

- `OIDC_CLIENT_SECRET`

Defaults:

- `OIDC_ISSUER=https://sso.service.security.gov.uk`
- `AWS_ROLE_ARN=arn:aws:iam::123456789012:role/ROLE_NAME`
- `AWS_CONSOLE_DESTINATION=https://console.aws.amazon.com/`
- `OIDC_SCOPES=openid email profile`
- `OIDC_EMAIL_CLAIM=email`
- `OIDC_EMAIL_VERIFIED_CLAIM=email_verified`
- `AWS_VERIFY_SSL=true`
- `COOKIE_SECURE=true`
- `STATE_COOKIE_NAME=auth_state`
- `STATE_TTL_SECONDS=600`
- `JWT_LEEWAY_SECONDS=60`
- `AWS_USE_SOURCE_IDENTITY=false`

Optional:

- `OIDC_REDIRECT_URI`
  - If unset, the app derives it as `<current-origin>/auth/callback`

## Local run

Create a virtualenv and install from the project metadata:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Start the app:

```bash
export OIDC_ISSUER="https://sso.service.security.gov.uk"
export OIDC_CLIENT_ID="..."
export OIDC_CLIENT_SECRET="..."
export AWS_ROLE_ARN="arn:aws:iam::123456789012:role/ROLE_NAME"
export COOKIE_SECURE="false"
python app.py
```

Then visit `http://localhost:8085/`.

If your local AWS environment uses the newer login provider and the cached token is expired, refresh it first:

```bash
aws login
```

If you are working around a local CA or proxy issue, you can temporarily disable AWS TLS verification:

```bash
export AWS_VERIFY_SSL="false"
```

That disables certificate verification for both boto STS calls and the AWS federation request. Leave it at the default `true` outside local troubleshooting.

Your OIDC client must allow `http://localhost:8085/auth/callback` for local testing.

## Tests

Run:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Covered:

- verified email extraction
- session-name sanitisation
- state and nonce round-trip and tamper detection
- federation login URL construction

## Build

Build the Lambda zip:

```bash
chmod +x build.sh
./build.sh
```

This creates `dist/lambda.zip`. The script reads dependencies from `pyproject.toml` and downloads Linux-compatible wheels for Python 3.12.
This creates `dist/lambda.zip` by running `pip install .` into a target directory and downloading Linux-compatible wheels for Python 3.12.

## Manual deployment

1. Create or update a Python 3.12 Lambda function.
2. Upload `dist/lambda.zip`.
3. Set the handler to `app.handler`.
4. Configure the function environment variables.
5. Create a Lambda Function URL with `AuthType=NONE`.
6. Register `<function-url>/auth/callback` with the OIDC provider.
7. Visit `<function-url>/`.

If you want a fixed callback URL, set `OIDC_REDIRECT_URI` explicitly to `<function-url>/auth/callback`.

## IAM policy for the Lambda execution role

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowWriteLambdaLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Sid": "AllowAssumeTaggedTargetRole",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity"
      ],
      "Resource": "arn:aws:iam::123456789012:role/ROLE_NAME"
    }
  ]
}
```

If `AWS_USE_SOURCE_IDENTITY=false`, `sts:SetSourceIdentity` is not used at runtime and can be removed.

## Trust policy snippet for the target role (`arn:aws:iam::123456789012:role/ROLE_NAME`)

Replace the principal ARN with the Lambda execution role ARN:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaBrokerRoleAssumption",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<lambda-account-id>:role/<lambda-execution-role-name>"
      },
      "Action": [
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity"
      ]
    }
  ]
}
```

If `AWS_USE_SOURCE_IDENTITY=false`, `sts:SetSourceIdentity` can be removed here too.

## Login flow

1. `GET /` loads issuer metadata and redirects to the OIDC authorisation endpoint.
2. The app stores a signed `state` value containing a nonce in an HTTP-only cookie.
3. `GET /auth/callback` verifies the query `state` against the cookie and checks the signed payload expiry.
4. The Lambda exchanges the authorization code for tokens.
5. The app validates the ID token signature, issuer, audience, expiry, and nonce.
6. The app extracts a verified email from the validated token.
7. The Lambda calls `AssumeRole` on target role with:
   - `RoleSessionName` derived from the email
   - `Tags=[{"Key":"Email","Value":<verified email>}]`
   - `TransitiveTagKeys=["Email"]`
   - `SourceIdentity=<verified email>` only when enabled
8. The temporary credentials are exchanged for an AWS federation sign-in token.
9. The browser is redirected into the AWS console.

## Known limitations

- The app rejects logins unless the validated token includes a truthy verified-email claim.
- State is browser-bound via a signed cookie rather than server-side storage.
- The AWS sign-in URL is sensitive and is never logged.
- The implementation is intentionally single-purpose and does not support multiple target roles.
- `AWS_VERIFY_SSL=false` is a local troubleshooting workaround, not a production setting.

## Assumptions

- The provider issues an ID token in the authorization code flow and signs it with the published JWKS.
- The token includes `email` plus a claim that can be configured as the verified-email flag.
- The Lambda execution role is allowed to call `sts:AssumeRole` and `sts:TagSession` on the target role.
- The target role trust policy allows the Lambda execution role to assume it.
