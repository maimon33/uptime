# Authentication Guide

This project currently ships with a working `password/token` admin flow and now
prepares the stack for an optional `Cognito` path.

Important boundary:

- `Password mode` is fully active today.
- `Cognito mode` is also active today for direct `/admin` sign-in.
- The current app uses Cognito username/password plus Cognito challenges such
  as MFA or first-login password change.

Use this guide to choose the right path for your deployment.

## Option 1: Password Only

This is the current built-in auth flow.

How it works:

- CloudFormation stores an admin key in Secrets Manager.
- `/admin` asks for that key once.
- The browser stores it in session storage and sends it as a bearer token to
  `/api/*`.

Recommended hardening:

- Set `AdminAllowedIpCidrs` in CloudFormation.
- Keep the admin URL private.
- Rotate the admin key periodically.
- Prefer a long random key instead of a human password.

Example allowlist values:

```text
203.0.113.10/32
203.0.113.0/24,198.51.100.0/24
2001:db8::/48
```

Behavior of `AdminAllowedIpCidrs`:

- It protects `/admin` and `/api/*`.
- It does not affect the public status page.
- It checks the direct client IP or the first `X-Forwarded-For` address if the
  app is behind CloudFront.

When to use this:

- very small trusted team
- low login frequency
- you want the least setup today

## Option 2: Cognito

Cognito is the simplest AWS-native path if you want proper user identities,
optional MFA, and a cleaner long-term admin login story.

What the stack can provision now:

- Cognito User Pool
- Cognito User Pool Client
- optional Cognito managed-login domain
- TOTP-ready MFA configuration
- environment variables on the management Lambda for the app-side auth flow

Recommended Cognito settings:

- `AdminAuthMode=cognito`
- `CognitoMfaMode=OPTIONAL` or `ON`
- set `CognitoManagedDomainPrefix`
- optionally set `CognitoAllowedEmailDomain=your-company.com`

Defaults and what you usually need to touch:

- `AdminAuthMode`
  Default: `password`
  Set this to `cognito` to provision Cognito resources.
- `CognitoManagedDomainPrefix`
  No default. This is the main value you need to choose because it must be
  globally unique in the target AWS region.
- `CognitoAllowedEmailDomain`
  Default: empty
  Optional for now.
- `CognitoMfaMode`
  Default: `OPTIONAL`
  Usually safe to leave as-is for a first rollout.
- `AdminAllowedIpCidrs`
  Default: empty
  Optional, but still useful even when Cognito is provisioned.

Why TOTP is recommended:

- avoids SMS cost
- avoids delivery issues
- good fit for a handful of operators

What the app supports today:

- Cognito username/password sign-in at `/admin`
- MFA challenge handling
- first-login password-change challenge handling
- optional allowed-email-domain enforcement using Cognito user attributes

What is not the primary path yet:

- redirecting `/admin` to the Cognito hosted login page
- doing first-time TOTP enrollment directly inside the app when Cognito returns
  `MFA_SETUP`

## Fastest Cognito Setup

If you want the simplest possible path:

1. Pick a home region
2. Pick a globally unique Cognito domain prefix
3. Deploy the stack with `AdminAuthMode=cognito`
4. Create your first Cognito user
5. Open `/admin` and sign in with that Cognito user

Prep script:

```bash
./scripts/prepare-cognito-cf.sh eu-central-1 uptime my-uptime-admin maimons.dev
```

That script prints the exact `aws cloudformation deploy` command to run.

Post-deploy user creation:

```bash
./scripts/create-cognito-admin-user.sh eu-central-1 uptime you@maimons.dev
```

That script:

- reads the Cognito outputs from the CloudFormation stack
- creates the first Cognito admin user
- prints the managed-login domain if it exists

After that:

1. Open `/admin`
2. Sign in with the Cognito email and password
3. If Cognito requires a password change, enter the new password in the admin
   login prompt
4. If MFA is enabled, enter the authenticator code when prompted

If you set `CognitoAllowedEmailDomain`, the user email must match that domain.

## Choosing Between Them

Choose `password` if:

- you need the app working immediately with no extra identity setup
- you only have a few trusted operators
- you can add IP allowlisting for extra safety

Choose `cognito` if:

- you want real user identities
- you want MFA
- you want an eventual managed login page instead of a shared secret
- you expect the admin surface to matter more over time

## CloudFormation Parameters

Relevant parameters in `cloudformation/uptime-bootstrap.yaml`:

- `AdminApiKey`
- `AdminAuthMode`
- `AdminAllowedIpCidrs`
- `CognitoManagedDomainPrefix`
- `CognitoAllowedEmailDomain`
- `CognitoMfaMode`

### Simple Parameter Guidance

Use this if you want the minimum number of decisions:

- `AdminAuthMode=cognito`
- `CognitoManagedDomainPrefix=<pick-one-unique-value>`
- leave `CognitoMfaMode` at `OPTIONAL`
- leave `CognitoAllowedEmailDomain` empty unless you already know you want it
- leave `AdminAllowedIpCidrs` empty unless you want extra hardening now

Suggested examples:

Password-only with IP allowlist:

```bash
aws cloudformation deploy \
  --region eu-central-1 \
  --stack-name uptime \
  --template-url https://www.maimons.dev.s3.amazonaws.com/uptime/cloudformation/uptime-bootstrap.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    AdminAuthMode=password \
    AdminAllowedIpCidrs=203.0.113.10/32
```

Cognito-prepared deployment:

```bash
aws cloudformation deploy \
  --region eu-central-1 \
  --stack-name uptime \
  --template-url https://www.maimons.dev.s3.amazonaws.com/uptime/cloudformation/uptime-bootstrap.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    AdminAuthMode=cognito \
    CognitoManagedDomainPrefix=my-uptime-admin \
    CognitoAllowedEmailDomain=maimons.dev \
    CognitoMfaMode=OPTIONAL
```

Equivalent helper:

```bash
./scripts/prepare-cognito-cf.sh eu-central-1 uptime my-uptime-admin maimons.dev
```

Then create the first user:

```bash
./scripts/create-cognito-admin-user.sh eu-central-1 uptime you@maimons.dev
```

## Cost Notes

For a handful of operators with a few sign-ins per month:

- password mode has no extra auth service cost
- Cognito with local users and TOTP is usually negligible-to-free at this scale
- SMS MFA is the main thing to avoid if you want to keep cost simple

## Current Recommendation

Right now the best practical path is:

1. run `password + AdminAllowedIpCidrs` if you need immediate production use
2. provision `cognito` if you already know that is your target end state
3. use Cognito directly in `/admin` once the stack and user are in place
