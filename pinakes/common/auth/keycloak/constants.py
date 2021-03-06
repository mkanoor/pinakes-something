ADMIN_CLI_CLIENT_ID = "admin-cli"

REALM_PATH = "realms/{realm}"

WELL_KNOWN_PATH = f"{REALM_PATH}/.well-known"
OPENID_CONFIGURATION_PATH = f"{WELL_KNOWN_PATH}/openid-configuration"
UMA2_CONFIGURATION_PATH = f"{WELL_KNOWN_PATH}/uma2-configuration"

PROTECTION_PATH = f"{REALM_PATH}/authz/protection"
TOKEN_ENDPOINT = f"{REALM_PATH}/protocol/openid-connect/token"
END_SESSION_ENDPOINT = f"{REALM_PATH}/protocol/openid-connect/logout"
RESOURCE_REGISTRATION_ENDPOINT = f"{PROTECTION_PATH}/resource_set"
PERMISSION_ENDPOINT = f"{PROTECTION_PATH}/permission"
POLICY_ENDPOINT = f"{PROTECTION_PATH}/uma-policy"

PASSWORD_GRANT = "password"
CLIENT_CREDENTIALS_GRANT = "client_credentials"
REFRESH_TOKEN_GRANT = "refresh_token"
SESSION_LOGOUT_PATH = "realms/{realm}/protocol/openid-connect/logout"
GROUP_MEMBERS_PATH = "admin/realms/{realm}/groups/{id}/members"

UMA_TICKET_GRANT = "urn:ietf:params:oauth:grant-type:uma-ticket"

AUTHZ_RESPONSE_MODE_PERMISSIONS = "permissions"
AUTHZ_RESPONSE_MODE_DECISION = "decision"
