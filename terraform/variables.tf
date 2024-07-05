variable "oidc_url" {
  type = string
  default = "https://login.pst.oneidfederation.ehealthontario.ca/sso/oauth2/realms/root/realms/idaaspstoidc/.well-known/openid-configuration"
}

variable "expiredTokenExempted" {
  type = string
  default = "true"
}