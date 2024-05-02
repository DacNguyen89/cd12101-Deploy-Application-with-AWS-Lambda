import Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const jwksUrl = 'https://test-endpoint.auth0.com/.well-known/jwks.json'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJKCsag23KVhXfMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi01dml6N3h3eXAwMm9tYnZ5LnVzLmF1dGgwLmNvbTAeFw0yNDA1MDIw
NjM5MTBaFw0zODAxMDkwNjM5MTBaMCwxKjAoBgNVBAMTIWRldi01dml6N3h3eXAw
Mm9tYnZ5LnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAOgsNGvMlDewg3GEIcFwVWKmcrWmwSqdBzN0JjPltsmZHU8n42fVXSc4lxET
zpjQyhbQrIn/SC4rBqvsOaWoUxGKD1wJoKPBac8d1uZIEi7o1pG/8aIdkWj6NDlF
F2RiMSB7opLfyxkdgCEt0p326Q4lRI/wnafu1z6o7DpgML7Y2YMmR9089Cm4QQCR
jl8FvLOf8CD1UL3gOvVm9RHSy4IGeoNcgAOB4Ne0zWxl4ql0YQRl+nkYTOQF7mcO
T1DCULWObUXj1jWR8LXi84FsYXzqR4/FXy5zyiH8qOVeglpX2MRihdnhdZrYhHAe
Gtlq8X6XZNAf2L1aPS0P8O/gP+MCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUZ82NGKO3adTtiPzvdhMgxgUawvgwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQDcz68Kt+XdwqKLy5V+srpzRfLG5KtCz9dRqBJ+CU5z
u+ndo7ROxrNhqNpHNy4w9sbh2AStlPZ9ChFqbrHP7O+0wU4rlEveamqbw/u818Zf
IGNQkes2y3G4aAaHNG3zIKj459gCrRQerpcduIxGyapTYNdPVKK6OIHq0tAMXweK
9UtIM8/e3wDxFRrG7crdoFOqV4ygqYvez9rHHc0egJOHblT5RpgGYSb+kgmmSR/E
e71PM2GO9/VeLVQaqNKudwyrw+0DJWHS4gu+7WJ/wCqfC191EqKx/Ke66tretz8K
ciF9lIJxracIiYeNGeSE1+fbE7x0CG4ucJ4lNX1O6Z2l
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })

  // TODO: Implement token verification
  return jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
