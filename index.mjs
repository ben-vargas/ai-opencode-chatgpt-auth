import { generatePKCE } from "@openauthjs/openauth/pkce"
import { randomBytes, randomUUID } from "node:crypto"

const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
const AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
const TOKEN_URL = "https://auth.openai.com/oauth/token"
const REDIRECT_URI = "http://localhost:1455/auth/callback"
const SCOPE = "openid profile email offline_access"
const BASE_URL = "https://chatgpt.com/backend-api"

function createState() {
  return randomBytes(16).toString("hex")
}

function parseAuthorizationInput(input) {
  const value = input.trim()
  if (!value) return {}

  try {
    const url = new URL(value)
    return {
      code: url.searchParams.get("code") ?? undefined,
      state: url.searchParams.get("state") ?? undefined,
    }
  } catch {}

  const stripped = value.startsWith("http://") || value.startsWith("https://") ? value : `${REDIRECT_URI}?${value}`
  try {
    const url = new URL(stripped)
    return {
      code: url.searchParams.get("code") ?? undefined,
      state: url.searchParams.get("state") ?? undefined,
    }
  } catch {}

  if (value.includes("#")) {
    const [code, state] = value.split("#", 2)
    return { code, state }
  }

  if (value.includes("code=")) {
    const params = new URLSearchParams(value)
    return {
      code: params.get("code") ?? undefined,
      state: params.get("state") ?? undefined,
    }
  }

  return { code: value }
}

function extractAccountId(token) {
  if (!token) return undefined
  const parts = token.split(".")
  if (parts.length < 2) return undefined
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString())
    return (
      payload?.["https://api.openai.com/auth"]?.chatgpt_account_id ??
      payload?.["https://chatgpt.com/account_id"] ??
      payload?.account_id ??
      payload?.sub
    )
  } catch {
    return undefined
  }
}

async function exchangeAuthorizationCode(code, verifier) {
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code,
      code_verifier: verifier,
      redirect_uri: REDIRECT_URI,
    }),
  })

  if (!response.ok) {
    return { type: "failed" }
  }

  const json = await response.json()
  if (!json.refresh_token || !json.access_token || typeof json.expires_in !== "number") {
    return { type: "failed" }
  }

  return {
    type: "success",
    refresh: json.refresh_token,
    access: json.access_token,
    expires: Date.now() + json.expires_in * 1000,
  }
}

async function refreshAccessToken(refreshToken) {
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    }),
  })

  if (!response.ok) {
    return undefined
  }

  const json = await response.json()
  if (!json.access_token || typeof json.expires_in !== "number") {
    return undefined
  }

  return {
    access: json.access_token,
    refresh: json.refresh_token ?? refreshToken,
    expires: Date.now() + json.expires_in * 1000,
  }
}

/**
 * @type {import('@opencode-ai/plugin').Plugin}
 */
export async function OpenAIAuthPlugin({ client }) {
  return {
    auth: {
      provider: "openai",
      async loader(getAuth, provider) {
        const auth = await getAuth()
        if (auth?.type !== "oauth") return {}

        let accountId = extractAccountId(auth.access)
        return {
          apiKey: "",
          baseURL: BASE_URL,
          /**
           * @param {RequestInfo} input
           * @param {RequestInit} [init]
           */
          async fetch(input, init) {
            const current = await getAuth()
            if (!current || current.type !== "oauth") return fetch(input, init)

            let access = current.access
            let refresh = current.refresh
            let expires = current.expires

            if (!access || expires - Date.now() < 30_000) {
              const refreshed = await refreshAccessToken(refresh)
              if (!refreshed) return fetch(input, init)
              access = refreshed.access
              refresh = refreshed.refresh
              expires = refreshed.expires
              await client.auth.set({
                path: { id: "openai" },
                body: {
                  type: "oauth",
                  refresh,
                  access,
                  expires,
                },
              })
              accountId = extractAccountId(access) ?? accountId
            }

            const headers = new Headers(init?.headers ?? {})
            headers.delete("x-api-key")
            headers.set("authorization", `Bearer ${access}`)
            if (accountId) headers.set("chatgpt-account-id", accountId)
            headers.set("OpenAI-Beta", "responses=experimental")
            headers.set("originator", "codex_cli_rs")
            headers.set("session_id", randomUUID())
            return fetch(input, {
              ...init,
              headers,
            })
          },
        }
      },
      methods: [
        {
          label: "ChatGPT OAuth (Codex backend)",
          type: "oauth",
          authorize: async () => {
            const pkce = await generatePKCE()
            const state = createState()
            const url = new URL(AUTHORIZE_URL)
            url.searchParams.set("response_type", "code")
            url.searchParams.set("client_id", CLIENT_ID)
            url.searchParams.set("redirect_uri", REDIRECT_URI)
            url.searchParams.set("scope", SCOPE)
            url.searchParams.set("code_challenge", pkce.challenge)
            url.searchParams.set("code_challenge_method", "S256")
            url.searchParams.set("state", state)
            url.searchParams.set("id_token_add_organizations", "true")
            url.searchParams.set("codex_cli_simplified_flow", "true")

            return {
              url: url.toString(),
              instructions:
                "After completing the ChatGPT authorization, copy the full callback URL (http://localhost:1455/auth/callback?code=...&state=...) and paste it here:",
              method: "code",
              callback: async (input) => {
                const { code, state: returnedState } = parseAuthorizationInput(input)
                if (!code || returnedState !== state) {
                  return { type: "failed" }
                }
                return exchangeAuthorizationCode(code, pkce.verifier)
              },
            }
          },
        },
        {
          provider: "openai",
          label: "Manually enter API Key",
          type: "api",
        },
      ],
    },
  }
}

