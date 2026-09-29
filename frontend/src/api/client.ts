export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"])

function csrfToken(): string | null {
  const prefix = "csrf_token="
  const match = document.cookie.split("; ").find((part) => part.startsWith(prefix))
  return match ? decodeURIComponent(match.slice(prefix.length)) : null
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown }
    if (typeof body.detail === "string") {
      return body.detail
    }
  } catch {
    // The body was not JSON. Fall through to a generic message.
  }
  return "Something went wrong. Please try again."
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  const method = (options.method ?? "GET").toUpperCase()
  if (options.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }
  if (UNSAFE_METHODS.has(method)) {
    const token = csrfToken()
    if (token) {
      headers.set("X-CSRF-Token", token)
    }
  }

  const response = await fetch(`/api${path}`, { ...options, headers })
  if (response.status === 401 && path !== "/auth/me" && path !== "/auth/login") {
    window.location.assign("/login")
  }
  if (response.status === 204) {
    return undefined as T
  }
  if (!response.ok) {
    throw new ApiError(response.status, await errorMessage(response))
  }
  return (await response.json()) as T
}
