import { api } from "@/api/client"
import type { User } from "@/types"

export function register(email: string, password: string): Promise<User> {
  return api<User>("/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  })
}

export function login(email: string, password: string): Promise<User> {
  return api<User>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  })
}

export function logout(): Promise<void> {
  return api<void>("/auth/logout", { method: "POST" })
}

export function currentUser(): Promise<User> {
  return api<User>("/auth/me")
}
