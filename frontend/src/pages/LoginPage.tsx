import { useState, type FormEvent } from "react"
import { Navigate, Link, useNavigate } from "react-router-dom"
import { useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

import { ApiError } from "@/api/client"
import { login } from "@/api/auth"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useCurrentUser } from "@/hooks/useCurrentUser"

export function LoginPage() {
  const me = useCurrentUser()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  if (me.data) {
    return <Navigate to="/" replace />
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    if (!email.includes("@") || password.length < 8) {
      setFormError("Enter a valid email and a password of at least 8 characters.")
      return
    }
    setFormError(null)
    setPending(true)
    try {
      const user = await login(email, password)
      queryClient.setQueryData(["me"], user)
      navigate("/")
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Could not log in."
      setFormError(message)
      toast.error(message)
    } finally {
      setPending(false)
    }
  }

  return (
    <main className="flex min-h-svh items-center justify-center p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">Panoptes</CardTitle>
          <CardDescription>Log in to see your projects.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="flex flex-col gap-4" onSubmit={onSubmit}>
            <div className="flex flex-col gap-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>
            {formError ? <p className="text-sm text-destructive">{formError}</p> : null}
            <Button type="submit" disabled={pending}>
              {pending ? "Logging in…" : "Log in"}
            </Button>
            <p className="text-sm text-muted-foreground">
              No account?{" "}
              <Link className="text-foreground underline underline-offset-4" to="/register">
                Register
              </Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
