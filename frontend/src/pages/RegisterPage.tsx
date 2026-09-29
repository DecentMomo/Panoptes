import { useState, type FormEvent } from "react"
import { Link, Navigate, useNavigate } from "react-router-dom"
import { toast } from "sonner"

import { register } from "@/api/auth"
import { ApiError } from "@/api/client"
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

export function RegisterPage() {
  const me = useCurrentUser()
  const navigate = useNavigate()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  if (me.data) {
    return <Navigate to="/" replace />
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    if (!email.includes("@")) {
      setFormError("Enter a valid email address.")
      return
    }
    if (password.length < 8) {
      setFormError("Password must be at least 8 characters.")
      return
    }
    setFormError(null)
    setPending(true)
    try {
      await register(email, password)
      toast.success("Account created. Log in to continue.")
      navigate("/login")
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Could not register."
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
          <CardTitle className="text-2xl">Create an account</CardTitle>
          <CardDescription>Panoptes keeps each project private to its owner.</CardDescription>
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
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>
            {formError ? <p className="text-sm text-destructive">{formError}</p> : null}
            <Button type="submit" disabled={pending}>
              {pending ? "Creating account…" : "Register"}
            </Button>
            <p className="text-sm text-muted-foreground">
              Already registered?{" "}
              <Link className="text-foreground underline underline-offset-4" to="/login">
                Log in
              </Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
