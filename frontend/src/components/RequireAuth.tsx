import { Navigate, Outlet } from "react-router-dom"

import { Skeleton } from "@/components/ui/skeleton"
import { useCurrentUser } from "@/hooks/useCurrentUser"

export function RequireAuth() {
  const me = useCurrentUser()

  if (me.isPending) {
    return (
      <main className="mx-auto flex min-h-svh w-full max-w-5xl flex-col gap-4 p-6">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-28 w-full" />
      </main>
    )
  }

  if (me.isError || !me.data) {
    return <Navigate to="/login" replace />
  }

  return <Outlet />
}
