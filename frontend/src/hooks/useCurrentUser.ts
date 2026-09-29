import { useQuery } from "@tanstack/react-query"

import { currentUser } from "@/api/auth"

export function useCurrentUser() {
  return useQuery({
    queryKey: ["me"],
    queryFn: currentUser,
    retry: false,
  })
}
