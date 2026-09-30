import { useEffect, useRef, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { getExplanation, requestExplanation } from "@/api/findings"

export function useExplanation(findingId: number) {
  const queryClient = useQueryClient()
  const started = useRef(false)
  const [active, setActive] = useState(false)
  const explanation = useQuery({
    queryKey: ["explanation", findingId],
    queryFn: () => getExplanation(findingId),
    enabled: active,
    retry: false,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === "queued" || status === "running" ? 2000 : false
    },
  })
  const request = useMutation({
    mutationFn: () => requestExplanation(findingId),
    onSuccess: (data) => {
      queryClient.setQueryData(["explanation", findingId], data)
      setActive(true)
    },
  })

  useEffect(() => {
    if (Number.isFinite(findingId) && !started.current) {
      started.current = true
      request.mutate()
    }
  }, [findingId, request])

  function retry() {
    request.reset()
    request.mutate()
  }

  return { explanation, request, retry }
}
