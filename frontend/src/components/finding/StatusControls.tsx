import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

import { ApiError } from "@/api/client"
import { listHistory, updateStatus } from "@/api/findings"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"

const STATUSES = ["open", "fixed", "false_positive", "accepted_risk"] as const

export function StatusControls({
  findingId,
  status,
}: {
  findingId: number
  status: string
}) {
  const queryClient = useQueryClient()
  const [nextStatus, setNextStatus] = useState<(typeof STATUSES)[number] | null>(null)
  const [reason, setReason] = useState("")
  const history = useQuery({
    queryKey: ["finding-history", findingId],
    queryFn: () => listHistory(findingId),
  })
  const change = useMutation({
    mutationFn: (body: { status: (typeof STATUSES)[number]; reason?: string }) =>
      updateStatus(findingId, body),
    onSuccess: async () => {
      setNextStatus(null)
      setReason("")
      await queryClient.invalidateQueries({ queryKey: ["finding", findingId] })
      await queryClient.invalidateQueries({ queryKey: ["finding-history", findingId] })
      toast.success("Status updated")
    },
    onError: (error) => {
      toast.error(error instanceof ApiError ? error.message : "Could not update the status.")
    },
  })

  function choose(value: (typeof STATUSES)[number]) {
    if (value === "false_positive") {
      setReason("")
      setNextStatus(value)
      return
    }
    change.mutate({ status: value })
  }

  const reasonMissing = nextStatus === "false_positive" && reason.trim() === ""

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {STATUSES.map((value) => (
          <Button
            key={value}
            type="button"
            variant={status === value ? "default" : "outline"}
            disabled={change.isPending || status === value}
            onClick={() => choose(value)}
          >
            {value.replaceAll("_", " ")}
          </Button>
        ))}
      </div>
      <Dialog open={nextStatus !== null} onOpenChange={(open) => !open && setNextStatus(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Mark as false positive</DialogTitle>
            <DialogDescription>A reason is required and is kept in the history.</DialogDescription>
          </DialogHeader>
          <textarea
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            className="min-h-24 w-full rounded-md border border-border bg-background p-3 text-sm"
          />
          <DialogFooter>
            <Button
              type="button"
              disabled={reasonMissing || change.isPending}
              onClick={() => change.mutate({ status: "false_positive", reason: reason.trim() })}
            >
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <div className="space-y-2">
        <h2 className="text-sm font-medium">Status history</h2>
        {history.data && history.data.length > 0 ? (
          <ul className="space-y-2 text-sm text-muted-foreground">
            {history.data.map((item) => (
              <li key={item.id}>
                {item.from_status} to {item.to_status} by {item.user_email}
                {item.reason ? ` · ${item.reason}` : ""}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No status changes yet.</p>
        )}
      </div>
    </section>
  )
}
