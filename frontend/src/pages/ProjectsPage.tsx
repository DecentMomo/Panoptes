import { useState, type FormEvent } from "react"
import { useNavigate } from "react-router-dom"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

import { logout } from "@/api/auth"
import { ApiError } from "@/api/client"
import { createProject, deleteProject, listProjects } from "@/api/projects"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { useCurrentUser } from "@/hooks/useCurrentUser"
import type { Project } from "@/types"

export function ProjectsPage() {
  const me = useCurrentUser()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const projects = useQuery({ queryKey: ["projects"], queryFn: listProjects })
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [formError, setFormError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Project | null>(null)
  const [deleting, setDeleting] = useState(false)

  async function onLogout() {
    try {
      await logout()
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Could not log out."
      toast.error(message)
      return
    }
    queryClient.clear()
    navigate("/login")
  }

  async function onCreate(event: FormEvent) {
    event.preventDefault()
    if (!name.trim()) {
      setFormError("A project needs a name.")
      return
    }
    setFormError(null)
    setCreating(true)
    try {
      await createProject(name.trim(), description)
      await queryClient.invalidateQueries({ queryKey: ["projects"] })
      setCreateOpen(false)
      setName("")
      setDescription("")
      toast.success("Project created")
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Could not create the project."
      setFormError(message)
      toast.error(message)
    } finally {
      setCreating(false)
    }
  }

  async function onDelete() {
    if (!deleteTarget) {
      return
    }
    setDeleting(true)
    try {
      await deleteProject(deleteTarget.id)
      await queryClient.invalidateQueries({ queryKey: ["projects"] })
      setDeleteTarget(null)
      toast.success("Project deleted")
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Could not delete the project."
      toast.error(message)
    } finally {
      setDeleting(false)
    }
  }

  return (
    <main className="mx-auto flex min-h-svh w-full max-w-5xl flex-col gap-6 p-6">
      <header className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-medium">Projects</h1>
          <p className="text-sm text-muted-foreground">{me.data?.email}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={() => setCreateOpen(true)}>New project</Button>
          <Button variant="outline" onClick={onLogout}>
            Log out
          </Button>
        </div>
      </header>

      {projects.isPending ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      ) : projects.isError ? (
        <Card>
          <CardHeader>
            <CardTitle>Could not load projects</CardTitle>
            <CardDescription>Refresh the page and try again.</CardDescription>
          </CardHeader>
        </Card>
      ) : projects.data.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>No projects yet</CardTitle>
            <CardDescription>
              Create a project, then upload code to scan it. Scanning arrives in the next phase.
            </CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {projects.data.map((project) => (
            <Card key={project.id}>
              <CardHeader>
                <CardTitle>{project.name}</CardTitle>
                <CardDescription>
                  {project.description?.trim() ? project.description : "No description"}
                </CardDescription>
              </CardHeader>
              <CardContent className="flex items-center justify-between gap-3">
                <span className="text-sm text-muted-foreground">No scans yet</span>
                <Button variant="destructive" onClick={() => setDeleteTarget(project)}>
                  Delete
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New project</DialogTitle>
            <DialogDescription>A project is a codebase you want to scan.</DialogDescription>
          </DialogHeader>
          <form className="flex flex-col gap-4" onSubmit={onCreate}>
            <div className="flex flex-col gap-2">
              <Label htmlFor="project-name">Name</Label>
              <Input
                id="project-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="project-description">Description</Label>
              <Input
                id="project-description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </div>
            {formError ? <p className="text-sm text-destructive">{formError}</p> : null}
            <DialogFooter>
              <Button type="submit" disabled={creating}>
                {creating ? "Creating…" : "Create"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteTarget !== null} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {deleteTarget?.name}?</DialogTitle>
            <DialogDescription>This cannot be undone.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onDelete} disabled={deleting}>
              {deleting ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  )
}
