import { api } from "@/api/client"
import type { Project } from "@/types"

export function listProjects(): Promise<Project[]> {
  return api<Project[]>("/projects")
}

export function createProject(name: string, description: string): Promise<Project> {
  return api<Project>("/projects", {
    method: "POST",
    body: JSON.stringify({
      name,
      description: description.trim() ? description.trim() : null,
    }),
  })
}

export function deleteProject(id: number): Promise<void> {
  return api<void>(`/projects/${id}`, { method: "DELETE" })
}
