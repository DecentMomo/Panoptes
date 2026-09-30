import { Route, Routes } from "react-router-dom"

import { RequireAuth } from "@/components/RequireAuth"
import { FindingPage } from "@/pages/FindingPage"
import { LoginPage } from "@/pages/LoginPage"
import { ProjectDetailPage } from "@/pages/ProjectDetailPage"
import { ProjectsPage } from "@/pages/ProjectsPage"
import { RegisterPage } from "@/pages/RegisterPage"
import { ScanPage } from "@/pages/ScanPage"

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route element={<RequireAuth />}>
        <Route path="/" element={<ProjectsPage />} />
        <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
        <Route path="/scans/:scanId" element={<ScanPage />} />
        <Route path="/findings/:findingId" element={<FindingPage />} />
      </Route>
    </Routes>
  )
}
