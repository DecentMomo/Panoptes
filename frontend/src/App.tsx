import { Route, Routes } from "react-router-dom"

import { RequireAuth } from "@/components/RequireAuth"
import { LoginPage } from "@/pages/LoginPage"
import { ProjectsPage } from "@/pages/ProjectsPage"
import { RegisterPage } from "@/pages/RegisterPage"

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route element={<RequireAuth />}>
        <Route path="/" element={<ProjectsPage />} />
      </Route>
    </Routes>
  )
}
