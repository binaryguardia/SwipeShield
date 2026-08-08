import { Routes, Route } from "react-router-dom"
import { RequireAuth } from "./auth"
import Nav from "./components/Nav"
import Login from "./pages/Login"
import Dashboard from "./pages/Dashboard"
import Sites from "./pages/Sites"
import SiteDetail from "./pages/SiteDetail"
import Fingerprints from "./pages/Fingerprints"

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="*"
        element={
          <RequireAuth>
            <div className="flex min-h-screen flex-col">
              <Nav />
              <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8">
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/sites" element={<Sites />} />
                  <Route path="/sites/:id" element={<SiteDetail />} />
                  <Route path="/fingerprint" element={<Fingerprints />} />
                  <Route path="*" element={<Dashboard />} />
                </Routes>
              </main>
            </div>
          </RequireAuth>
        }
      />
    </Routes>
  )
}
