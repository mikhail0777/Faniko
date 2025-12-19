import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useLocation,
  useParams,
} from "react-router-dom";

import Home from "./pages/Home";
import CreatorLanding from "./pages/CreatorLanding";
import CreatorSignup from "./pages/CreatorSignup";
import ExploreCreators from "./pages/ExploreCreators";
import CreatorProfile from "./pages/CreatorProfile";
import CreatorDashboard from "./pages/CreatorDashboard";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import Account from "./pages/Account";

import { AuthProvider, useAuth } from "./AuthContext";
import BottomNav from "./BottomNav";

function RequireAuth({
  children,
  role,
}: {
  children: JSX.Element;
  role?: "fan" | "creator";
}) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-gray-600">
        Loading…
      </div>
    );
  }

  if (!user) {
    return (
      <Navigate to="/login" replace state={{ from: location.pathname }} />
    );
  }

  if (role && user.role !== role) {
    return <Navigate to="/" replace />;
  }

  return children;
}

// Extra guard so you can't open someone ELSE's dashboard
function CreatorDashboardGuard() {
  const { user } = useAuth();
  const params = useParams();
  const routeUsername = (params.username || "").toLowerCase();

  if (!user) {
    return null;
  }

  if (user.role !== "creator") {
    return <Navigate to="/" replace />;
  }

  if (user.username.toLowerCase() !== routeUsername) {
    return (
      <Navigate
        to={`/creator/${user.username}/dashboard`}
        replace
      />
    );
  }

  return <CreatorDashboard />;
}

export default function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="min-h-screen pb-16 bg-gray-50">
          <Routes>
            {/* PUBLIC */}
            <Route path="/" element={<Home />} />
            <Route path="/creator" element={<CreatorLanding />} />
            <Route
  path="/creator/signup"
  element={
    <RequireAuth>
      <CreatorSignup />
    </RequireAuth>
  }
/>
            <Route path="/explore" element={<ExploreCreators />} />
            <Route path="/c/:username" element={<CreatorProfile />} />

            {/* AUTH PAGES */}
            <Route path="/login" element={<Login />} />
            <Route path="/signup" element={<Signup />} />

            {/* ACCOUNT (LOGOUT LIVES HERE) */}
            <Route
              path="/account"
              element={
                <RequireAuth>
                  <Account />
                </RequireAuth>
              }
            />

            {/* PROTECTED CREATOR DASHBOARD */}
            <Route
              path="/creator/:username/dashboard"
              element={
                <RequireAuth role="creator">
                  <CreatorDashboardGuard />
                </RequireAuth>
              }
            />

            {/* 404 */}
            <Route
              path="*"
              element={
                <div className="p-8 text-center text-gray-600">
                  Page not found
                </div>
              }
            />
          </Routes>

          <BottomNav />
        </div>
      </Router>
    </AuthProvider>
  );
}

