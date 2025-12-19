import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";

export default function Account() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  if (!user) {
    // Route is protected anyway, but this is a safety check
    return null;
  }

  const isCreator = user.role === "creator";

  function handleLogout() {
    logout();
    navigate("/", { replace: true });
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md border rounded-2xl bg-white p-6 space-y-4 shadow-sm">
        <h1 className="text-xl font-extrabold">Your account</h1>
        <p className="text-sm text-gray-600">
          Logged in as{" "}
          <span className="font-semibold">@{user.username}</span>
        </p>
        <p className="text-xs text-gray-500 break-all">{user.email}</p>

        <div className="mt-4 space-y-3">
          {isCreator ? (
            <>
              <Link
                to={`/creator/${user.username}/dashboard`}
                className="block text-center rounded-2xl bg-gray-900 text-white px-4 py-2.5 text-sm font-semibold hover:bg-gray-800"
              >
                Go to creator dashboard
              </Link>
              <Link
                to={`/c/${user.username}`}
                className="block text-center rounded-2xl border border-gray-300 text-gray-900 px-4 py-2.5 text-sm font-semibold bg-white hover:bg-gray-50"
              >
                View your public profile
              </Link>
            </>
          ) : (
            <Link
              to="/creator"
              className="block text-center rounded-2xl border border-gray-300 text-gray-900 px-4 py-2.5 text-sm font-semibold bg-white hover:bg-gray-50"
            >
              Become a creator
            </Link>
          )}
        </div>

        <button
          onClick={handleLogout}
          className="w-full mt-4 rounded-2xl border border-red-200 text-red-600 px-4 py-2.5 text-sm font-semibold hover:bg-red-50"
        >
          Log out
        </button>

        <p className="text-[11px] text-gray-500 text-center mt-2">
          More account settings (payments, messages, notifications) will appear
          here as we build them.
        </p>
      </div>
    </div>
  );
}
