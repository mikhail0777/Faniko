// src/BottomNav.tsx
import React from "react";
import { Link, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext";

export default function BottomNav() {
  const location = useLocation();
  const { user } = useAuth();

  const creatorTarget =
    user && user.role === "creator"
      ? `/creator/${user.username}/dashboard`
      : "/creator";

  const items = [
    { key: "home", label: "Home", to: "/" },
    { key: "explore", label: "Explore", to: "/explore" },
    {
      key: "creator",
      label: user?.role === "creator" ? "Dashboard" : "Creator",
      to: creatorTarget,
    },
    {
  key: "auth",
  label: user ? "Account" : "Log in",
  to: user ? "/account" : "/login",
},

  ];

  return (
    <nav className="fixed bottom-0 left-0 right-0 border-t border-gray-200 bg-white/90 backdrop-blur-md z-30">
      <div className="max-w-3xl mx-auto flex justify-around py-2 text-xs font-medium text-gray-600">
        {items.map((item) => {
          const active = location.pathname === item.to;
          return (
            <Link
              key={item.key}
              to={item.to}
              className={`flex flex-col items-center gap-1 px-3 ${
                active ? "text-brand-700" : "text-gray-500"
              }`}
            >
              <span className="text-lg">
                {item.key === "home" && "🏠"}
                {item.key === "explore" && "🔍"}
                {item.key === "creator" && "🎬"}
                {item.key === "auth" && (user ? "🙂" : "🔐")}
              </span>
              <span>{item.label}</span>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
