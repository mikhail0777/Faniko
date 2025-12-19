import React, { createContext, useContext, useEffect, useState } from "react";

export type Role = "fan" | "creator";

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  role: Role;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string, username: string) => Promise<void>;
  logout: () => void;
  upgradeToCreator: (updates?: Partial<AuthUser>) => void;
}

const STORAGE_KEY = "faniko:user";

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Restore from localStorage
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        const parsed = JSON.parse(stored) as AuthUser;
        setUser(parsed);
      } catch {
        localStorage.removeItem(STORAGE_KEY);
      }
    }
    setLoading(false);
  }, []);

  function persist(next: AuthUser | null) {
    setUser(next);
    if (next) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  }

  // 🔐 Real login – uses backend /api/auth/login
  async function login(email: string, password: string) {
    const res = await fetch("http://localhost:4000/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: email.trim().toLowerCase(),
        password: password.trim(),
      }),
    });

    if (!res.ok) {
      let msg = "Login failed";
      try {
        const data = await res.json();
        if (data.error) msg = data.error;
      } catch {
        // ignore JSON parse errors
      }
      throw new Error(msg);
    }

    const data = (await res.json()) as {
      id: string;
      email: string;
      username: string;
      role: Role;
    };

    const authUser: AuthUser = {
      id: data.id,
      email: data.email,
      username: data.username.toLowerCase(),
      role: data.role,
    };

    persist(authUser);
  }

  // 🔹 Frontend-side signup: backend call is already done in Signup.tsx
  // This just stores the new user in local auth state as a fan.
  async function signup(email: string, _password: string, username: string) {
    // No backend call here – Signup.tsx already did /api/auth/signup
    const newUser: AuthUser = {
      id: "u_" + Date.now().toString(), // frontend-only ID (not used by backend)
      username: username.toLowerCase(),
      email: email.trim().toLowerCase(),
      role: "fan", // start as fan; later they can upgrade to creator
    };
    persist(newUser);
  }

  function logout() {
    persist(null);
  }

  // Called after CreatorSignup succeeds to upgrade the SAME account
  function upgradeToCreator(updates?: Partial<AuthUser>) {
    setUser((prev) => {
      if (!prev) return prev;
      const next: AuthUser = {
        ...prev,
        role: "creator",
        ...updates,
        username: (updates?.username ?? prev.username).toLowerCase(),
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      return next;
    });
  }

  const value: AuthContextValue = {
    user,
    loading,
    login,
    signup,
    logout,
    upgradeToCreator,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
