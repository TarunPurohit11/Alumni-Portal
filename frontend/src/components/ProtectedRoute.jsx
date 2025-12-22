import { Navigate } from "react-router-dom";
import { useAuth } from "../context/useAuth"; // Assuming useAuth is defined/imported

export default function ProtectedRoute({ allowedRole, children }) {
  // Destructure isLoading
  const { user, isLoading } = useAuth(); 

  // 1. Show a loading state if data is still being checked
  if (isLoading) {
    return <div className="min-h-screen flex items-center justify-center text-xl text-indigo-600">Loading profile...</div>;
  }

  // 2. If loading is done AND user is null, redirect to login
  if (!user) return <Navigate to="/login" />;

  // 3. Role check
  if (allowedRole && allowedRole !== user.role) return <Navigate to="/unauthorized" />;

  // User is authenticated and authorized
  return children;
}