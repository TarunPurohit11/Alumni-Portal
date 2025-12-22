import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";

import ProtectedRoute from "./components/ProtectedRoute";

// Import your pages:
import Login from "./features/auth/Login";
import StudentDashboard from "./features/student/StudentDashboard";
import AlumniDashboard from "./features/alumni/AlumniDashboard";
import AdminDashboard from "./features/admin/AdminDashboard";
import Unauthorized from "./pages/Unauthorized";
import OAuth2RedirectHandler from "./features/auth/OAuth2RedirectHandler";
import Landing from "./pages/Landing";
import StudentProfileEdit from "./features/student/StudentProfileEdit";
import GroupAssessmentPage from "./pages/GroupAssessmentPage";
import TechGroupPage from "./pages/TechGroupPage";
import EventsAndAnnouncements from "./pages/EventsAndAnnouncements";
import AlumniDirectory from "./pages/AlumniDirectory";
import ProfileView from "./pages/ProfileView";
import TechGroup from "./pages/TechGroup";
import GroupAccessHandler from "./components/GroupAccessHandler";
import Message from "./pages/Message";
export default function App() {
  return (
    <Routes>

      {/* Public Routes */}
      <Route path = "/" element = {<Landing/>} />
      <Route path="/login" element={<Login />} />
      <Route path="/unauthorized" element={<Unauthorized />} />
      <Route path="/auth/success" element={<OAuth2RedirectHandler />} />
      <Route path="/tech/groups" element={<TechGroup />} />
      <Route path="/EventsAndAnnouncements" element={<EventsAndAnnouncements />} />
      <Route path="/AlumniDirectory" element={<AlumniDirectory />} />
      <Route path="/groups/:groupId/assessment" element={<GroupAssessmentPage />} />

      <Route
        path="/profile/:id"
        element={
          <ProtectedRoute>
            <ProfileView />
          </ProtectedRoute>
        }
      />
      <Route path="/messages" element={<ProtectedRoute><Message /></ProtectedRoute>} />
      
      {/* STUDENT ROUTES */}
      <Route
        path="/student/dashboard"
        element={
          <ProtectedRoute allowedRole="STUDENT">
            <StudentDashboard />
          </ProtectedRoute>
        }
      />

      <Route 
          path="/edit-profile" 
          element={<ProtectedRoute><StudentProfileEdit /></ProtectedRoute>} 
      />

      {/* ALUMNI ROUTES */}
      <Route
        path="/alumni/dashboard"
        element={
          <ProtectedRoute allowedRole="ALUMNI">
            <AlumniDashboard />
          </ProtectedRoute>
        }
      />

      {/* ADMIN ROUTES */}
      <Route
        path="/admin/dashboard"
        element={
          <ProtectedRoute allowedRole="ADMIN">
            <AdminDashboard />
          </ProtectedRoute>
        }
      />

      <Route
        path="/groups/:groupId"
        element={
          <ProtectedRoute>
            <GroupAccessHandler />
          </ProtectedRoute>
        }
      />

      <Route
        path="/groups/:groupId/assessment"
        element={
          <ProtectedRoute allowedRole="STUDENT">
            <GroupAssessmentPage />
          </ProtectedRoute>
        }
      />

      <Route
        path="/groups/:groupId/view"
        element={
          <ProtectedRoute>
            <TechGroupPage />
          </ProtectedRoute>
        }
      />


      {/* Default Route */}
      <Route path="*" element={<Navigate to="/login" />} />
    </Routes>
  );
}
