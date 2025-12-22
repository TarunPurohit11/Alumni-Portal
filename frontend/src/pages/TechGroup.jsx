// src/pages/TechGroup.jsx

import React from "react";
import { useAuth } from "../context/AuthContext";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import QuickAccessCard from "../features/student/QuickAccessCard";
import GroupingListingContent from "../components/GroupingListingContent";

export default function TechGroup() {
  const { user, logout, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-screen text-gray-700">
        Loading...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Navbar */}
      <Navbar user={user} logout={logout} />

      {/* Main Content */}
      <main className="flex-grow max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 pt-10 pb-16">
        {/* Hub Header */}
        <div className="mb-10 text-center bg-white p-6 rounded-xl shadow-md border-t-4 border-indigo-600">
          <h1 className="text-4xl font-extrabold text-gray-900">
            Tech Group Central Hub
          </h1>
          <p className="mt-2 text-lg text-gray-600">
            Welcome, {user?.username || "Guest User"}. Find your next project or community.
          </p>
        </div>

        {/* Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Groups Section */}
          <div className="lg:col-span-3">
            <GroupingListingContent user={user} />
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-1">
            <div className="sticky top-8">
              <QuickAccessCard />
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
}
