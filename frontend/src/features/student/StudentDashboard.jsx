import React from "react";
import { useAuth } from "../../context/useAuth"; 
import { useNavigate } from "react-router-dom"; // <-- 1. Import useNavigate
import Navbar from "../../components/Navbar";
import StudentProfileCard from "./StudentProfileCard";
import QuickAccessCard from "./QuickAccessCard";

export default function StudentDashboard() {
  const { user, logout } = useAuth(); 
  const navigate = useNavigate(); // <-- 2. Initialize useNavigate

  // 3. Define the handler function
  const handleEditProfileClick = () => {
    // Navigates to the route where StudentProfileEdit component is rendered
    navigate('/edit-profile'); 
  };

  const username = user?.username || "Rahul Kumar";

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      
      {/* 1. Navbar */}
      <Navbar user={user} logout={logout} />
      
      <main className="flex-grow max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 pt-8 pb-12">
        
        {/* Dashboard Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Student Dashboard</h1>
          <p className="mt-1 text-md text-gray-500">Welcome back, {username}</p>
        </div>

        {/* Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Left Column: Student Profile (2/3 width) */}
          <div className="lg:col-span-2">
            {/* 4. Pass the handler function to the component */}
            <StudentProfileCard 
              user={user} 
              onEditClick={handleEditProfileClick} 
            />
          </div>
          
          {/* Right Column: Quick Access (1/3 width) */}
          <div className="lg:col-span-1">
            <QuickAccessCard />
          </div>
          
        </div>
      </main>

      {/* 3. Footer */}
      <footer className="w-full bg-gray-800 text-center py-4 mt-auto">
        <p className="text-sm text-gray-400">
          © 2024 IT Gopeshwar Alumni Portal. All rights reserved.
        </p>
      </footer>
    </div>
  );
}