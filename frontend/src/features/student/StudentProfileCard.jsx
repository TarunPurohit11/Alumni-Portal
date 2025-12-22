import React from 'react';
import { Edit } from 'lucide-react'; 

// Component now expects an onEditClick function as a prop
export default function StudentProfileCard({ user, onEditClick }) {
  // Mock data for fallback, ensure these arrays exist for safety
  const mockData = {
    username: 'Rahul Kumar',
    email: 'student@college.edu',
    techStack: ['React', 'Java'], // Added sample data for clarity
    achievements: ['Hackathon Winner'], 
  };
  
  // Use user prop, defaulting to mockData if user is null/undefined
  const userData = { ...mockData, ...(user || {}) }; 
  
  const initials = userData.username.split(' ').map(n => n[0]).join('');

  return (
    <div className="bg-white p-6 rounded-xl shadow-lg border border-gray-100 min-h-[300px]">
      
      {/* Profile Header */}
      <div className="flex justify-between items-start mb-6 border-b pb-4">
        <div className="flex items-center gap-4">
          <div className="w-16 h-16 rounded-full bg-indigo-500 flex items-center justify-center text-white text-2xl font-semibold">
            {initials}
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-800">{userData.username}</h2>
            <p className="text-sm text-gray-500">{userData.email}</p>
          </div>
        </div>
        {/* ACTION: Added onClick handler using the passed prop */}
        <button 
          onClick={onEditClick} // <-- This prop will trigger navigation
          className="flex items-center text-sm text-gray-600 hover:text-indigo-600 transition cursor-pointer"
        >
          <Edit className="w-4 h-4 mr-1" /> Edit Profile
        </button>
      </div>

      {/* Tech Stack Section */}
      <div className="mb-6">
        <h3 className="text-xs font-bold uppercase text-gray-500 tracking-wider mb-2">TECH STACK</h3>
        <div className="flex flex-wrap gap-2">
          {userData.techStack?.map((tech, index) => ( 
            <span key={index} className="px-3 py-1 text-sm font-medium text-indigo-700 bg-indigo-100 rounded-full">
              {tech}
            </span>
          ))}
        </div>
      </div>

      {/* Achievements Section */}
      <div>
        <h3 className="text-xs font-bold uppercase text-gray-500 tracking-wider mb-2">ACHIEVEMENTS</h3>
        <div className="text-gray-700">
          {userData.achievements?.length > 0 ? (
            <ul className="list-none space-y-1">
              {userData.achievements.map((item, index) => (
                <li key={index} className="text-sm">{item}</li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-gray-500">No achievements listed yet.</p>
          )}
        </div>
      </div>

    </div>
  );
}