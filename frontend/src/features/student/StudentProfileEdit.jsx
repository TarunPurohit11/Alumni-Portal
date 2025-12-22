import React, { useState, useEffect } from 'react';
import { useAuth } from '../../context/useAuth'; 
import { User, Mail, Code, Star, Save, X } from 'lucide-react'; // Icons

// Renamed component to StudentProfileEdit
export default function StudentProfileEdit() {
  const { user, updateUserProfile } = useAuth(); // Assuming useAuth provides a way to update the profile

  // Initialize form state with current user data or defaults
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    techStackInput: '', 
    techStack: [],
    achievementsInput: '', 
    achievements: [],
  });

  const [message, setMessage] = useState('');

  // 1. Load user data when the component mounts
  useEffect(() => {
    if (user) {
      setFormData({
        username: user.username || '',
        email: user.email || '',
        techStackInput: '',
        techStack: user.techStack || [], // Ensure default is an array
        achievementsInput: '',
        achievements: user.achievements || [], // Ensure default is an array
      });
    }
  }, [user]);

  // Handle standard input changes (username, email)
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  // Handle adding a new Tech Stack item
  const handleAddTech = () => {
    const skill = formData.techStackInput.trim();
    if (skill && !formData.techStack.includes(skill)) {
      setFormData(prev => ({
        ...prev,
        techStack: [...prev.techStack, skill],
        techStackInput: '', // Clear input
      }));
    }
  };

  // Handle removing a Tech Stack item
  const handleRemoveTech = (skillToRemove) => {
    setFormData(prev => ({
      ...prev,
      techStack: prev.techStack.filter(skill => skill !== skillToRemove),
    }));
  };

  // Handle adding a new Achievement
  const handleAddAchievement = () => {
    const achievement = formData.achievementsInput.trim();
    if (achievement && !formData.achievements.includes(achievement)) {
      setFormData(prev => ({
        ...prev,
        achievements: [...prev.achievements, achievement],
        achievementsInput: '', // Clear input
      }));
    }
  };

  // Handle removing an Achievement
  const handleRemoveAchievement = (achievementToRemove) => {
    setFormData(prev => ({
      ...prev,
      achievements: prev.achievements.filter(ach => ach !== achievementToRemove),
    }));
  };

  // Handle Form Submission
  const handleSubmit = (e) => {
    e.preventDefault();
    setMessage('Saving profile...');

    // Prepare data to send (excluding the input fields)
    const profileUpdate = {
      username: formData.username,
      email: formData.email,
      techStack: formData.techStack,
      achievements: formData.achievements,
    };

    // --- Placeholder for actual API call ---
    new Promise((resolve) => setTimeout(resolve, 1500))
      .then(() => {
        // In a real app, you'd call an API and then update context:
        // if (updateUserProfile) { updateUserProfile(profileUpdate); }
        setMessage('Profile updated successfully! 🎉');
      })
      .catch(error => {
        setMessage(`Error updating profile: ${error.message}`);
      });
    // ---------------------------------------
  };

  return (
    <div className="min-h-screen bg-gray-50 pt-10 pb-16">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 border-b pb-2">Edit Your Profile</h1>
          <p className="mt-2 text-gray-500">Update your personal, technical, and achievement details.</p>
        </div>

        {/* Status Message */}
        {message && (
          <div className={`p-3 rounded-md mb-4 ${message.includes('Error') ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
            {message}
          </div>
        )}

        <form onSubmit={handleSubmit} className="bg-white p-8 rounded-xl shadow-lg border border-gray-100 space-y-8">

          {/* 1. Basic Information */}
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-gray-800 flex items-center gap-2"><User className="w-5 h-5"/> Basic Information</h2>
            
            {/* Username Field */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700">Full Name</label>
              <input
                type="text"
                name="username"
                id="username"
                value={formData.username}
                onChange={handleChange}
                required
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:ring-indigo-500 focus:border-indigo-500"
              />
            </div>

            {/* Email Field */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email Address</label>
              <input
                type="email"
                name="email"
                id="email"
                value={formData.email}
                onChange={handleChange}
                required
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:ring-indigo-500 focus:border-indigo-500"
              />
            </div>
          </div>

          <hr className="border-gray-200" />

          {/* 2. Tech Stack */}
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-gray-800 flex items-center gap-2"><Code className="w-5 h-5"/> Tech Stack</h2>
            
            <div className="flex flex-wrap gap-2 mb-4">
              {formData.techStack.map((tech, index) => (
                <span key={index} className="flex items-center px-3 py-1 text-sm font-medium text-indigo-700 bg-indigo-100 rounded-full">
                  {tech}
                  <button type="button" onClick={() => handleRemoveTech(tech)} className="ml-2 text-indigo-500 hover:text-indigo-700">
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>

            <div className="flex gap-3">
              <input
                type="text"
                name="techStackInput"
                placeholder="Enter a new skill (e.g., Python)"
                value={formData.techStackInput}
                onChange={handleChange}
                onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddTech())}
                className="block flex-grow border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:ring-indigo-500 focus:border-indigo-500"
              />
              <button 
                type="button" 
                onClick={handleAddTech}
                className="px-4 py-2 bg-indigo-600 text-white font-medium rounded-md hover:bg-indigo-700 transition"
              >
                Add Skill
              </button>
            </div>
          </div>

          <hr className="border-gray-200" />

          {/* 3. Achievements */}
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-gray-800 flex items-center gap-2"><Star className="w-5 h-5"/> Achievements</h2>

            <div className="flex flex-col gap-2 mb-4">
              {formData.achievements.map((ach, index) => (
                <div key={index} className="flex justify-between items-center p-2 bg-gray-50 rounded-md border border-gray-200">
                  <span className="text-sm text-gray-700">{ach}</span>
                  <button type="button" onClick={() => handleRemoveAchievement(ach)} className="text-red-500 hover:text-red-700">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
            
            <div className="flex gap-3">
              <input
                type="text"
                name="achievementsInput"
                placeholder="Enter a new achievement (e.g., Deans List 2024)"
                value={formData.achievementsInput}
                onChange={handleChange}
                onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddAchievement())}
                className="block flex-grow border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:ring-indigo-500 focus:border-indigo-500"
              />
              <button 
                type="button" 
                onClick={handleAddAchievement}
                className="px-4 py-2 bg-indigo-600 text-white font-medium rounded-md hover:bg-indigo-700 transition"
              >
                Add Achievement
              </button>
            </div>
          </div>
          
          <hr className="border-gray-200" />
          
          {/* Submission Button */}
          <div className="flex justify-end pt-4">
            <button
              type="submit"
              className="flex items-center gap-2 px-6 py-3 bg-green-600 text-white font-semibold rounded-md shadow-md hover:bg-green-700 transition focus:outline-none focus:ring-4 focus:ring-green-300"
            >
              <Save className="w-5 h-5" />
              Save Profile
            </button>
          </div>

        </form>
      </div>
    </div>
  );
}