import React, { useState, useEffect } from 'react';
import { useAuth } from '../../context/useAuth'; 
// Note: Assuming FiSave and FiX for save and cancel icons
import { FiSave, FiX, FiMapPin, FiBriefcase, FiCheckCircle, FiUpload } from 'react-icons/fi';

// Helper function to capitalize (used for displaying the role)
const capitalize = (s) => s && s[0].toUpperCase() + s.slice(1).toLowerCase();

// --- Mock Data Setup (Replace this with actual API fetching later) ---
const fetchAlumniProfile = (user) => {
    // In a real app, this would be an async API call.
    // We use the same fallback/default data structure from the dashboard.
    const displayName = user?.username 
        ? user.username.split('@')[0].replace(/[._]/g, ' ').split(' ').map(capitalize).join(' ')
        : "Alumni User";

    return {
        name: displayName,
        email: user?.username || '',
        role: user?.role || "Alumni", 
        isAvailableToMentor: true,
        currentRole: "Senior Software Engineer",
        currentCompany: "TechFlow Solutions",
        location: "San Francisco, CA",
        bio: "Experienced developer specializing in modern full-stack development and passionate about mentoring new talent.",
    };
};
// --- End Mock Data Setup ---


export default function EditAlumniProfile({ onCancel, onSuccess }) { 
    const { user } = useAuth();
    // 1. Initialize form state
    const [formData, setFormData] = useState(fetchAlumniProfile(user));
    const [isSubmitting, setIsSubmitting] = useState(false);

    // 2. Handle input changes
    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: type === 'checkbox' ? checked : value
        }));
    };

    // 3. Handle form submission (Placeholder for API call)
    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        console.log("Saving profile changes:", formData);

        // --- Simulated API Call ---
        await new Promise(resolve => setTimeout(resolve, 1500)); 
        // --- End Simulated API Call ---

        setIsSubmitting(false);

        if (onSuccess) {
            alert("Profile successfully updated!");
            onSuccess(formData); // Pass updated data back to parent if needed
        }
    };
    
    // Helper for rendering form inputs
    const InputField = ({ label, name, value, type = 'text', icon: Icon, placeholder, disabled = false }) => (
        <div className="flex flex-col space-y-1">
            <label htmlFor={name} className="text-sm font-medium text-gray-700">{label}</label>
            <div className="relative">
                {Icon && <Icon className="absolute left-3 top-3 w-4 h-4 text-gray-400" />}
                <input
                    type={type}
                    id={name}
                    name={name}
                    value={value}
                    onChange={handleChange}
                    placeholder={placeholder}
                    disabled={disabled}
                    className={`w-full p-3 pl-${Icon ? '10' : '3'} border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition duration-150 text-sm ${disabled ? 'bg-gray-50 cursor-not-allowed' : 'bg-white'}`}
                />
            </div>
        </div>
    );

    return (
        <div className="max-w-4xl mx-auto p-8 bg-white rounded-2xl shadow-xl">
            <h2 className="text-3xl font-bold text-gray-800 mb-2 border-b border-gray-100 pb-3">
                Edit Your Alumni Profile 
            </h2>
            <p className="text-gray-500 mb-6">Update your professional details and mentorship status.</p>

            <form onSubmit={handleSubmit} className="space-y-6">
                
                {/* Profile Picture/Avatar Upload (Placeholder) */}
                <div className="flex items-center space-x-6 pb-4 border-b border-gray-100">
                    <div className="w-24 h-24 bg-indigo-50 rounded-full border-4 border-indigo-100 flex items-center justify-center text-3xl font-bold text-indigo-600 shadow-inner">
                        {formData.name.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2)}
                    </div>
                    <div>
                        <p className="text-lg font-semibold text-gray-800">{formData.name}</p>
                        <button
                            type="button"
                            className="mt-2 flex items-center px-4 py-2 bg-gray-100 text-gray-700 text-sm font-medium rounded-lg hover:bg-gray-200 transition duration-150"
                            onClick={() => console.log('Upload avatar clicked')}
                        >
                            <FiUpload className="mr-2" /> Upload New Photo
                        </button>
                    </div>
                </div>

                {/* Professional Details Section */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <InputField 
                        label="Email (Read-Only)" 
                        name="email" 
                        value={formData.email} 
                        disabled={true} 
                        placeholder="Your contact email"
                    />
                    <InputField 
                        label="Current Role" 
                        name="currentRole" 
                        value={formData.currentRole} 
                        icon={FiBriefcase}
                        placeholder="e.g., Senior Software Engineer"
                    />
                    <InputField 
                        label="Company" 
                        name="currentCompany" 
                        value={formData.currentCompany} 
                        icon={FiBriefcase}
                        placeholder="e.g., TechFlow Solutions"
                    />
                    <InputField 
                        label="Location" 
                        name="location" 
                        value={formData.location} 
                        icon={FiMapPin}
                        placeholder="e.g., San Francisco, CA"
                    />
                </div>

                {/* Bio/About Section */}
                <div className="flex flex-col space-y-1">
                    <label htmlFor="bio" className="text-sm font-medium text-gray-700">Biography / About Me</label>
                    <textarea
                        id="bio"
                        name="bio"
                        value={formData.bio}
                        onChange={handleChange}
                        rows="4"
                        placeholder="Tell us about your career and expertise..."
                        className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition duration-150 text-sm"
                    />
                </div>

                {/* Mentorship Checkbox */}
                <div className="flex items-start pt-4 border-t border-gray-100">
                    <input
                        type="checkbox"
                        id="isAvailableToMentor"
                        name="isAvailableToMentor"
                        checked={formData.isAvailableToMentor}
                        onChange={handleChange}
                        className="mt-1 w-5 h-5 text-indigo-600 bg-gray-100 border-gray-300 rounded focus:ring-indigo-500"
                    />
                    <div className="ml-3">
                        <label htmlFor="isAvailableToMentor" className="text-sm font-medium text-gray-700 flex items-center">
                            <FiCheckCircle className="mr-1 w-4 h-4 text-green-500" />
                            Open to Mentorship
                        </label>
                        <p className="text-xs text-gray-500 mt-1">
                            Check this box to allow current students and recent graduates to reach out for career guidance.
                        </p>
                    </div>
                </div>

                {/* Action Buttons */}
                <div className="flex justify-end space-x-3 pt-6">
                    <button
                        type="button"
                        onClick={onCancel}
                        className="flex items-center px-6 py-3 border border-gray-300 text-gray-700 font-semibold rounded-xl hover:bg-gray-100 transition duration-150"
                    >
                        <FiX className="mr-2 w-5 h-5" /> Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={isSubmitting}
                        className="flex items-center px-6 py-3 text-white font-semibold rounded-xl shadow-lg transition duration-150 transform hover:scale-[1.01] 
                             bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 disabled:from-gray-400 disabled:to-gray-500"
                    >
                        {isSubmitting ? (
                            <>
                                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                                Saving...
                            </>
                        ) : (
                            <>
                                <FiSave className="mr-2 w-5 h-5" /> Save Changes
                            </>
                        )}
                    </button>
                </div>
            </form>
        </div>
    );
}