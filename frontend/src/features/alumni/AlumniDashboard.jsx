import React, { useState, useMemo } from 'react';
import { useAuth } from '../../context/useAuth'; 
import Navbar from '../../components/Navbar';
import { 
  FiMapPin, 
  FiBriefcase, 
  FiEdit3, 
  FiUsers, 
  FiUser, 
  FiMessageSquare, 
  FiCalendar, 
  FiUpload,
  FiShare2,
  FiLogOut,
  FiSave,
  FiX,
  FiCheckCircle
} from 'react-icons/fi';

// Helper function to capitalize the first letter of a string
const capitalize = (s) => s && s[0].toUpperCase() + s.slice(1).toLowerCase();

// --- MOCK EditAlumniProfile Component (for demonstration and execution) ---
// In a real application, this would be imported from a separate file:
// import EditAlumniProfile from './EditAlumniProfile'; 
const fetchAlumniProfile = (user, currentDetails) => {
    const displayName = user?.username 
        ? user.username.split('@')[0].replace(/[._]/g, ' ').split(' ').map(capitalize).join(' ')
        : "Alumni User";

    return {
        name: displayName,
        email: user?.username || '',
        role: user?.role || "Alumni", 
        // Use currentDetails for initialization if available
        ...currentDetails,
        bio: currentDetails.bio || "Experienced developer specializing in modern full-stack development and passionate about mentoring new talent.",
    };
};

function EditAlumniProfile({ user, currentDetails, onCancel, onSuccess }) { 
    const initialData = useMemo(() => fetchAlumniProfile(user, currentDetails), [user, currentDetails]);
    const [formData, setFormData] = useState(initialData);
    const [isSubmitting, setIsSubmitting] = useState(false);

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: type === 'checkbox' ? checked : value
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        console.log("Saving profile changes:", formData);

        // Simulate API call
        await new Promise(resolve => setTimeout(resolve, 1000)); 
        setIsSubmitting(false);

        if (onSuccess) {
            onSuccess(formData); 
        }
    };
    
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
                
                {/* Avatar section is simplified for the mock */}
                <div className="flex items-center space-x-6 pb-4 border-b border-gray-100">
                    <div className="w-24 h-24 bg-indigo-50 rounded-full border-4 border-indigo-100 flex items-center justify-center text-3xl font-bold text-indigo-600 shadow-inner">
                        {formData.name.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2)}
                    </div>
                    <div>
                        <p className="text-lg font-semibold text-gray-800">{formData.name}</p>
                    </div>
                </div>

                {/* Professional Details Section */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <InputField label="Email (Read-Only)" name="email" value={formData.email} disabled={true} />
                    <InputField label="Current Role" name="currentRole" value={formData.currentRole} icon={FiBriefcase} placeholder="e.g., Senior Software Engineer"/>
                    <InputField label="Company" name="currentCompany" value={formData.currentCompany} icon={FiBriefcase} placeholder="e.g., TechFlow Solutions"/>
                    <InputField label="Location" name="location" value={formData.location} icon={FiMapPin} placeholder="e.g., San Francisco, CA"/>
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
// --- END MOCK EditAlumniProfile Component ---


// Helper component for Quick Access links (Unchanged)
const QuickAccessLink = ({ icon: Icon, text, onClick }) => (
  <button
    className="flex items-center w-full p-3 rounded-lg text-left text-white transition duration-200 hover:bg-white/10"
    onClick={onClick}
  >
    <Icon className="mr-3 w-5 h-5" />
    <span className="text-base font-medium tracking-wide">{text}</span>
  </button>
);

// Sub-component for a profile detail item (Unchanged)
const DetailItem = ({ icon: Icon, label, value }) => (
  <div>
    <p className="uppercase text-xs font-semibold tracking-widest text-gray-500 mb-2">{label}</p>
    <div className="flex items-center">
      <Icon className="mr-2 w-4 h-4 text-indigo-500" /> 
      <span className="font-medium">{value}</span>
    </div>
  </div>
);

export default function AlumniDashboard() { 
  const { user, logout } = useAuth();
  const [resourceLink, setResourceLink] = useState('');
  
  // 1. State for View Toggle
  const [isEditing, setIsEditing] = useState(false); 

  // 2. State for Updatable Profile Details (Lifted from hardcoded values)
  const [profileDetails, setProfileDetails] = useState(() => ({
      currentRole: "Senior Software Engineer",
      currentCompany: "TechFlow Solutions",
      location: "San Francisco, CA",
      isAvailableToMentor: true,
      bio: "Experienced developer specializing in modern full-stack development and passionate about mentoring new talent.", // Added bio for edit page
  }));

  // --- Dynamic User Data Extraction (Now uses profileDetails state) ---
  const alumniData = useMemo(() => {
    let displayName = user?.username || "Alumni User";
    if (displayName.includes('@')) {
      displayName = displayName
        .split('@')[0]
        .replace(/[._]/g, ' ')
        .split(' ')
        .map(capitalize)
        .join(' ');
    } else {
      displayName = capitalize(displayName);
    }
    const initials = displayName.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2);

    return {
      name: displayName,
      initials: initials,
      role: user?.role || "Alumni",
      ...profileDetails 
    };
  }, [user, profileDetails]);
  // --- End Dynamic User Data Extraction ---

  const handleResourceUpload = () => {
    console.log(`Uploading resource link for ${alumniData.name}:`, resourceLink);
    alert(`Resource submitted: ${resourceLink}`);
    setResourceLink(''); 
  };
  
  // 3. Function to handle the successful update from the Edit page
  const handleProfileSuccess = (updatedData) => {
      // Update the state used by the dashboard
      setProfileDetails({
          currentRole: updatedData.currentRole,
          currentCompany: updatedData.currentCompany,
          location: updatedData.location,
          isAvailableToMentor: updatedData.isAvailableToMentor,
          bio: updatedData.bio, // Update the bio as well
      });
      setIsEditing(false); // Navigate back to the dashboard
  };


  // 4. Conditional Rendering (The "navigation" logic)
  if (isEditing) {
    return (
        <div className="min-h-screen bg-gray-100 font-sans antialiased p-6 sm:p-10">
            <EditAlumniProfile 
                user={user}
                currentDetails={profileDetails}
                onCancel={() => setIsEditing(false)} 
                onSuccess={handleProfileSuccess}
            />
        </div>
    );
  }

  // --- Original Dashboard View ---
  return (
    <div className="min-h-screen bg-gray-100 font-sans antialiased">
      
      {/* Global Navbar */}
      <Navbar user={user} logout={logout} />


      {/* Main Content Area */}
      <main className="p-6 sm:p-10">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Left/Main Column */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* Profile Card */}
            <div className="bg-white p-8 rounded-2xl shadow-xl transition duration-300 hover:shadow-2xl">
              <div className="flex justify-between items-start mb-6">
                
                <div className="flex items-center">
                  <div className="relative w-20 h-20 mr-5">
                    <div 
                      className="absolute inset-0 rounded-full p-0.5" 
                      style={{ 
                        background: 'linear-gradient(135deg, #6366F1, #9333EA)',
                        borderRadius: '9999px',
                        boxShadow: '0 0 10px rgba(99, 102, 241, 0.5)'
                      }}
                    >
                      <div className="w-full h-full bg-white rounded-full flex items-center justify-center text-2xl font-bold text-gray-600">
                        {alumniData.initials}
                      </div>
                    </div>
                  </div>

                  <div>
                    <h2 className="text-2xl font-bold text-gray-800 tracking-wide">{alumniData.name}</h2>
                    {alumniData.isAvailableToMentor && (
                      <span className="flex items-center text-xs font-semibold text-teal-700 bg-teal-100 px-3 py-1 rounded-full mt-2 w-fit shadow-sm">
                        <span className="w-2 h-2 mr-1 bg-teal-500 rounded-full animate-pulse"></span>
                        Available for Mentorship
                      </span>
                    )}
                  </div>
                </div>
                
                {/* 5. Update onClick handler to navigate */}
                <button 
                  className="flex items-center text-sm font-semibold text-gray-600 px-4 py-2 rounded-lg border border-gray-300 hover:bg-indigo-50 hover:text-indigo-700 transition duration-150 shadow-sm"
                  onClick={() => setIsEditing(true)} // <-- Navigation trigger
                >
                  <FiEdit3 className="mr-1 w-4 h-4" /> Edit Profile
                </button>
              </div>

              {/* Professional Details Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-base text-gray-700 pt-6 border-t border-gray-100">
                <DetailItem icon={FiBriefcase} label="Current Role" value={alumniData.currentRole} />
                <DetailItem icon={FiUsers} label="Company" value={alumniData.currentCompany} />
                <DetailItem icon={FiMapPin} label="Location" value={alumniData.location} />
              </div>
            </div>
            
            {/* Share Roadmap Resources Card (Action-oriented card) */}
            <div className="bg-white p-8 rounded-2xl shadow-xl border border-gray-100">
              <h3 className="flex items-center text-xl font-bold text-gray-800 mb-4">
                <FiShare2 className="text-indigo-600 mr-2 text-2xl" /> Contribute & Share Resources
              </h3>
              <p className="text-sm text-gray-600 mb-5 leading-relaxed">
                Empower the next generation by sharing valuable links to roadmaps, learning guides, or career-related articles.
              </p>
              <div className="flex flex-col sm:flex-row space-y-3 sm:space-y-0 sm:space-x-3">
                <input
                  type="url"
                  placeholder="Paste URL for resource (e.g., drive link, article)..."
                  value={resourceLink}
                  onChange={(e) => setResourceLink(e.target.value)}
                  className="flex-grow p-3.5 border border-gray-300 rounded-xl focus:ring-4 focus:ring-indigo-100 focus:border-indigo-500 outline-none transition duration-150 text-sm"
                />
                
                {/* Primary Gradient Button */}
                <button
                  onClick={handleResourceUpload}
                  disabled={!resourceLink.trim()}
                  className="flex items-center justify-center px-6 py-3 text-white font-semibold rounded-xl shadow-lg transition duration-150 transform hover:scale-[1.01] 
                             bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 disabled:from-gray-400 disabled:to-gray-500"
                >
                  <FiUpload className="mr-2 w-5 h-5" /> Submit Link
                </button>
              </div>
            </div>

          </div>

          {/* Right Column - Quick Access (Gradient Panel) */}
          <div className="lg:col-span-1">
            <div 
                className="p-6 rounded-2xl shadow-2xl text-white"
                style={{ 
                    background: 'linear-gradient(135deg, #4F46E5, #9333EA)',
                }}
            >
              <h3 className="text-xl font-extrabold mb-5 border-b border-white/20 pb-3 tracking-wider">Quick Access Panel</h3>
              <nav className="space-y-2">
                <QuickAccessLink icon={FiUsers} text="View Tech Groups" onClick={() => console.log('Tech Groups clicked')} />
                <QuickAccessLink icon={FiUser} text="Student Directory" onClick={() => console.log('Student Directory clicked')} />
                <QuickAccessLink icon={FiMessageSquare} text="Message Mentoring Requests" onClick={() => console.log('Messages clicked')} />
                <QuickAccessLink icon={FiCalendar} text="Alumni Events Calendar" onClick={() => console.log('Events clicked')} />
              </nav>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="p-5 text-center text-xs text-gray-500 bg-white border-t border-gray-100 mt-10">
        <p className="font-light">© 2024 IT Gopeswar Alumni Portal. All rights reserved. | <span className="font-medium text-indigo-600">{alumniData.role} Role Active</span></p>
      </footer>
    </div>
  );
}