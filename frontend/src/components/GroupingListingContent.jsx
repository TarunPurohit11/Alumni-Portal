import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import useGroupAccessHandler from './GroupAccessHandler';

// --- Group Card Component ---
const GroupCard = ({ group, user, isJoined, onJoinGroup, onViewOpportunities }) => (
  <div
    className={`p-6 rounded-xl shadow-lg transition duration-300 flex flex-col h-full 
      ${isJoined ? 'bg-indigo-50 border-4 border-indigo-600' : 'bg-white border-4 border-gray-100 hover:shadow-xl'}`}
  >
    <div className="flex items-center mb-4">
      <h3 className="text-xl font-bold ml-4 text-gray-900">{group.title}</h3>
      {isJoined && (
        <span className="ml-auto text-xs font-bold text-indigo-700 bg-indigo-200 px-3 py-1 rounded-full">
          JOINED
        </span>
      )}
    </div>
    <p className="text-gray-600 mb-6 flex-grow text-sm">{group.description || group.content}</p>
    <div className="mt-auto space-y-2">

      {/* Join / Dashboard Button */}
      {user.role !== 'ADMIN' && !isJoined && (
        <button
          onClick={() => onJoinGroup(group.id)}
          className="w-full text-center px-4 py-2 text-sm font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white"
        >
          Join Group
        </button>
      )}

      {isJoined && (
        <button
          onClick={() => onJoinGroup(group.id)} // Use same handler to go to dashboard
          className="w-full text-center px-4 py-2 text-sm font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white"
        >
          Go to Dashboard
        </button>
      )}

      {/* View Opportunities Button - only for admins or joined users */}
      {(user.role === 'ADMIN' || isJoined) && (
        <button
          onClick={() => onViewOpportunities(group.id)}
          className="block w-full text-center px-4 py-2 text-sm font-semibold rounded-lg text-indigo-600 border border-indigo-600 hover:bg-indigo-50 transition duration-150"
        >
          View Opportunities
        </button>
      )}
    </div>
  </div>
);

// --- Main Component ---
const GroupingListingContent = ({ user }) => {
  const [joinedGroups, setJoinedGroups] = useState([]);
  const [allGroups, setAllGroups] = useState([]);
  const [loading, setLoading] = useState(true);

  const { handleGroupClick } = useGroupAccessHandler();
  const navigate = useNavigate();

  const fetchGroups = async () => {
    setLoading(true);
    try {
      const allRes = await axios.get('http://localhost:8080/api/groups/all?page=0&size=20', {
        headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
      });
      setAllGroups(allRes.data.content || []);

      if (user && (user.role === 'STUDENT' || user.role === 'ALUMNI')) {
        const username = encodeURIComponent(user.username);
        const joinedRes = await axios.get(
          `http://localhost:8080/api/groups/user/${username}?page=0&size=20`,
          { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } }
        );
        setJoinedGroups(Array.isArray(joinedRes.data?.content) ? joinedRes.data.content : []);
      } else if (user.role === 'ADMIN') {
        setJoinedGroups([]); // Admin sees all groups but not in "Your Groups"
      }

    } catch (err) {
      console.error('Failed to fetch groups', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGroups();
  }, [user]);

  const handleJoinGroup = async (groupId) => {
  try {
    // 1. Check if user is already a member or an ADMIN
    const alreadyJoined = joinedGroups.some(g => g.id === groupId);
    
    if (alreadyJoined || user.role === 'ADMIN') {
      // Direct access: they are already in, just go to the dashboard
      navigate(`/groups/${groupId}/view`);
      return;
    }

    /* 2. Trigger the Assessment Flow 
      We remove the axios.post('/join') because we don't want them 
      to join until they PROVE they are qualified via the test.
    */
    handleGroupClick(groupId); 
    
  } catch (err) {
    console.error("Navigation error:", err);
    alert('Could not process group access.');
  }
};

  const handleViewOpportunities = (groupId, isJoined) => {
    if (user.role === 'ADMIN' || isJoined) {
      navigate(`/groups/${groupId}/view`);
    } else {
      alert('Only admins or group members can view opportunities.');
    }
  };

  if (loading) return <p className="text-center py-20 text-gray-600">Loading groups...</p>;

  return (
    <section className="bg-white rounded-xl shadow-lg p-6">
      <div className="mx-auto px-0">
        {/* Joined Groups Section */}
        {joinedGroups.length > 0 && (
          <>
            <div className="text-left mb-6 border-b pb-4">
              <h2 className="text-3xl font-extrabold text-indigo-700 mb-2">🚀 Your Groups</h2>
              <p className="text-md text-gray-600">Quick access to your dashboards and member-only content.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
              {joinedGroups.map(group => (
                <GroupCard
                  key={group.id}
                  group={group}
                  user={user}
                  isJoined={true}
                  onJoinGroup={handleJoinGroup}
                  onViewOpportunities={(id) => handleViewOpportunities(id, true)}
                />
              ))}
            </div>
            <hr className="border-t border-gray-200 mb-12" />
          </>
        )}

        {/* Available Groups Section */}
        <div className="text-left mb-6 border-b pb-4">
          <h2 className="text-3xl font-extrabold text-gray-900">
            {joinedGroups.length > 0 ? 'Discover New Groups' : 'Explore All Groups'}
          </h2>
          <p className="text-md text-gray-600">Expand your skills by exploring these available communities.</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {allGroups.map(group => {
            const isJoined = joinedGroups.some(j => j.id === group.id);
            return (
              <GroupCard
                key={group.id}
                group={group}
                user={user}
                isJoined={isJoined}
                onJoinGroup={handleJoinGroup}
                onViewOpportunities={(id) => handleViewOpportunities(id, isJoined)}
              />
            );
          })}
        </div>
      </div>
    </section>
  );
};

export default GroupingListingContent;
