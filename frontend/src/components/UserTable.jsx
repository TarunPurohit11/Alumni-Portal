import UserActions from "./UserActions";

const getRoleColor = (role) => ({
  ADMIN: "bg-red-100 text-red-700",
  ALUMNI: "bg-indigo-100 text-indigo-700",
  STUDENT: "bg-green-100 text-green-700",
}[role] || "bg-gray-100 text-gray-700");

const getStatusColor = (enabled) => (enabled ? "text-green-600" : "text-red-600");

export default function UserTable({ users, toggleUser, deleteUser }) {
  return (
    <div className="bg-white border rounded-lg overflow-hidden">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            {["User", "Role", "Status", "Actions"].map((h) => (
              <th key={h} className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200">
          {users.map((u) => (
            <tr key={u.id} className="hover:bg-gray-50">
              <td className="px-6 py-4 flex items-center">
                <img src={u.profilePic || "/default-avatar.png"} alt="avatar" className="h-10 w-10 rounded-full mr-4" />
                <div>
                  <p className="font-medium text-gray-800">{u.name}</p>
                  <p className="text-xs text-gray-500">{u.username}</p>
                </div>
              </td>
              <td className="px-6 py-4">
                <span className={`px-3 py-1 rounded-full text-xs font-medium ${getRoleColor(u.role)}`}>{u.role}</span>
              </td>
              <td className="px-6 py-4 text-sm font-medium">
                <span className={getStatusColor(u.enabled)}>{u.enabled ? "ACTIVE" : "DISABLED"}</span>
              </td>
              <td className="px-6 py-4">
                <UserActions user={u} toggleUser={toggleUser} deleteUser={deleteUser} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
