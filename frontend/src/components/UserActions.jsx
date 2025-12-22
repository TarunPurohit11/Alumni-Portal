export default function UserActions({ user, toggleUser, deleteUser }) {
  if (user.role === "ADMIN") return null;

  return (
    <div className="flex space-x-3">
      <button
        onClick={() => toggleUser(user)}
        className={`px-3 py-1 rounded text-sm ${
          user.enabled
            ? "bg-orange-100 text-orange-700 hover:bg-orange-200"
            : "bg-green-100 text-green-700 hover:bg-green-200"
        }`}
      >
        {user.enabled ? "Disable" : "Enable"}
      </button>
      <button
        onClick={() => deleteUser(user.id)}
        className="px-3 py-1 rounded text-sm bg-red-100 text-red-700 hover:bg-red-200"
      >
        Delete
      </button>
    </div>
  );
}
