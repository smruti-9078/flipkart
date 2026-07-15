import React, {useState} from 'react'
import { useSelector } from 'react-redux';
import { Search, Eye, Trash2 } from 'lucide-react';

const AdminUsers = () => {
    const { users } = useSelector((store) => store.user);

  const [search, setSearch] = useState("");

  const filteredUsers = users?.filter(
    (user) =>
      user.fullName?.toLowerCase().includes(search.toLowerCase()) ||
      user.email?.toLowerCase().includes(search.toLowerCase())
  );

  const handleView = (id) => {
    console.log("View User:", id);
    // Navigate to user details page
  };

  const handleDelete = (id) => {
    console.log("Delete User:", id);
    // Delete API Call
  };
  return (
    <div className="min-h-screen bg-slate-50 p-8">

      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-center gap-4 mb-8">

        <h1 className="text-3xl font-bold text-gray-800">
          Users
        </h1>

        <div className="relative w-full md:w-80">
          <Search
            size={18}
            className="absolute left-3 top-3 text-gray-400"
          />

          <input
            type="text"
            placeholder="Search users..."
            className="w-full pl-10 pr-4 py-3 border rounded-xl outline-none focus:ring-2 focus:ring-blue-500"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

      </div>

      {/* Table */}
      <div className="bg-white rounded-xl shadow overflow-hidden">

        <table className="w-full">

          <thead className="bg-blue-600 text-white">
            <tr>
              <th className="p-4 text-left">Profile</th>
              <th className="p-4 text-left">Name</th>
              <th className="p-4 text-left">Email</th>
              <th className="p-4 text-left">Role</th>
              <th className="p-4 text-left">Status</th>
              <th className="p-4 text-center">Actions</th>
            </tr>
          </thead>

          <tbody>

            {filteredUsers?.length > 0 ? (
              filteredUsers.map((user) => (
                <tr
                  key={user._id}
                  className="border-b hover:bg-slate-50"
                >
                  <td className="p-4">
                    <img
                      src={
                        user.profilePicture ||
                        "https://ui-avatars.com/api/?name=User"
                      }
                      alt={user.fullName}
                      className="w-12 h-12 rounded-full object-cover border"
                    />
                  </td>

                  <td className="p-4 font-medium">
                    {user.fullName}
                  </td>

                  <td className="p-4">
                    {user.email}
                  </td>

                  <td className="p-4 capitalize">
                    {user.role}
                  </td>

                  <td className="p-4">
                    <span
                      className={`px-3 py-1 rounded-full text-sm font-medium ${
                        user.isActive
                          ? "bg-green-100 text-green-700"
                          : "bg-red-100 text-red-700"
                      }`}
                    >
                      {user.isActive ? "Active" : "Inactive"}
                    </span>
                  </td>

                  <td className="p-4">
                    <div className="flex justify-center gap-3">

                      <button
                        onClick={() => handleView(user._id)}
                        className="bg-blue-100 text-blue-600 p-2 rounded-lg hover:bg-blue-600 hover:text-white transition"
                      >
                        <Eye size={18} />
                      </button>

                      <button
                        onClick={() => handleDelete(user._id)}
                        className="bg-red-100 text-red-600 p-2 rounded-lg hover:bg-red-600 hover:text-white transition"
                      >
                        <Trash2 size={18} />
                      </button>

                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td
                  colSpan={6}
                  className="text-center py-10 text-gray-500"
                >
                  No Users Found
                </td>
              </tr>
            )}

          </tbody>

        </table>

      </div>
    </div>
  )
}

export default AdminUsers