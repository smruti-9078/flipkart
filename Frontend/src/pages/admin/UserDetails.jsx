import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import { ArrowLeft, Mail, Phone, Shield, User } from "lucide-react";
import { toast } from "sonner";

const UserDetails = () => {
  const params = useParams();
  const userId = params.userId || params.id;
  const navigate = useNavigate();

  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const fetchUser = async () => {
      if (!userId) {
        setLoading(false);
        return;
      }

      try {
        setLoading(true);

        const token = localStorage.getItem("accessToken");

        const res = await axios.get(
          `http://localhost:8000/api/user/get-user/${userId}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (!mounted) return;

        if (res.data.success) {
          const u = res.data.user || {};
          setUser({
            ...u,
            name: `${u.firstName || ""} ${u.lastName || ""}`.trim(),
            profileImage: u.profilePic || u.profileImage || "",
            phone: u.phoneNo || u.phone || "",
            status: u.status || (u.isVerified ? "Active" : "Active"),
          });
        }
      } catch (error) {
        if (!mounted) return;
        console.log(error);
        toast.error(error.response?.data?.message || "Failed to fetch user");
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [userId]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-[70vh]">
        <div className="text-xl font-semibold animate-pulse">
          Loading User...
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="text-center mt-20 text-red-500 text-xl">
        User not found.
      </div>
    );
  }

  return (
    <div className="p-18 bg-gray-100 min-h-screen">
      {/* Header */}

      <div className="flex items-center justify-between mb-6">
        <button
          onClick={() => navigate(-1)}
          className="flex items-center gap-2 bg-white px-4 py-2 rounded-lg shadow hover:bg-gray-200 transition"
        >
          <ArrowLeft size={18} />
          Back
        </button>

        <h1 className="text-3xl font-bold text-gray-800">
          User Details
        </h1>
      </div>

      {/* Profile Card */}

      <div className="bg-white rounded-xl shadow-lg p-8">
        <div className="flex flex-col md:flex-row items-center gap-8">

          <img
            src={
              user.profileImage ||
              "https://cdn-icons-png.flaticon.com/512/149/149071.png"
            }
            alt=""
            className="w-36 h-36 rounded-full border-4 border-blue-500 object-cover"
          />

          <div className="flex-1">

            <h2 className="text-3xl font-bold text-gray-800">
              {user.name}
            </h2>

            <p className="text-gray-500">
              Joined on{" "}
              {new Date(user.createdAt).toLocaleDateString()}
            </p>

            <div className="grid md:grid-cols-2 gap-4 mt-6">

              <div className="flex items-center gap-3">
                <Mail className="text-blue-500" />
                <span>{user.email}</span>
              </div>

              <div className="flex items-center gap-3">
                <Phone className="text-green-500" />
                <span>{user.phone || "Not Available"}</span>
              </div>

              <div className="flex items-center gap-3">
                <Shield className="text-purple-500" />
                <span className="capitalize">{user.role}</span>
              </div>

              <div className="flex items-center gap-3">
                <User className="text-orange-500" />
                <span>
                  {user.isVerified ? "Verified" : "Not Verified"}
                </span>
              </div>

            </div>
          </div>
        </div>
      </div>

      {/* Statistics */}

      <div className="grid md:grid-cols-3 gap-6 mt-8">

        <div className="bg-white rounded-xl shadow p-6">
          <h3 className="text-gray-500">Total Orders</h3>
          <p className="text-3xl font-bold text-blue-600 mt-2">
            {user.totalOrders || 0}
          </p>
        </div>

        <div className="bg-white rounded-xl shadow p-6">
          <h3 className="text-gray-500">Total Spending</h3>
          <p className="text-3xl font-bold text-green-600 mt-2">
            ₹{user.totalSpent || 0}
          </p>
        </div>

      </div>
    </div>
  );
};

export default UserDetails;