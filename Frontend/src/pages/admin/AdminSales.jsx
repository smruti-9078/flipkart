import React from 'react'
import {
  DollarSign,
  ShoppingCart,
  Users,
  Package,
  TrendingUp,
} from "lucide-react";
const AdminSales = () => {

  const dashboard = {
    totalRevenue: 0,
    totalOrders: 0,
    totalUsers: 0,
    totalProducts: 0,
    recentOrders: [],
    topProducts: [],
  };

// const [loading, setLoading] = useState(true);
  const cards = [
    {
      title: "Total Revenue",
      value: `₹${dashboard.totalRevenue}`,
      icon: <DollarSign size={30} />,
      color: "bg-green-500",
    },
    {
      title: "Total Orders",
      value: dashboard.totalOrders,
      icon: <ShoppingCart size={30} />,
      color: "bg-blue-500",
    },
    {
      title: "Total Users",
      value: dashboard.totalUsers,
      icon: <Users size={30} />,
      color: "bg-purple-500",
    },
    {
      title: "Products",
      value: dashboard.totalProducts,
      icon: <Package size={30} />,
      color: "bg-orange-500",
    },
  ];
  return (
    <div className="min-h-screen bg-gray-100 p-6">
      <h1 className="text-3xl font-bold mb-8">
        ShopSphere Admin Dashboard
      </h1>

      {/* Stats */}
      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
        {cards.map((card, index) => (
          <div
            key={index}
            className="bg-white rounded-xl shadow-lg p-6 flex justify-between items-center"
          >
            <div>
              <p className="text-gray-500">{card.title}</p>
              <h2 className="text-3xl font-bold mt-2">
                {card.value}
              </h2>
            </div>

            <div
              className={`${card.color} p-4 rounded-full text-white`}
            >
              {card.icon}
            </div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-2 gap-8">
        {/* Recent Orders */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <div className="flex items-center gap-2 mb-5">
            <ShoppingCart className="text-blue-600" />
            <h2 className="text-xl font-bold">
              Recent Orders
            </h2>
          </div>

          {dashboard.recentOrders.length === 0 ? (
            <p className="text-gray-500">
              No Orders Available
            </p>
          ) : (
            <div className="space-y-4">
              {dashboard.recentOrders.map((order) => (
                <div
                  key={order._id}
                  className="border rounded-lg p-4 flex justify-between items-center"
                >
                  <div>
                    <h3 className="font-semibold">
                      {order.user?.name}
                    </h3>

                    <p className="text-sm text-gray-500">
                      {new Date(
                        order.createdAt
                      ).toLocaleDateString()}
                    </p>
                  </div>

                  <div className="text-right">
                    <p className="font-bold text-green-600">
                      ₹{order.totalAmount}
                    </p>

                    <span
                      className={`text-sm font-medium ${
                        order.status === "Delivered"
                          ? "text-green-600"
                          : order.status === "Cancelled"
                          ? "text-red-600"
                          : "text-yellow-600"
                      }`}
                    >
                      {order.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Products */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <div className="flex items-center gap-2 mb-5">
            <TrendingUp className="text-green-600" />
            <h2 className="text-xl font-bold">
              Top Selling Products
            </h2>
          </div>

          {dashboard.topProducts.length === 0 ? (
            <p className="text-gray-500">
              No Product Data
            </p>
          ) : (
            <div className="space-y-4">
              {dashboard.topProducts.map((product) => (
                <div
                  key={product._id}
                  className="flex items-center gap-4 border rounded-lg p-4"
                >
                  <img
                    src={product.productImg[0]}
                    alt={product.productName}
                    className="w-16 h-16 rounded-lg object-cover"
                  />

                  <div className="flex-1">
                    <h3 className="font-semibold">
                      {product.productName}
                    </h3>

                    <p className="text-gray-500">
                      Sold : {product.totalSold}
                    </p>
                  </div>

                  <div className="font-bold text-green-600">
                    ₹{product.productPrice}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default AdminSales