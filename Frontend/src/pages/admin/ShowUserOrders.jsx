import React from 'react'
import  { useState } from "react";

const ShowUserOrders = () => {
  const [orders] = useState([]);
  //const [loading, setLoading] = useState(true);
  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">My Orders</h1>

      {orders.length === 0 ? (
        <div className="text-center text-gray-500 text-lg">
          No orders found.
        </div>
      ) : (
        <div className="space-y-8">
          {orders.map((order) => (
            <div
              key={order._id}
              className="bg-white rounded-xl shadow-md border p-6"
            >
              {/* Order Details */}
              <div className="flex flex-col md:flex-row md:justify-between gap-3 border-b pb-4">
                <div>
                  <p className="font-semibold">
                    Order ID:
                    <span className="text-gray-600 ml-2">
                      {order._id}
                    </span>
                  </p>

                  <p className="mt-2">
                    Date:
                    <span className="text-gray-600 ml-2">
                      {new Date(order.createdAt).toLocaleDateString()}
                    </span>
                  </p>
                </div>

                <div className="text-right">
                  <p>
                    Status:
                    <span
                      className={`ml-2 font-semibold ${
                        order.status === "Delivered"
                          ? "text-green-600"
                          : order.status === "Cancelled"
                          ? "text-red-500"
                          : "text-yellow-600"
                      }`}
                    >
                      {order.status}
                    </span>
                  </p>

                  <p className="mt-2 font-bold text-lg text-blue-600">
                    ₹{order.totalAmount}
                  </p>
                </div>
              </div>

              {/* Products */}
              <div className="mt-5 space-y-4">
                {order.items.map((item) => (
                  <div
                    key={item._id}
                    className="flex flex-col md:flex-row items-center gap-4 border rounded-lg p-4"
                  >
                    <img
                      src={item.product.productImg[0]}
                      alt={item.product.productName}
                      className="w-24 h-24 rounded-lg object-cover"
                    />

                    <div className="flex-1">
                      <h2 className="text-lg font-semibold">
                        {item.product.productName}
                      </h2>

                      <p className="text-gray-500 mt-1">
                        Brand: {item.product.brand}
                      </p>

                      <p className="text-gray-500">
                        Category: {item.product.category}
                      </p>
                    </div>

                    <div className="text-right">
                      <p>Qty : {item.quantity}</p>

                      <p className="font-bold text-blue-600 mt-2">
                        ₹{item.price}
                      </p>
                    </div>
                  </div>
                ))}
              </div>

              {/* Shipping Address */}
              {order.shippingAddress && (
                <div className="mt-6 border-t pt-4">
                  <h3 className="font-semibold mb-2">
                    Shipping Address
                  </h3>

                  <p>{order.shippingAddress.fullName}</p>

                  <p>{order.shippingAddress.address}</p>

                  <p>
                    {order.shippingAddress.city},{" "}
                    {order.shippingAddress.state}
                  </p>

                  <p>
                    {order.shippingAddress.country} -{" "}
                    {order.shippingAddress.pincode}
                  </p>

                  <p>{order.shippingAddress.phone}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default ShowUserOrders