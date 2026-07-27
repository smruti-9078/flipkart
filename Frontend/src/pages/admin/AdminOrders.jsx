import React, { useEffect, useState } from "react";
import axios from "axios";
import { Package } from "lucide-react";
import { toast } from "sonner";

const AdminOrders = () => {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);

  const token = localStorage.getItem("accessToken");

  const updateStatus = async (_orderId, status) => {
    try {
      const { data } = await axios.put(
        `http://localhost:8000/api/order/admin/${_orderId}`,
        { status },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (data.success) {
        toast.success(data.message);
        loadOrders();
      }
    } catch (error) {
      console.error(error);
      toast.error(error.response?.data?.message || "Status update failed");
    }
  };

  const loadOrders = async () => {
    try {
      setLoading(true);

      const { data } = await axios.get(
        "http://localhost:8000/api/order/admin",
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (data.success) {
        // support different response shapes: { orders: [...] } or { cart: {...} } or { cart: [] }
        let source = data.orders ?? data.carts ?? data.cart ?? data;
        if (!source) source = [];
        // if source is an object (single cart), wrap into array
        if (!Array.isArray(source)) {
          // if it's a cart object with items, convert to an order-like object
          if (source.items) {
            source = [
              {
                _id: source._id,
                products: source.items,
                totalAmount: source.totalPrice,
                user: source.userId || source.user,
                createdAt: source.createdAt,
                orderStatus: source.orderStatus || "Pending",
                paymentMethod: source.paymentMethod || "",
                paymentStatus: source.paymentStatus || "",
              },
            ];
          } else {
            source = [];
          }
        }

        setOrders(source);
      }
    } catch (error) {
      console.error(error);
      toast.error(error.response?.data?.message || "Failed to load orders");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOrders();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen text-xl font-semibold">
        Loading Orders...
      </div>
    );
  }

  return (
    <div className="p-18 bg-gray-100 min-h-screen">
      <div className="flex items-center gap-3 mb-6">
        <Package size={32} className="text-blue-600" />
        <h1 className="text-3xl font-bold">Manage Orders</h1>
      </div>

      {orders.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-8 text-center">
          <h2 className="text-xl font-semibold">No Orders Found</h2>
        </div>
      ) : (
        <div className="space-y-6">
          {orders.map((order, index) => (
            <div
              key={order._id}
              className="bg-white rounded-xl shadow-md p-6"
            >
              <div className="flex justify-between flex-wrap gap-4 mb-5">
                <div>
                  <h2 className="font-bold text-lg">
                    Order #{index + 1}
                  </h2>

                  <p className="text-gray-600">
                    Customer: {order.userId?.firstName}{" "}
                    {order.userId?.lastName}
                  </p>

                  <p className="text-gray-600">
                    Email: {order.userId?.email}
                  </p>

                  <p className="text-gray-600">
                    Date:{" "}
                    {new Date(order.createdAt).toLocaleDateString()}
                  </p>
                </div>

                <div className="text-right">
                  <h3 className="text-xl font-bold text-green-600">
                    ₹{order.totalPrice}
                  </h3>

                  <p className="capitalize text-gray-600">
                    Payment: {order.paymentMethod}
                  </p>

                  <p
                    className={`font-semibold ${
                      order.paymentStatus === "Paid"
                        ? "text-green-600"
                        : "text-red-500"
                    }`}
                  >
                    {order.paymentStatus}
                  </p>
                </div>
              </div>

              <div className="border rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-100">
                    <tr>
                      <th className="text-left p-3">Product</th>
                      <th className="text-center p-3">Qty</th>
                      <th className="text-center p-3">Price</th>
                    </tr>
                  </thead>

                  <tbody>
                    {(order.items ||[]).map((item, idx) => {
                      const productObj = item.product || item.productId || item.product?.product || item.productId?.product || {};
                      const img =
                        productObj?.images?.[0] ||
                        productObj?.productImg?.[0]?.url ||
                        productObj?.productImg?.[0] ||
                        "";
                      const name = productObj?.productName || productObj?.name || productObj?.title || "Product";
                      const price = item.product?.productPrice || productObj?.productPrice || item.price || 0;
                      const qty = item.quantity || item.qty || 1;
                      const key = item._id || productObj?._id || `${order._id}-${idx}`;

                      return (
                        <tr key={key} className="border-t">
                          <td className="p-3">
                            <div className="flex items-center gap-3">
                              <img src={img} alt="" className="w-14 h-14 rounded object-cover" />
                              <span>{name}</span>
                            </div>
                          </td>

                          <td className="text-center">{qty}</td>

                          <td className="text-center">₹{price}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div className="flex justify-between items-center mt-5 flex-wrap gap-4">
                <div>
                  <span className="font-semibold">
                    Order Status:
                  </span>

                  <span
                    className={`ml-2 px-3 py-1 rounded-full text-white ${
                      order.orderStatus === "Delivered"
                        ? "bg-green-500"
                        : order.orderStatus === "Cancelled"
                        ? "bg-red-500"
                        : "bg-yellow-500"
                    }`}
                  >
                    {order.orderStatus}
                  </span>
                </div>

                <select
                  value={order.orderStatus}
                  onChange={(e) =>
                    updateStatus(order._id, e.target.value)
                  }
                  className="border rounded-lg px-4 py-2"
                >
                  <option>Pending</option>
                  <option>Confirmed</option>
                  <option>Processing</option>
                  <option>Shipped</option>
                  <option>Delivered</option>
                  <option>Cancelled</option>
                </select>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AdminOrders;