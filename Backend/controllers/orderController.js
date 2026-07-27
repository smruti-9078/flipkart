import { Order } from "../models/orderModel.js";
import { Cart } from "../models/cartModel.js";

export const placeOrder = async (req, res) => {
  try {
    const userId = req.id;
    const { paymentMethod = "Cash on Delivery" } = req.body;

    const cart = await Cart.findOne({ userId }).populate({ path: "items.productId", model: "product" });
    if (!cart || cart.items.length === 0) {
      return res.status(400).json({ success: false, message: "Cart is empty" });
    }

    const orderItems = cart.items.map((item) => ({
      productId: item.productId._id || item.productId,
      quantity: item.quantity,
      price: item.price,
    }));

    const order = await Order.create({
      userId,
      items: orderItems,
      totalPrice: cart.totalPrice,
      orderStatus: "Pending",
      paymentMethod,
      paymentStatus: "Pending",
    });

    cart.items = [];
    cart.totalPrice = 0;
    await cart.save();

    return res.status(201).json({ success: true, message: "Order placed successfully", order });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

export const getOrders = async (req, res) => {
  try {
    const userId = req.id;
    const orders = await Order.find({ userId }).populate({ path: "items.productId", model: "product" });
    return res.status(200).json({ success: true, orders });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

export const getAllOrders = async (req, res) => {
  try {
    const orders = await Order.find()
      .populate("userId", "firstName lastName email")
      .populate({
        path: "items.productId",
        model: "product",
      })
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      orders,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};



export const updateOrderStatus = async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;

    const validStatuses = [
      "Pending",
      "Confirmed",
      "Processing",
      "Shipped",
      "Delivered",
      "Cancelled",
    ];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid order status",
      });
    }

    const order = await Order.findById(orderId);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Order not found",
      });
    }

    order.orderStatus = status;

    await order.save();

    return res.status(200).json({
      success: true,
      message: "Order status updated successfully",
      order,
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};