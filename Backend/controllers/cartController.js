import { Cart } from "../models/cartModel.js";
import { Product } from "../models/productModel.js";

export const getCart = async (req, res) => {
  try {
    const userId = req.id;

    const cart = await Cart.findOne({ userId }).populate({ path: "items.productId", model: "product" });
    if (!cart) {
      return res.json({
        success: true,
        cart: [],
      });
    }
    res.status(200).json({ success: true, cart });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const addToCart = async (req, res) => {
  try {
    const userId = req.id;

    const { productId } = req.body || {};
    console.log("Request Body:", req.body);

    if (!productId) {
      return res.status(400).json({ success: false, message: "productId is required" });
    }

    // check if product exists
    const product = await Product.findById(productId);

    if (!product) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }
    
    //find the user's cart (if exists)
    let cart = await Cart.findOne({ userId });

    //if cart doesnot exists, create anew one
    if (!cart) {
      cart = new Cart({
        userId,
        items: [{ productId, quantity: 1, price: product.productPrice ?? 0 }],
        totalPrice: product.productPrice ?? 0,
      });
    } else {
      //Find if product is already in the cart
      const itemIndex = cart.items.findIndex(
        (item) => item.productId.toString() === productId,
      );
      if (itemIndex > -1) {
        // if product exists -> just increase quantity
        cart.items[itemIndex].quantity += 1;
      } else {
        // if new product -> push to cart
        cart.items.push({
          productId,
          quantity: 1,
          price: product.productPrice,
        });
      }

      // recalculate the total price
      cart.totalPrice = cart.items.reduce(
        (acc, item) => acc + item.price * item.quantity,
        0,
      );
    }

    //save update cart
    await cart.save();

    //populate product details before sending response

    const populatedCart = await Cart.findById(cart._id).populate({
      path: "items.productId",
      model: "product",
    });

    res.status(200).json({
      success: true,
      message: "Product added to cart successfully",
      cart: populatedCart,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const updateQuantity = async (req, res) => {
  try {
    const userId = req.id;
    const {productId, type} = req.body || {};
    console.log("Request Body:", req.body);

    if (!productId) {
      return res.status(400).json({ 
        success: false, 
        message: "productId is required" });
    }
    if (!type || !["increase", "decrease"].includes(type)) {
      return res.status(400).json({ success: false, message: "type must be 'increase' or 'decrease'" });
    }

    let cart = await Cart.findOne({ userId });
    if (!cart) {
      return res.status(404).json({
        success: false,
        message: "Cart not found",
      });
    }
    const item = cart.items.find(
      (item) => item.productId.toString() === productId,
    );
    if (!item) {
      return res.status(404).json({
        success: false,
        message: "Item not found",
      });
    }
    if (type === "increase") {
      item.quantity += 1;
    } else if (type === "decrease") {
      if (item.quantity > 1) {
        item.quantity -= 1;
      } else {
        // remove the item from cart when quantity would go to 0
        cart.items = cart.items.filter((i) => i.productId.toString() !== productId);
      }
    }
    cart.totalPrice = cart.items.reduce((acc, item) => acc + item.price * item.quantity, 0);

    await cart.save();
    cart = await cart.populate({ path: "items.productId", model: "product" });

    return res.status(200).json({ success: true, cart });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const removeFromCart = async (req, res) => {
  try {
    const userId = req.id;
    const { productId } = req.body;

    let cart = await Cart.findOne({ userId });
    if (!cart) {
      return res.status(404).json({
        success: false,
        message: "Cart not found",
      });
    }
    cart.items = cart.items.filter((item) => item.productId.toString() !== productId);
    cart.totalPrice = cart.items.reduce((acc, item) => acc + item.price * item.quantity, 0);

    await cart.save();
    cart = await cart.populate({ path: "items.productId", model: "product" });

    return res.status(200).json({ success: true, cart });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
