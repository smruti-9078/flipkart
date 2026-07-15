import React from "react";
import { Button } from "./ui/button";
import { ShoppingCart } from "lucide-react";
import { Skeleton } from "./ui/skeleton";
import axios from "axios";
import { toast } from "sonner";
import { useDispatch } from "react-redux";
import { setCart } from "@/redux/productsSlice";
import { useNavigate } from "react-router-dom";

const ProductCard = ({ product = {}, loading }) => {
  const {
    productImg = [],
    productPrice = 0,
    productName = "",
    _id,
    id,
  } = product;
  const accessToken = localStorage.getItem("accessToken");
  const dispatch = useDispatch();
  const productId = _id || id;
  const navigate = useNavigate()

  const addToCart = async () => {
    if (!productId) {
      toast.error("Unable to add this product to cart");
      return;
    }

    if (!accessToken) {
      toast.error("Please log in to add items to cart");
      return;
    }

    try {
      const res = await axios.post(
        `http://localhost:8000/api/cart/add`,
        { productId },
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        },
      );
      if (res.data.success) {
        toast.success("Product added to Cart");
        dispatch(setCart(res.data.cart));
      }

    
    } catch (error) {
      console.error(
        "Add to cart error:",
        error.response?.status,
        error.response?.data || error.message,
      );
      toast.error(
        error.response?.data?.message || "Failed to add product to cart",
      );
    }
  };
  return (
    <div className="shadow-lg rounded-lg overflow-hidden h-max transition-transform duration-300 hover:scale-110">
      <div className="w-full h-full aspect-square overflow-hidden">
        {loading ? (
          <Skeleton className="w-full h-full rounded-lg" />
        ) : (
          <img
            onClick={()=>navigate(`/products/${product._id}`)}
            src={productImg[0]?.url}
            alt=""
            className="w-full h-full transition-transform duration-300 hover:scale-110"
          />
        )}
      </div>
      {loading ? (
        <div className="px-2 space-y-2 my-2">
          <Skeleton className="w-[200px] h-4" />
          <Skeleton className="w-[200px] h-4" />
          <Skeleton className="w-[200px] h-8" />
        </div>
      ) : (
        <div className="px-2 space-y-2 my-2">
          <h1 className="h-12 font-semibold line-clamp-2">{productName}</h1>
          <h2 className="semi-bold">₹{productPrice}</h2>
          <Button
            onClick={() => addToCart(product._id)}
            className="bg-blue-500 hover:bg-blue-600 text-white mb-3 w-full"
          >
            <ShoppingCart />
            Add to Cart
          </Button>
        </div>
      )}
    </div>
  );
};

export default ProductCard;
