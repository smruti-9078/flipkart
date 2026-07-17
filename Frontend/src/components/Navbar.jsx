import { ShoppingCart,Search } from "lucide-react";
import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "./ui/button";
import axios from "axios";
import { toast } from "sonner";
import { useSelector, useDispatch } from "react-redux";
import { setUser } from "@/redux/userSlice";

const Navbar = () => {
  const { user } = useSelector((store)=>store.user)
  const  {cart} = useSelector(store=>store.product)
  const admin = user?.role === "admin" ? true:false
  const dispatch = useDispatch()
  const navigate = useNavigate()

  const logoutHandler = async () => {
    try {
      const accessToken = localStorage.getItem("accessToken")

      if (accessToken) {
        const res = await axios.post(
          `http://localhost:8000/api/user/logout`,
          {},
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
            },
          }
        )

        if (res.data.success) {
          toast.success(res.data.message)
        }
      }
    } catch (error) {
      console.log(error)
      toast.error("Logout failed, but your session was cleared locally")
    } finally {
      localStorage.removeItem("accessToken")
      dispatch(setUser(null))
      navigate("/login")
    }
  }
  //console.log(cart)
  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-white shadow border-b">
      <div className="max-w-8xl mx-auto flex gap-5 px-5">
        <div className="h-16 flex justify-between items-center">
          <Link to="/">
          <h1 className="italic text-blue-600 text-3xl font-bold">ShopSphere</h1>
          </Link>
          
        </div>
        <div className="hidden lg:flex w-[35%] border rounded-lg overflow-hidden m-5">
          <input
            type="text"
            placeholder="Search for products..."
            className="flex-1 px-4 py-2 outline-none"
          />
          <button className="bg-blue-600 px-4 text-white cursor-pointer">
            <Search size={20} />
          </button>
        </div>
        <nav className="hidden md:flex gap-8 items-center">
          <ul className="flex gap-7 items-center text-xl font-semibold">
            <Link to={"/"} className="font-medium text-gray-700 hover:text-blue-600">Home</Link>
            <Link to={"/products"} className="font-medium text-gray-700 hover:text-blue-600">Products</Link>
            {user && 
              <Link
                to={`/profile/${user._id}`}
                className="font-medium text-gray-700 hover:text-blue-600"
                >
                <li >Hello, {user.firstName}</li>
              </Link>
              }
              {admin && 
              <Link
                to={`/dashboard/sales`}
                className="font-medium text-gray-700 hover:text-blue-600"
                >
                <li>Dashboard</li>
              </Link>
              }   
            
          </ul>
          <Link to={`/cart`} className="relative">
            <ShoppingCart size={24} />
            <span className="absolute -top-2 -right-3 bg-red-500 text-white rounded-full text-xs px-2">
              {cart?.items?.length}
            </span>
          </Link>
          {user ? (
            <Button onClick={logoutHandler} className="bg-blue-600 hover:bg-blue-700 cursor-pointer">
              Logout
            </Button>
          ) : (
            <Button onClick={()=>navigate(`login`)}className="bg-blue-600 hover:bg-blue-700 cursor-pointer">
              Login
            </Button>
          )}
        </nav>
      </div>
    </header>
  );
};

export default Navbar;
