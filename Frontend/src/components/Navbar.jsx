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
    <header className="bg-slate-900 fixed w-full z-20  text-white p-2">
      <div className="max-w-7xl mx-auto flex justify-between items-center py-3">
        <div>
          <h1 className="italic text-3xl font-bold">Flipkart</h1>
        </div>
        <div className="flex items-center bg-white rounded-md overflow-hidden w-[40%]">
          <input
            type="text"
            placeholder="Search for products..."
            className="w-full px-4 py-2 text-black outline-none"
          />
          <button className="px-4 text-gray-600">
            <Search size={20} />
          </button>
        </div>
        <nav className="flex gap-10 justify-between items-center">
          <ul className="flex gap-7 items-center text-xl font-semibold">
            <Link to={"/"} className="hover:text-gray-300 transition-colors duration-300">Home</Link>
            <Link to={"/products"} className="hover:text-gray-300 transition-colors duration-300">Products</Link>
            {user && 
              <Link
                to={`/profile/${user._id}`}>
                
                <li>Hello, {user.firstName}</li>
              </Link>
              }   
            
          </ul>
          <Link to={`/cart`} className="relative">
            <ShoppingCart />
            <span className="bg-red-500 rounded-full absolute text-white -top-3 -right-5 px-2">
              {cart?.items?.length}
            </span>
          </Link>
          {user ? (
            <Button onClick={logoutHandler} className="bg-blue-600 text-white cursor-pointer">
              Logout
            </Button>
          ) : (
            <Button onClick={()=>navigate(`login`)}className="bg-blue-600 text-white cursor-pointer">
              Login
            </Button>
          )}
        </nav>
      </div>
    </header>
  );
};

export default Navbar;
