import { ShoppingCart,Search } from "lucide-react";
import React from "react";
import { Link } from "react-router-dom";
import { Button } from "./ui/button";

const Navbar = () => {
  const user = true;
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
            <Link
              to={"/"}
              className="hover:text-gray-300 transition-colors duration-300"
            >
              Home
            </Link>
            <Link
              to={"/products"}
              className="hover:text-gray-300 transition-colors duration-300"
            >
              Products
            </Link>
            {user && (
              <Link
                to={"/profile"}
                className="hover:text-gray-300 transition-colors duration-300"
              >
                Hello User
              </Link>
            )}
          </ul>
          <Link to={`/cart`} className="relative">
            <ShoppingCart />
            <span className="bg-red-500 rounded-full absolute text-white -top-3 -right-5 px-2">
              0
            </span>
          </Link>
          {user ? (
            <Button className="bg-blue-600 text-white cursor-pointer">
              Logout
            </Button>
          ) : (
            <Button className="bg-blue-600 text-white cursor-pointer">
              Login
            </Button>
          )}
        </nav>
      </div>
    </header>
  );
};

export default Navbar;
