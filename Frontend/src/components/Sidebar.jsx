import React from "react";
import { NavLink } from "react-router-dom";
import { LayoutDashboard, PackagePlus, PackageSearch, Users,ShoppingCart } from "lucide-react";
import { FaRegEdit } from "react-icons/fa";

const Sidebar = () => {
    const menuItems = [
    {
      title: "Dashboard",
      icon: <LayoutDashboard size={22} />,
      path: "/dashboard/sales",
    },
    {
      title: "Add Product",
      icon: <PackagePlus size={22} />,
      path: "/dashboard/add-product",
    },
    {
      title: "Products",
      icon: <PackageSearch size={22} />,
      path: "/dashboard/products",
    },
    {
      title: "Users",
      icon: <Users size={22} />,
      path: "/dashboard/users",
    },
    {
      title: "Orders",
      icon: <ShoppingCart size={22} />,
      path: "/dashboard/orders",
    },
  ];
  return (
     <aside className="hidden md:flex fixed left-0 top-0 h-screen w-72 bg-white border-r border-gray-200 shadow-sm flex-col">
      {/* Logo */}
      <div className="h-20 flex items-center justify-center border-b">
        <h1 className="text-3xl font-bold text-blue-600">
          ShopSphere
        </h1>
      </div>

      {/* Menu */}
      <div className="flex-1 px-5 py-8 space-y-3">
        {menuItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center gap-4 px-4 py-3 rounded-xl font-medium transition-all duration-300 ${
                isActive
                  ? "bg-blue-600 text-white shadow-md"
                  : "text-gray-700 hover:bg-blue-50 hover:text-blue-600"
              }`
            }
          >
            {item.icon}
            <span>{item.title}</span>
          </NavLink>
        ))}
      </div>

      {/* Footer */}
      <div className="border-t p-5">
        <p className="text-sm text-gray-500 text-center">
          ShopSphere Admin
        </p>
      </div>
    </aside>
    
  )
};

export default Sidebar;
