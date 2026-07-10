import React from 'react'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import Home from './pages/Home'
import Navbar from './components/Navbar'
import Signup from './pages/Signup'
import Login from './pages/Login'
import Verify from './pages/Verify'
import VerifyEmail from './pages/VerifyEmail'
import Footer from './components/Footer/Footer.jsx'
import Profile from './pages/Profile'
import Products from './pages/Products'
import Cart from './pages/Cart'

const router = createBrowserRouter([
  {
    path: "/",
    element:<><Navbar/><Home/><Footer/></>
  },
  {
    path: "/signup",
    element:<><Signup /></>
  },
  {
    path: "/login",
    element:<><Login /></>
  },
  {
    path: "/verify",
    element:<><Verify /></>
  },
  {
    path: "/verify/:token",
    element:<><VerifyEmail/></>
  },
  {
    path: "/profile/:id",
    element:<><Navbar/><Profile/><Footer/></>
  },
  {
    path: "/products",
    element:<><Navbar/><Products/><Footer/></>
  },
  {
    path: "/cart",
    element:<><Navbar/><Cart/></>
  },

  
])

const App = () => {
  return (
    <>
      <RouterProvider router={router}/>

      
    </>
  )
}

export default App
