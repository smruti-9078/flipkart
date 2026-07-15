import Sidebar from '@/components/Sidebar'
import React from 'react'

import { Outlet } from 'react-router-dom'

const Dashboard = () => {
  return (
    <div className='min-h-screen bg-slate-50'>
        <Sidebar/>
        <div className='md:ml-72 p-6'>
            <Outlet/>
        </div>

    </div>
  )
}

export default Dashboard