import React, { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Eye, EyeOff, Loader2 } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";

const Signup = () => {
    const [showPassword, setShowPassword] = useState(false)
    const [loading, setLoading] =useState(false)
    const [formData, setFormData] = useState({
        
        firstName:"",
        lastName:"",
        email:"",
        password:""
    })
    const navigate = useNavigate()

    const handleChange = (e)=>{
        const {name, value} = e.target;
        setFormData((prev)=>({
            ...prev,
            [name]:value
        }))
    }

    const submitHandler = async(e)=>{
        e.preventDefault();
        //console.log(formData)
        try {
          setLoading(true)
            const res= await axios.post(`http://localhost:8000/api/user/register`, formData, {
            
                headers:{
                    "Content-Type":"application/json"
                }
            })
            if(res.data.success){
                navigate('/verify')
                toast.success(res.data.message)
            }
        } catch (error) {
            console.log(error)
            toast.error(error.response.data.message)
        }finally{
          setLoading(false)
        }
    }
  return (
    <div className="flex justify-center items-center min-h-screen bg-gradient-to-br from-indigo-600 to-purple-600 ">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-center text-blue-600 text-2xl font-semibold ">Create your account</CardTitle>
          <CardDescription className="text-center text-slate-600 ">
            Enter given details to create your account 
          </CardDescription>
        </CardHeader>
        <CardContent>
            <div className="flex flex-col gap-3">
              <div className="grid grid-cols-2 gap-2">
                <div className="grid gap-2">
                    <Label htmlFor="firstName" className='text-gray-600'>First Name</Label>
                    <Input id="firstName" 
                    placeholder="First Name"
                    name="firstName"
                    type='text'
                    required 
                    value={formData.firstName}
                    onChange={handleChange}
                    />
                </div>
                <div className="grid gap-2">
                    <Label htmlFor="lastName"className='text-gray-600'>Last Name</Label>
                    <Input id="lastName" 
                    placeholder="Last Name"
                    name="lastName"
                    type='text'
                    required
                    value={formData.lastName}
                    onChange={handleChange} 
                    />
                </div>
                
              </div> 
              <div className="grid gap-2">
                <Label htmlFor="email" className='text-gray-600'>Email</Label>
                <Input
                  id="email"
                  type="email"
                  name='email'
                  placeholder="m@example.com"
                  required
                    value={formData.email}
                    onChange={handleChange}
                />
              </div>
              
              <div className="grid gap-2">
                <div className="flex items-center">
                  <Label htmlFor="password"className='text-gray-600'>Password</Label>
                  
                </div>
                <div className="relative">
                    <Input id="password"  name="password" placeholder="Enter your password" value={formData.password} onChange={handleChange} required type={showPassword ? 'text':'password'} />
                {
                    showPassword ? <EyeOff onClick={()=>setShowPassword(false)} className="w-5 h-5 text-gray-700 absolute right-5 bottom-2"/> :<Eye onClick={()=>setShowPassword(true)}className="w-5 h-5 text-gray-700 absolute right-5 bottom-2"/>
                }
                </div>
                
              </div>
            </div>
        </CardContent>
        <CardFooter className="flex-col gap-2">
          <Button onClick={submitHandler} type="submit" className="w-full bg-blue-600 hover:bg-blue-800">
            {loading? <><Loader2 className="animate-spin h-4 w-4 mr-2"/>Please wait</>:'Signup'}
          </Button>
          <p className="text-slate-800 text-md">Already have an account ? <Link to={'/login'} className="hover:underline cursor-pointer text-blue-800">Login</Link></p>
        </CardFooter>
      </Card>
    </div>
  );
};

export default Signup;
