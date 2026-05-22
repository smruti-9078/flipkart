import React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const Profile = () => {
  return (
    <div className="pt-20 min-h-screen bg-gray-100">
      <Tabs defaultValue="profile" className="max-w-7xl mx-auto items-center">
        <TabsList>
          <TabsTrigger value="profile">Profile</TabsTrigger>
          <TabsTrigger value="orders">Orders</TabsTrigger>
        </TabsList>
        <TabsContent value="profile">
          <div>
            <div className="flex flex-col justify-center items-center bg-gray-100">
                <h1 className="font-bold mb-7 text-2xl text-gray-800">Update Profile</h1>
                <div className="w-full flex gap-10 justify-between items-start px-7 max-w-2xl">
                    {/* profile picture */}
                    <div className="flex flex-col gap-3 justify-center items-center">
                        
                            <img src="../src/pages/lamborghini.jpg" alt="Profile Picture" className="w-32 h-32 rounded-full object-cover border-5 border-violet-600"/>
                            <label className="mt-4 cursor-pointer bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-800">Change Picture
                                <input type="file" accept="image/*" className="hidden"/>                        
                             </label>
                        
                    </div>
                    {/* profile from */}
                    <form className="space-y-4 shadow-lg p-5 rounded-lg bg-white">
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <Label className ="block text-sm font-medium">First Name</Label>
                                <Input type="text" name="firstName" placeholder="First Name" className="w-full border rounded-lg px-3 py-2 mt-1"/>
                            </div>
                            <div>
                                <Label className ="block text-sm font-medium">Last Name</Label>
                                <Input type="text" name="lastName" placeholder="Last Name"className="w-full border rounded-lg px-3 py-2 mt-1"/>
                            </div>

                            
                        </div>
                        <div>
                          <Label className ="block text-sm font-medium">Last Name</Label>
                                <Input type="email" name="email" disbaled className="w-full border rounded-lg px-3 py-2 mt-1 bg-gray-100 cursor-not-allowed"/>

                        </div>
                        <div>
                          <Label className ="block text-sm font-medium">Phone Number</Label>
                                <Input type="text" name="phoneNo" placeholder="Enter your contact Number" className="w-full border rounded-lg px-3 py-2 mt-1"/>
                        </div>
                        <div>
                          <Label className ="block text-sm font-medium">Address</Label>
                                <Input type="text" name="address" placeholder="Enter your Address" className="w-full border rounded-lg px-3 py-2 mt-1"/>
                        </div>
                        <div>
                          <Label className ="block text-sm font-medium">City</Label>
                                <Input type="text" name="city" placeholder="Enter your City" className="w-full border rounded-lg px-3 py-2 mt-1"/>
                        </div>
                        <div>
                          <Label className ="block text-sm font-medium">Zip Code</Label>
                                <Input type="text" name="zipCode" placeholder="Enter your ZipCode" className="w-full border rounded-lg px-3 py-2 mt-1"/>
                        </div>
                        <Button type="submit" className="bg-indigo-600 text-white w-full hover:bg-indigo-800">
                          Update Profile

                        </Button>

                    </form>

                </div>
            </div>
          </div>
        </TabsContent>
        <TabsContent value="orders">
          <Card>
            <CardHeader>
              <CardTitle>Orders</CardTitle>
              <CardDescription>
                Track performance and user engagement metrics. Monitor trends
                and identify growth opportunities.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-6">
            
             <div className="grid gap-3">
                <label htmlFor="tabs-demo-current">Current Password</label>
                <input id="tabs-demo-current" type="password" />
             </div>
             <div className="grid gap-3">
                <label htmlFor="tabs-demo-current">New Password</label>
                <input id="tabs-demo-current" type="password" />
             </div>
            
            </CardContent>
            <CardFooter>
                <button className='bg-black text-white '> Change Password</button>
            </CardFooter>
          </Card>
        </TabsContent>
        
      </Tabs>
    </div>
  );
};

export default Profile;
