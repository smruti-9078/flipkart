import React, { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import axios from "axios";

const VerifyEmail = () => {
  const { token } = useParams();
  const navigate = useNavigate();

  // verifying | success | error
  const [status, setStatus] = useState(()=>(token ? "verifying" : "error"));

  useEffect(() => {
    if (!token) return;

    let isMounted = true;

    const runVerification = async () => {
      try {
        const res = await axios.post(
          "http://localhost:8000/api/user/verify",
          {},
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (res.data.success && isMounted) {
          setStatus("success");

          setTimeout(() => {
            navigate("/login");
          }, 2000);
        }
      } catch (error) {
        console.log(error);
        if (isMounted) setStatus("error");
      }
    };

    runVerification();

    return () => {
      isMounted = false;
    };
  }, [token, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-indigo-600 to-purple-600 px-4">
      <div className="bg-white w-full max-w-md rounded-2xl shadow-xl p-8 text-center">

        {/* Verifying */}
        {status === "verifying" && (
          <>
            <div className="flex justify-center mb-6">
              <div className="h-10 w-10 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin"></div>
            </div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">
              Verifying your email...
            </h1>
            <p className="text-gray-500">
              Please wait while we confirm your account.
            </p>
          </>
        )}

        {/* Success */}
        {status === "success" && (
          <>
            <div className="text-5xl mb-4">✅</div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">
              Email Verified
            </h1>
            <p className="text-green-600">
              Redirecting to login...
            </p>
          </>
        )}

        {/* Error */}
        {status === "error" && (
          <>
            <div className="text-5xl mb-4">❌</div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">
              Verification Failed
            </h1>
            <p className="text-red-600">
              Invalid or expired verification link.
            </p>
          </>
        )}

      </div>
    </div>
  );
};

export default VerifyEmail;