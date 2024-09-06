"use client";

import React, { useEffect } from "react";
import { getCsrfToken, useSession } from "next-auth/react";
import { useAccount, useConnect, useNetwork, useSignMessage } from "wagmi";

function Profile() {
  const { address, isConnected } = useAccount();
  const { data: session, status } = useSession();
  const loading = status === "loading";

  useEffect(() => {
    // console.log(session);
    console.log(isConnected);
  }, [session, loading, isConnected]);

  async function handleClick() {
    try {
      if (isConnected && session) {
        const response = await fetch("api/protected", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ hello: "hello from client" }),
        });
        const result = await response.json();
        console.log("result", result);
      } else {
        console.log("You are not connected or signed in");
      }
    } catch (error) {
      console.log(error);
    }
  }

  // const handleAPICall = async () => {
  //   const response = await fetch("api/hello/12", {
  //     method: "POST",
  //     headers: {
  //       "Content-Type": "application/json",
  //     },
  //     body: JSON.stringify({ hello: "hello" }),
  //   });
  //   const result = await response.json();
  //   console.log("result", result);
  // };

  if (typeof window !== "undefined" && loading) return null;

  if (!session && !loading && !isConnected) {
    return (
      <>
        <div>Access Denied Please Signin to view your profile page</div>
      </>
    );
  }

  if (session && isConnected) {
    return (
      <>
        <div>Welcome to profile page</div>
        <button
          onClick={() => {
            handleClick();
            // handleAPICall();
          }}
        >
          call protected API
        </button>
      </>
    );
  }
}

export default Profile;
