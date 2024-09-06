import React from 'react'
import { ConnectButton } from "@rainbow-me/rainbowkit";

export default function Navbar() {
    return (
        <div className='p-2 h-[4rem] flex items-center text-center justify-center bg-gray-800'>
            <div className='absolute right-10 text-slate-100'>
                <ConnectButton />
            </div>
        </div>
    )
};