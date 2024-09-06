import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { SiweMessage } from "siwe";
import { ethers, hashMessage, recoverAddress } from "ethers";

async function verifySmartWalletSignature({
  message,
  signature,
  walletAddress,
}: {
  message: string;
  signature: string;
  walletAddress: string;
}): Promise<boolean> {
  try {
    // Hash the message to obtain the message hash

    const messageHash = hashMessage(message);
    console.log('Line number 18',messageHash);

    // Recover the address from the message hash and the signature
    const recoveredAddress = recoverAddress(messageHash, signature);
    console.log('Line number 23',recoveredAddress);

    // Compare the recovered address with the provided wallet address
    return recoveredAddress.toLowerCase() === walletAddress.toLowerCase();
  } catch (error) {
    console.error("Signature verification failed:", error);
    return false;
  }
}

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: "Ethereum",
      credentials: {
        message: { label: "Message", type: "text", placeholder: "0x0" },
        signature: { label: "Signature", type: "text", placeholder: "0x0" },
      },
      async authorize(credentials, req) {
        try {
          const messageData = credentials?.message || "{}";
          console.log('Line number:',messageData);
          const signature = credentials?.signature || "";
          console.log('Line number 46:',signature);
          
          // Parse the message data
          const siwe = new SiweMessage(JSON.parse(messageData));
          console.log('Line number 50:',siwe);

          // Verify the signature
          const isValid = await verifySmartWalletSignature({
            message: messageData,
            signature,
            walletAddress: siwe.address,
          });

          if (isValid) {
            return { id: siwe.address };
          } else {
            throw new Error("Invalid signature");
          }
        } catch (e) {
          console.log("error:", e);
          return null;
        }
      },
    }),
  ],
  session: {
    strategy: "jwt",
  },
  secret: process.env.NEXTAUTH_SECRET,
  callbacks: {
    async session({ session, token }: { session: any; token: any }) {
      session.address = token.sub;
      session.user.name = token.sub;
      return session;
    },
  },
};
