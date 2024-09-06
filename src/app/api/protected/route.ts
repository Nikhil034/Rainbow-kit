// import { getToken } from "next-auth/jwt";

// const secret = process.env.NEXTAUTH_SECRET;

// export default async function POST(req: any, res: any) {
//   // if using `NEXTAUTH_SECRET` env variable, we detect it, and you won't actually need to `secret`
//   // const token = await getToken({ req })
//   const token = await getToken({ req, secret });
//   console.log("JSON Web Token", token);
//   res.end();
// }

import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";
import { getServerSession } from "next-auth";
import { authOptions } from "../auth/auth-options";
import { auth } from "../auth/auth";

export async function POST(req: NextRequest) {
  //using auth from api
  const session = await auth();
  console.log("session", JSON.stringify(session, null, 2));

  //using getServerSession
  const session2 = await getServerSession(authOptions);
  console.log("session2", JSON.stringify(session2, null, 2));

  //using getToken
  const token = await getToken({
    req,
    secret: process.env.NEXTAUTH_SECRET ?? "",
  });
  console.log("token: ", JSON.stringify(token, null, 2));

  const { hello } = await req.json();
  console.log(hello);

  if (!session) {
    return NextResponse.json(
      { message: "You must be logged in." },
      { status: 401 }
    );
  } else {
    return NextResponse.json(
      { result: { session, token, hello } },
      { status: 200 }
    );
  }
}
