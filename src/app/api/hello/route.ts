// import { NextRequest, NextResponse } from "next/server";

// export async function POST(req: NextRequest, res: NextResponse) {
//   console.log("req", req.method);

//   const receivedData = req.body;
//   console.log("res", res);
//   return NextResponse.json({ result: receivedData }, { status: 200 });
// }


import { NextResponse } from "next/server";

export function GET() {
  return new NextResponse("Inside Hello");
}
