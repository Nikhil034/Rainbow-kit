import { NextApiRequest } from "next";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: Request, res: { params: { id: string } }) {
  const { hello } = await req.json();

  const receivedData = hello;
  console.log("req", hello);
  console.log("res", res.params.id);

  return NextResponse.json({ result: receivedData }, { status: 200 });
}
