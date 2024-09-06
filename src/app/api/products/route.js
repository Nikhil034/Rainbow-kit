import mongoose from "mongoose";
import { NextResponse } from "next/server";
import { connectionStr } from "@/app/lib/db_connect";
import { Product } from "@/app/lib/model/product";

export async function GET() {
  let data = [];

  try {
    await mongoose.connect(connectionStr);
    data = await Product.find();
  } catch (error) {
    console.error(error);
    data = { success: false };
  }

  return NextResponse.json({ result: data, success: true });
}
