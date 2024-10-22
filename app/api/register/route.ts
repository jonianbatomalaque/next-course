import { prisma } from "@/prisma/client";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import bcrypt from "bcrypt";

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(5)
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    // Validate the request body
    const validation = schema.safeParse(body);
    if (!validation.success) {
      return NextResponse.json(validation.error.errors, { status: 400 });
    }

    // Check if the user already exists
    const user = await prisma.user.findUnique({ where: { email: body.email } });
    if (user) {
      return NextResponse.json({ message: "User already exists" }, { status: 400 });
    }

    // If the user doesn't exist, proceed to create the user (or next steps)
    // You can add the user creation logic here, for example:
    // const newUser = await prisma.user.create({ data: { email: body.email, password: body.password } });

    const hashedPassword = await bcrypt.hash(body.password, 10);

    const newUser = await prisma.user.create({
        data:{
            email :body.email,
            hashedPassword
        }
    })

    return NextResponse.json({ email: newUser.email }, { status: 200 });

  } catch (error) {
    // Handle any unexpected errors
    console.error(error);
    return NextResponse.json({ message: "Internal Server Error" }, { status: 500 });
  }
}
