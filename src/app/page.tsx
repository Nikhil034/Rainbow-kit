"use client";

import React, { useState } from "react";
import TimeDayPicker from "@/components/DayTimePicker/TimeDayPicker";
import TimeDatePicker from "@/components/DayTimePicker/TimeDatePicker";
import "./Home.css";

export default function Home() {
  const [showTimeDayPicker, setShowTimeDayPicker] = useState(true);

  return (
    // <div className="container">{showTimeDayPicker && <TimeDayPicker />}</div>
    <div className="container">{showTimeDayPicker && <TimeDatePicker />}</div>
  );
}
