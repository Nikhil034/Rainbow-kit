"use client";
import React, { useState, useEffect } from "react";
import DayTimeSchedule from "@/components/DayTimePicker/DayTimeSchedule";

// Define an interface for the props of DayTimeSchedule component
interface DayTimeScheduleProps {
  timeSlotSizeMinutes: number;
  allowedDates: string[];
  dateAndRanges: any[]; // You might need to define a proper interface for dateAndRanges
}

function Page() {
  const [availabilityData, setAvailabilityData] = useState<
    AvailabilityData[] | null
  >(null);

  useEffect(() => {
    const fetchAvailability = async () => {
      try {
        const response = await fetch(
          "/api/get-availability/0x3013bb4E03a7B81106D69C10710EaE148C8410E1"
        );
        const data = await response.json();
        setAvailabilityData(data.data);
      } catch (error) {
        console.error("Error fetching availability:", error);
      }
    };

    fetchAvailability();
  }, []);

  return (
    <div>
      <div className="flex justify-between mt-4 ml-[10rem]">
        {availabilityData && (
          <DayTimeSchedule
            timeSlotSizeMinutes={availabilityData[0].timeSlotSizeMinutes}
            allowedDates={availabilityData.reduce(
              (dates, item) => dates.concat(item.allowedDates),
              []
            )}
            dateAndRanges={availabilityData.reduce(
              (ranges, item) => ranges.concat(item.dateAndRanges),
              []
            )}
          />
        )}
      </div>
    </div>
  );
}

export default Page;
