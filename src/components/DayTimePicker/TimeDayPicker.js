"use client";

import React, { useState, useEffect } from "react";
import { DateTime, Duration } from "luxon";
import { useAccount } from "wagmi";
import Select from "react-select";
import DayTimeSchedule from "./DayTimeSchedule.js";
import {
  StyledTimeDayPicker,
  StyledSection,
  StyledButton,
  StyledDropdown,
  StyledToggle,
} from "@/components/style components/StylesTimeDayPicker";
import timezonesData from "../../config/timezones.json";

function TimeDayPicker() {
  const [tempTimeSlotSizeMinutes, setTempTimeSlotSizeMinutes] = useState(30);
  const [tempAvailabilityStartTime, setTempAvailabilityStartTime] =
    useState("10:00");
  const [tempAvailabilityEndTime, setTempAvailabilityEndTime] =
    useState("18:00");
  const [tempSelectedDays, setTempSelectedDays] = useState({
    sunday: false,
    monday: true,
    tuesday: true,
    wednesday: true,
    thursday: true,
    friday: true,
    saturday: false,
  });
  const { address } = useAccount();

  const [timeSlotSizeMinutes, setTimeSlotSizeMinutes] = useState(30);
  const [jsonData, setJsonData] = useState(null);
  const [availabilityStartTime, setAvailabilityStartTime] = useState("10:00");
  const [availabilityEndTime, setAvailabilityEndTime] = useState("18:00");
  const [isLoading, setIsLoading] = useState(true);
  const [selectedDays, setSelectedDays] = useState({
    sunday: false,
    monday: true,
    tuesday: true,
    wednesday: true,
    thursday: true,
    friday: true,
    saturday: false,
  });
  const [selectedOption, setSelectedOption] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const handleSearchChange = (selectedOption) => {
    setSelectedOption(selectedOption);
  };

  const options = timezonesData.map((timezone) => ({
    value: timezone.name,
    label: `${timezone.name} (${timezone.offset})`,
  }));

  useEffect(() => {
    const loadingTimeout = setTimeout(() => {
      setIsLoading(false);
    }, 2000);

    return () => {
      clearTimeout(loadingTimeout);
    };
  }, []);

  const handleTimeSlotChange = (event) => {
    setTempTimeSlotSizeMinutes(parseInt(event.target.value, 10));
  };

  const handleAvailabilityStartTimeChange = (event) => {
    setTempAvailabilityStartTime(event.target.value);
  };

  const handleAvailabilityEndTimeChange = (event) => {
    setTempAvailabilityEndTime(event.target.value);
  };

  const handleDayToggle = (day) => {
    setTempSelectedDays((prevSelectedDays) => ({
      ...prevSelectedDays,
      [day]: !prevSelectedDays[day],
    }));
  };

  const handleApplyButtonClick = async () => {
    // const userTimezone = selectedOption ? selectedOption.value : "UTC";
    const userTimezone = DateTime.local().zoneName;
    console.log(userTimezone);

    const combinedStartTime = DateTime.fromFormat(
      tempAvailabilityStartTime,
      "HH:mm"
    )
      .set({ second: 0, millisecond: 0 })
      .setZone(userTimezone);

    const combinedEndTime = DateTime.fromFormat(
      tempAvailabilityEndTime,
      "HH:mm"
    )
      .set({ second: 0, millisecond: 0 })
      .setZone(userTimezone);

    console.log("combinedStartTime", combinedStartTime.toString());
    console.log("combinedENdTime", combinedEndTime.toString());

    const availabilityStartTimeUTC = combinedStartTime
      .toUTC()
      .toFormat("HH:mm");
    const availabilityEndTimeUTC = combinedEndTime.toUTC().toFormat("HH:mm");


    console.log("userTimezone", userTimezone);
    console.log("tempAvailabilityStartTime", tempAvailabilityStartTime)
    console.log("tempAvailabilityEndTime", tempAvailabilityEndTime)
    console.log("formattedStartTime", formattedStartTime)
    console.log("formattedEndTime", formattedEndTime)

    console.log("combinedStartTime", combinedStartTime);
    console.log("combinedEndTime", combinedEndTime);


    console.log("availabilityStartTimeUTC", availabilityStartTimeUTC)
    console.log("availabilityEndTimeUTC", availabilityEndTimeUTC)

    const data = {
      userAddress: address,
      timeSlotSizeMinutes: tempTimeSlotSizeMinutes,
      availabilityStartTime: availabilityStartTimeUTC,
      availabilityEndTime: availabilityEndTimeUTC,
      selectedDays: tempSelectedDays,
      selectedTimeZone: userTimezone,
    };
    console.log("final DATA", data);
    // try {
    //   const response = await fetch("/api/store-availibility", {
    //     method: "POST",
    //     headers: {
    //       "Content-Type": "application/json",
    //     },
    //     body: JSON.stringify(data),
    //   });

    //   if (!response.ok) {
    //     throw new Error("Failed to store data to API");
    //   }

    //   setTimeSlotSizeMinutes(tempTimeSlotSizeMinutes);
    //   setAvailabilityStartTime(availabilityStartTimeUTC);
    //   setAvailabilityEndTime(availabilityEndTimeUTC);
    //   setSelectedDays(tempSelectedDays);

    //   console.log("Data stored successfully:", data);
    // } catch (error) {
    //   console.error("Error storing data to API:", error);
    // }
  };

  return (
    <>
      <div className="">
        {isLoading ? (
          <StyledTimeDayPicker>
            <div>Loading...</div>
          </StyledTimeDayPicker>
        ) : (
          <>
            <StyledTimeDayPicker>
              <div className="dropdown" style={{ minWidth: "25%" }} >
                <StyledDropdown>
                  <label>
                    <span>Select Time Zone:</span>
                    <Select
                      value={selectedOption}
                      onChange={handleSearchChange}
                      options={options}
                      isSearchable
                    />
                  </label>
                </StyledDropdown>
                <div>
                  <StyledSection>
                    <label>
                      Select Time Slot Size:
                      <select
                        value={tempTimeSlotSizeMinutes}
                        onChange={handleTimeSlotChange}
                      >
                        <option value={15}>15 minutes</option>
                        <option value={30}>30 minutes</option>
                        <option value={45}>45 minutes</option>
                        <option value={60}>60 minutes</option>
                      </select>
                    </label>
                  </StyledSection>
                </div>
                <div>
                  <StyledSection>
                    <label>
                      Select Availability Time:
                      <input
                        type="time"
                        value={tempAvailabilityStartTime}
                        onChange={handleAvailabilityStartTimeChange}
                      />
                      &nbsp;to&nbsp;
                      <input
                        type="time"
                        value={tempAvailabilityEndTime}
                        onChange={handleAvailabilityEndTimeChange}
                      />
                    </label>
                  </StyledSection>
                </div>
                <div>
                  <StyledToggle>
                    <label>Select Availability Days:</label>
                    <div className="toggle-switches">
                      {Object.keys(tempSelectedDays).map((day) => (
                        <div key={day} className="toggle-switch">
                          <span>{day}</span>
                          <label className="switch">
                            <input
                              type="checkbox"
                              checked={tempSelectedDays[day]}
                              onChange={() => handleDayToggle(day)}
                            />
                            <span className="slider"></span>
                          </label>
                        </div>
                      ))}
                    </div>
                  </StyledToggle>
                </div>
                <StyledButton onClick={handleApplyButtonClick}>
                  Apply
                </StyledButton>
              </div>
              <div className="flex justify-between mt-4 ml-[10rem]">
                <DayTimeSchedule
                  timeSlotSizeMinutes={timeSlotSizeMinutes}
                  availabilityStartTime={availabilityStartTime}
                  availabilityEndTime={availabilityEndTime}
                  selectedValidDays={selectedDays}
                />
              </div>
            </StyledTimeDayPicker>
          </>
        )}
      </div>
    </>
  );
}

export default TimeDayPicker;
