"use client";

import React, { useState, useEffect } from "react";
import { StyledTimePickerContainer } from "@/components/style components/StylesDayTimeSchedule";
import DayTimeScheduler from "@captainwalterdev/daytimescheduler";
import { fakeRequest } from "./fakeRequest";
import { useAccount } from "wagmi";
import { DateTime, Duration } from "luxon";
import dateFns from 'date-fns';
import { useSession } from "next-auth/react";

function DayTimeSchedule() {
    const { isConnected, address } = useAccount();
    const { data: session, status } = useSession();
    const loading = status === "loading";
    // const address = "0x3013bb4E03a7B81106D69C10710EaE148C8410E1";
    const [isScheduling, setIsScheduling] = useState(false);
    const [isScheduled, setIsScheduled] = useState(false);
    const [scheduleErr, setScheduleErr] = useState("");
    const [isLoading, setIsLoading] = useState(true);
    const [APIData, setAPIData] = useState();
    const [bookedSlots, setBookedSlots] = useState([]);

    useEffect(() => {
        const loadingTimeout = setTimeout(() => {
            setIsLoading(false);
        }, 2000);

        if (isConnected) {
            getAvailability();
        }

        // Retrieve bookedSlots from localStorage on component mount
        const storedBookedSlots = localStorage.getItem('bookedSlots');
        if (storedBookedSlots) {
            // Parse the string representation of dates into Date objects
            const parsedBookedSlots = JSON.parse(storedBookedSlots).map(dateString => new Date(dateString));
            setBookedSlots(parsedBookedSlots);
            console.log("parsedBookedSlots", parsedBookedSlots)
        }

        return () => {
            clearTimeout(loadingTimeout);
        };
    }, [address, isConnected, session]);




    const getAvailability = async () => {
        try {
            const response = await fetch(`/api/get-availability/${address}`, {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                },
            });

            const result = await response.json();
            console.log("result", result);
            if (result.success) {
                setAPIData(result.data);
                setIsLoading(false);
            }
        } catch (error) {
            console.log("error in catch", error);
        }
    };

    const handleScheduled = date => {
        setIsScheduling(true);
        setScheduleErr('');

        fakeRequest(date)
            .then(json => {

                console.log('fake response: ', json.scheduled);

                // Add the scheduled date to the bookedSlots array
                const newBookedSlots = [...bookedSlots, new Date(json.scheduled)];
                setBookedSlots(newBookedSlots);

                console.log("newBookedSlots", newBookedSlots)
                console.log("bookedSlots", JSON.stringify(newBookedSlots))
                // Store bookedSlots in localStorage
                localStorage.setItem('bookedSlots', JSON.stringify(newBookedSlots));
                setScheduleErr('');
                setIsScheduled(true);
            })
            .catch(err => {
                setScheduleErr(err);
            })
            .finally(() => {
                setIsScheduling(false);
            });
    };

    const timeSlotSizeMinutes = 15;
    let dateAndRanges = [];
    let allowedDates = [];

    // Check if API data exists
    if (APIData) {
        // console.log("APIData", APIData)
        APIData.forEach((item) => {
            // console.log("item", item)
            dateAndRanges.push(...item.dateAndRanges);
            allowedDates.push(...item.allowedDates);
        });

        dateAndRanges.forEach((range) => {
            // console.log("range", range)
            range.date = new Date(range.date);
            range.formattedUTCTime_startTime = new Date(range.formattedUTCTime_startTime)
            range.formattedUTCTime_endTime = new Date(range.formattedUTCTime_endTime)

            // console.log("range.formattedUTCTime_startTime", range.formattedUTCTime_startTime)
            // console.log("range.formattedUTCTime_endTime", range.formattedUTCTime_endTime)

            const timeOptions = { hour: '2-digit', minute: '2-digit', hour12: false };
            const formattedStartTime = range.formattedUTCTime_startTime.toLocaleTimeString(undefined, timeOptions);
            const formattedEndTime = range.formattedUTCTime_endTime.toLocaleTimeString(undefined, timeOptions);

            // console.log("formattedStartTime", formattedStartTime);
            // console.log("formattedEndTime", formattedEndTime);

            range.utcTime_startTime = formattedStartTime;
            range.utcTime_endTime = formattedEndTime;

            // const formatFromUTCTime_startTime = DateTime.fromFormat(formattedStartTime, "HH:mm");
            // const localTime_startTime = formatFromUTCTime_startTime.toFormat("HH:mm");
            // console.log("localTime_startTime", localTime_startTime);
            const [startHourTime, startMinuteTime] = formattedStartTime.split(":");
            // const formatFromUTCTime_endTime = DateTime.fromFormat(formattedEndTime, "HH:mm");
            // const localTime_endTime = formatFromUTCTime_endTime.toFormat("HH:mm");
            // console.log("localTime_endTime", localTime_endTime);
            const [endHourTime, endMinuteTime] = formattedEndTime.split(":");

            // console.log([startHourTime, startMinuteTime, endHourTime, endMinuteTime])

            range.timeRanges = [[startHourTime, startMinuteTime, endHourTime, endMinuteTime]]
        });

        allowedDates = [...new Set(dateAndRanges.flatMap(({ formattedUTCTime_startTime, formattedUTCTime_endTime }) => [formattedUTCTime_startTime, formattedUTCTime_endTime]))];
    }


    // function timeSlotValidator(slotTime, dateAndRanges, bookedSlots) {
    //     for (const { date, timeRanges } of dateAndRanges) {
    //         for (const [startHour, startMinute, endHour, endMinute] of timeRanges) {
    //             const startTime = new Date(
    //                 date.getFullYear(),
    //                 date.getMonth(),
    //                 date.getDate(),
    //                 startHour,
    //                 startMinute,
    //                 0
    //             );

    //             const endTime = new Date(
    //                 date.getFullYear(),
    //                 date.getMonth(),
    //                 date.getDate(),
    //                 endHour,
    //                 endMinute,
    //                 0
    //             );

    //             if (
    //                 slotTime.getTime() >= startTime.getTime() &&
    //                 slotTime.getTime() <= endTime.getTime()
    //             ) {
    //                 // Check if the slot is booked
    //                 const isBooked = bookedSlots.some(bookedSlot => {
    //                     return (
    //                         dateFns.isSameDay(date, bookedSlot) &&
    //                         slotTime.getHours() === bookedSlot.getHours() &&
    //                         slotTime.getMinutes() === bookedSlot.getMinutes()
    //                     );
    //                 });

    //                 // If the slot is not booked, return true
    //                 if (!isBooked) {
    //                     return true;
    //                 }
    //             }
    //         }
    //     }

    //     return false;
    // }


    function timeSlotValidator(slotTime, dateAndRanges, bookedSlots) {
        for (const { formattedUTCTime_startTime: startTime, formattedUTCTime_endTime: endTime } of dateAndRanges) {

            // Check if slotTime is within the time range of startTime and endTime
            if (
                slotTime.getTime() >= startTime.getTime() &&
                slotTime.getTime() <= endTime.getTime()
            ) {
                // Check if the slot is booked
                const isBooked = bookedSlots.some(bookedSlot => {
                    console.log("slotTime.getHours()", slotTime.getHours(), ":", slotTime.getMinutes())
                    console.log("bookedSlot.getHours()", bookedSlot.getHours(), ":", bookedSlot.getMinutes())
                    return (
                        dateFns.isSameDay(startTime, bookedSlot) &&
                        slotTime.getHours() === bookedSlot.getHours() &&
                        slotTime.getMinutes() === bookedSlot.getMinutes()
                    );
                });

                // If the slot is not booked, return true
                if (!isBooked) {
                    return true;
                }
            }
        }

        return false;
    }


    return (
        <div className="" style={{ display: "flex" }}>
            <StyledTimePickerContainer>
                {isLoading ? (
                    <div style={{ padding: "1rem" }}>Loading...</div>
                ) : (
                    <>
                        <DayTimeScheduler
                            allowedDates={allowedDates}
                            timeSlotSizeMinutes={timeSlotSizeMinutes}
                            isLoading={isScheduling}
                            isDone={isScheduled}
                            err={scheduleErr}
                            onConfirm={handleScheduled}
                            timeSlotValidator={(slotTime) => timeSlotValidator(slotTime, dateAndRanges, bookedSlots)}
                        />
                    </>
                )}
            </StyledTimePickerContainer>
        </div>
    );
}

export default DayTimeSchedule;
