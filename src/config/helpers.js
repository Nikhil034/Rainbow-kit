// from: src\components\DayTimeSchedule.js

const dateString = "Thu Apr 04 2024 16:00:00 GMT+0530 (India Standard Time)";
const epochTime = new Date(dateString).getTime() / 1000;
console.log(epochTime);


// from: src\components\TimeDayPicker.js

const handleAPICall = async () => {
    const response = await fetch('api/hello/12', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ hello: 'hello', })
    });
    const result = await response.json();
    console.log("result", result);
}

{/* <StyledButton onClick={handleAPICall}>Call</StyledButton>  */ }